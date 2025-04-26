import json
import sqlite3
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger()
config = get_config()


class StorageHandler:
    """Handles all storage operations for SentinelMind."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize the storage handler.
        
        Args:
            db_path: Optional path to the database file
        """
        self.db_path = db_path or config.get_db_path()
        self._initialize_db()
        
    def _initialize_db(self) -> None:
        """Initialize the database with required tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            
            # Logs table - stores metadata about processed log files
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                file_size INTEGER,
                log_type TEXT NOT NULL,
                records_count INTEGER,
                processed_at TIMESTAMP,
                UNIQUE(file_path, file_hash)
            )
            ''')
            
            # Anomalies table - stores detected anomalies
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_file_id INTEGER,
                timestamp TIMESTAMP,
                event_type TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                user_id TEXT,
                resource TEXT,
                action TEXT,
                status TEXT,
                severity REAL,
                score REAL,
                raw_data TEXT,
                detection_algorithm TEXT,
                processed_at TIMESTAMP,
                FOREIGN KEY (log_file_id) REFERENCES log_files(id)
            )
            ''')
            
            # Attack chains table - stores correlated anomalies forming attack chains
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                severity REAL,
                confidence REAL,
                mitre_techniques TEXT,
                status TEXT,
                created_at TIMESTAMP
            )
            ''')
            
            # Link anomalies to attack chains
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS chain_anomalies (
                chain_id INTEGER,
                anomaly_id INTEGER,
                sequence_order INTEGER,
                PRIMARY KEY (chain_id, anomaly_id),
                FOREIGN KEY (chain_id) REFERENCES attack_chains(id),
                FOREIGN KEY (anomaly_id) REFERENCES anomalies(id)
            )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_source_ip ON anomalies(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_username ON anomalies(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_chains_time ON attack_chains(start_time, end_time)')
            
            conn.commit()
            conn.close()
            logger.info(f"Database initialized successfully at {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise
            
    def register_log_file(self, 
                         filename: str, 
                         file_path: str, 
                         log_type: str, 
                         records_count: int, 
                         file_hash: Optional[str] = None, 
                         file_size: Optional[int] = None) -> int:
        """Register a log file in the database.
        
        Args:
            filename: The name of the log file
            file_path: Full path to the log file
            log_type: Type of log (CSV, JSON, syslog)
            records_count: Number of records in the log file
            file_hash: Optional hash of the file for deduplication
            file_size: Optional size of the file in bytes
            
        Returns:
            The ID of the inserted log file record
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT OR REPLACE INTO log_files 
            (filename, file_path, file_hash, file_size, log_type, records_count, processed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                filename, 
                file_path, 
                file_hash, 
                file_size, 
                log_type, 
                records_count, 
                datetime.now().isoformat()
            ))
            
            log_file_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"Registered log file {filename} with ID {log_file_id}")
            return log_file_id
            
        except Exception as e:
            logger.error(f"Failed to register log file: {str(e)}")
            raise
    
    def store_anomaly(self, 
                     log_file_id: int, 
                     timestamp: str, 
                     event_data: Dict[str, Any], 
                     score: float, 
                     detection_algorithm: str) -> int:
        """Store detected anomaly in the database.
        
        Args:
            log_file_id: ID of the processed log file
            timestamp: Timestamp of the anomalous event
            event_data: Extracted event data 
            score: Anomaly score (higher is more anomalous)
            detection_algorithm: Name of the detection algorithm used
            
        Returns:
            The ID of the inserted anomaly record
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate severity based on score (0-1)
            severity = min(max(score, 0), 1)
            
            cursor.execute('''
            INSERT INTO anomalies 
            (log_file_id, timestamp, event_type, source_ip, destination_ip, 
             username, user_id, resource, action, status, severity, score, 
             raw_data, detection_algorithm, processed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_file_id,
                timestamp,
                event_data.get('event_type'),
                event_data.get('source_ip'),
                event_data.get('destination_ip'),
                event_data.get('username'),
                event_data.get('user_id'),
                event_data.get('resource'),
                event_data.get('action'),
                event_data.get('status'),
                severity,
                score,
                json.dumps(event_data),
                detection_algorithm,
                datetime.now().isoformat()
            ))
            
            anomaly_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.debug(f"Stored anomaly with ID {anomaly_id}")
            return anomaly_id
            
        except Exception as e:
            logger.error(f"Failed to store anomaly: {str(e)}")
            raise
    
    def store_attack_chain(self, 
                          name: str, 
                          anomaly_ids: List[int], 
                          start_time: str, 
                          end_time: str, 
                          severity: float, 
                          confidence: float, 
                          mitre_techniques: List[str]) -> int:
        """Store an attack chain with linked anomalies.
        
        Args:
            name: Name of the attack chain
            anomaly_ids: List of anomaly IDs in this chain
            start_time: Start time of the attack chain
            end_time: End time of the attack chain
            severity: Severity score (0-1)
            confidence: Confidence score (0-1)
            mitre_techniques: List of MITRE ATT&CK technique IDs
            
        Returns:
            The ID of the inserted attack chain
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert the attack chain
            cursor.execute('''
            INSERT INTO attack_chains 
            (name, start_time, end_time, severity, confidence, mitre_techniques, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                name,
                start_time,
                end_time,
                severity,
                confidence,
                json.dumps(mitre_techniques),
                'new',
                datetime.now().isoformat()
            ))
            
            chain_id = cursor.lastrowid
            
            # Link anomalies to this chain with order
            for i, anomaly_id in enumerate(anomaly_ids):
                cursor.execute('''
                INSERT INTO chain_anomalies (chain_id, anomaly_id, sequence_order)
                VALUES (?, ?, ?)
                ''', (chain_id, anomaly_id, i))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Stored attack chain '{name}' with ID {chain_id} linking {len(anomaly_ids)} anomalies")
            return chain_id
            
        except Exception as e:
            logger.error(f"Failed to store attack chain: {str(e)}")
            raise
    
    def get_anomalies(self, 
                     limit: Optional[int] = 100, 
                     offset: Optional[int] = 0, 
                     filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve anomalies with optional filtering.
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            filters: Dictionary of filter conditions
            
        Returns:
            List of anomaly records
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = '''
            SELECT a.*, l.filename, l.log_type
            FROM anomalies a
            JOIN log_files l ON a.log_file_id = l.id
            '''
            
            params = []
            where_clauses = []
            
            # Apply filters if provided
            if filters:
                for key, value in filters.items():
                    if key == 'min_severity':
                        where_clauses.append('a.severity >= ?')
                        params.append(value)
                    elif key == 'source_ip':
                        where_clauses.append('a.source_ip = ?')
                        params.append(value)
                    elif key == 'username':
                        where_clauses.append('a.username = ?')
                        params.append(value)
                    elif key == 'start_time':
                        where_clauses.append('a.timestamp >= ?')
                        params.append(value)
                    elif key == 'end_time':
                        where_clauses.append('a.timestamp <= ?')
                        params.append(value)
                    elif key == 'event_type':
                        where_clauses.append('a.event_type = ?')
                        params.append(value)
            
            # Add WHERE clause if filters were applied
            if where_clauses:
                query += ' WHERE ' + ' AND '.join(where_clauses)
                
            # Add ordering and pagination
            query += ' ORDER BY a.timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            result = []
            for row in rows:
                row_dict = dict(row)
                # Parse the raw_data JSON
                if row_dict.get('raw_data'):
                    row_dict['raw_data'] = json.loads(row_dict['raw_data'])
                result.append(row_dict)
                
            conn.close()
            return result
            
        except Exception as e:
            logger.error(f"Failed to retrieve anomalies: {str(e)}")
            raise
    
    def get_attack_chains(self, 
                         limit: Optional[int] = 100, 
                         offset: Optional[int] = 0, 
                         include_anomalies: bool = False) -> List[Dict[str, Any]]:
        """Retrieve attack chains with optional anomaly details.
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            include_anomalies: Whether to include linked anomalies
            
        Returns:
            List of attack chain records
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM attack_chains
            ORDER BY start_time DESC
            LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            rows = cursor.fetchall()
            result = []
            
            for row in rows:
                chain = dict(row)
                
                # Parse the MITRE techniques JSON
                if chain.get('mitre_techniques'):
                    chain['mitre_techniques'] = json.loads(chain['mitre_techniques'])
                
                # Include linked anomalies if requested
                if include_anomalies:
                    cursor.execute('''
                    SELECT a.* FROM anomalies a
                    JOIN chain_anomalies ca ON a.id = ca.anomaly_id
                    WHERE ca.chain_id = ?
                    ORDER BY ca.sequence_order
                    ''', (chain['id'],))
                    
                    anomalies = []
                    for anomaly_row in cursor.fetchall():
                        anomaly = dict(anomaly_row)
                        if anomaly.get('raw_data'):
                            anomaly['raw_data'] = json.loads(anomaly['raw_data'])
                        anomalies.append(anomaly)
                    
                    chain['anomalies'] = anomalies
                
                result.append(chain)
                
            conn.close()
            return result
            
        except Exception as e:
            logger.error(f"Failed to retrieve attack chains: {str(e)}")
            raise
    
    def export_findings(self, 
                       output_path: str, 
                       export_format: str = 'json', 
                       include_chains: bool = True, 
                       include_anomalies: bool = True) -> str:
        """Export findings to a file.
        
        Args:
            output_path: Path to save the exported file
            export_format: Format to export (json or csv)
            include_chains: Whether to include attack chains
            include_anomalies: Whether to include anomalies
            
        Returns:
            The path to the exported file
        """
        try:
            data = {
                "exported_at": datetime.now().isoformat(),
                "sentinelmind_version": "1.0.0"
            }
            
            # Get anomalies if requested
            if include_anomalies:
                data["anomalies"] = self.get_anomalies(limit=10000)  # Get up to 10k anomalies
            
            # Get attack chains if requested
            if include_chains:
                data["attack_chains"] = self.get_attack_chains(
                    limit=1000,  # Get up to 1k chains
                    include_anomalies=True  # Always include linked anomalies for chains
                )
            
            # Export as JSON
            if export_format.lower() == 'json':
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)
                
            # Export as CSV
            elif export_format.lower() == 'csv':
                import csv
                
                # We'll create separate CSV files for anomalies and chains
                base_path = os.path.splitext(output_path)[0]
                
                # Export anomalies if requested
                if include_anomalies and "anomalies" in data:
                    anomalies_path = f"{base_path}_anomalies.csv"
                    with open(anomalies_path, 'w', newline='') as f:
                        if data["anomalies"]:
                            writer = csv.DictWriter(f, fieldnames=data["anomalies"][0].keys())
                            writer.writeheader()
                            for anomaly in data["anomalies"]:
                                # Convert raw_data back to string for CSV
                                if "raw_data" in anomaly and isinstance(anomaly["raw_data"], dict):
                                    anomaly["raw_data"] = json.dumps(anomaly["raw_data"])
                                writer.writerow(anomaly)
                
                # Export attack chains if requested
                if include_chains and "attack_chains" in data:
                    chains_path = f"{base_path}_attack_chains.csv"
                    with open(chains_path, 'w', newline='') as f:
                        if data["attack_chains"]:
                            # Exclude the anomalies list from the CSV headers
                            fieldnames = [k for k in data["attack_chains"][0].keys() if k != "anomalies"]
                            writer = csv.DictWriter(f, fieldnames=fieldnames)
                            writer.writeheader()
                            for chain in data["attack_chains"]:
                                # Convert mitre_techniques back to string for CSV
                                if "mitre_techniques" in chain and isinstance(chain["mitre_techniques"], list):
                                    chain["mitre_techniques"] = json.dumps(chain["mitre_techniques"])
                                # Create a copy without the anomalies field
                                chain_copy = {k: v for k, v in chain.items() if k != "anomalies"}
                                writer.writerow(chain_copy)
                
                # Return the base path since we created multiple files
                return base_path
            
            else:
                raise ValueError(f"Unsupported export format: {export_format}")
            
            logger.info(f"Exported findings to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to export findings: {str(e)}")
            raise

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics from the database.
        
        Returns:
            Dictionary of statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            stats = {}
            
            # Get count of log files
            cursor.execute("SELECT COUNT(*) FROM log_files")
            stats["log_files_count"] = cursor.fetchone()[0]
            
            # Get count of anomalies
            cursor.execute("SELECT COUNT(*) FROM anomalies")
            stats["anomalies_count"] = cursor.fetchone()[0]
            
            # Get count of attack chains
            cursor.execute("SELECT COUNT(*) FROM attack_chains")
            stats["attack_chains_count"] = cursor.fetchone()[0]
            
            # Get average severity of anomalies
            cursor.execute("SELECT AVG(severity) FROM anomalies")
            stats["avg_anomaly_severity"] = cursor.fetchone()[0] or 0
            
            # Get highest severity anomalies count (severity > 0.7)
            cursor.execute("SELECT COUNT(*) FROM anomalies WHERE severity > 0.7")
            stats["high_severity_anomalies"] = cursor.fetchone()[0]
            
            # Get most recent scan time
            cursor.execute("SELECT MAX(processed_at) FROM log_files")
            stats["last_scan_time"] = cursor.fetchone()[0]
            
            conn.close()
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get database stats: {str(e)}")
            raise 