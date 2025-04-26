import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime
import time

from PyQt6.QtCore import QThread, pyqtSignal

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.core.ingestor import LogIngestor
from sentinelmind.core.parser import LogParser
from sentinelmind.core.feature_extractor import FeatureExtractor
from sentinelmind.core.anomaly_detector import AnomalyDetector
from sentinelmind.core.attack_linker import AttackLinker
from sentinelmind.core.storage import StorageHandler

logger = get_logger()
config = get_config()


class ScanThread(QThread):
    """Thread for scanning log files for threats."""
    
    # Define signals
    status_update = pyqtSignal(str)
    progress_update = pyqtSignal(int)
    anomaly_detected = pyqtSignal(dict)
    scan_complete = pyqtSignal(int, int)  # anomaly_count, chain_count
    scan_error = pyqtSignal(str)
    
    def __init__(self, file_path: str, model_type: str = "isolation_forest", threshold: Optional[float] = None):
        """Initialize the scan thread.
        
        Args:
            file_path: Path to the log file to scan
            model_type: ML model to use (isolation_forest or autoencoder)
            threshold: Override anomaly detection threshold (0.0 to 1.0)
        """
        super().__init__()
        
        self.file_path = file_path
        self.model_type = model_type
        self.threshold = threshold
        
        # Initialize components
        self.ingestor = None
        self.parser = None
        self.feature_extractor = None
        self.detector = None
        self.attack_linker = None
        self.storage = None
        
        # Initialize counters
        self.anomaly_count = 0
        self.chain_count = 0
        
    def run(self):
        """Run the scan thread."""
        try:
            # Initialize components
            self.status_update.emit("Initializing components...")
            self.ingestor = LogIngestor()
            self.parser = LogParser()
            self.feature_extractor = FeatureExtractor()
            self.storage = StorageHandler()
            
            # Initialize anomaly detector
            self.detector = AnomalyDetector(model_type=self.model_type, load_model=True)
            if self.threshold is not None:
                self.detector.threshold = max(0.0, min(self.threshold, 1.0))
                
            # Initialize attack linker
            self.attack_linker = AttackLinker()
            
            # Ingest log file
            self.status_update.emit(f"Ingesting log file: {self.file_path}")
            logs, metadata = self.ingestor.ingest_file(self.file_path)
            
            # Register log file in storage
            log_file_id = self.storage.register_log_file(
                filename=metadata['filename'],
                file_path=metadata['file_path'],
                log_type=metadata['log_type'],
                records_count=metadata['records_count'],
                file_hash=metadata.get('file_hash'),
                file_size=metadata.get('file_size')
            )
            
            # Parse logs
            self.status_update.emit(f"Parsing {len(logs)} log entries...")
            normalized_logs = self.parser.parse_logs(logs)
            
            # Process logs in batches
            self.anomaly_count = 0
            all_anomalies = []
            batch_size = 1000
            
            total_batches = (len(normalized_logs) + batch_size - 1) // batch_size
            
            for i in range(0, len(normalized_logs), batch_size):
                # Calculate progress
                progress = int((i / len(normalized_logs)) * 90)  # Reserve 10% for correlation
                self.progress_update.emit(progress)
                
                # Update status
                batch_num = (i // batch_size) + 1
                self.status_update.emit(f"Analyzing batch {batch_num}/{total_batches}...")
                
                # Get batch
                batch = normalized_logs[i:i+batch_size]
                
                # Extract features
                features_df, _ = self.feature_extractor.extract_features(batch)
                
                if not features_df.empty:
                    # Predict anomalies
                    predictions, scores = self.detector.predict(features_df)
                    
                    # Store anomalies
                    for j, (pred, score) in enumerate(zip(predictions, scores)):
                        if pred == 1:  # If it's an anomaly
                            self.anomaly_count += 1
                            
                            # Get the log entry
                            log_entry = batch[j]
                            
                            # Store the anomaly
                            try:
                                anomaly_id = self.storage.store_anomaly(
                                    log_file_id=log_file_id,
                                    timestamp=log_entry.get('timestamp', ''),
                                    event_data=log_entry,
                                    score=float(score),
                                    detection_algorithm=self.model_type
                                )
                                
                                # Add ID to the log entry for linking
                                log_entry['id'] = anomaly_id
                                log_entry['score'] = float(score)
                                log_entry['severity'] = min(max(float(score), 0), 1)
                                
                                # Emit anomaly signal
                                self.anomaly_detected.emit(log_entry)
                                
                                # Add to list of anomalies
                                all_anomalies.append(log_entry)
                                
                            except Exception as e:
                                logger.error(f"Error storing anomaly: {str(e)}")
            
            # Link anomalies into attack chains
            self.status_update.emit("Correlating anomalies into attack chains...")
            self.progress_update.emit(95)  # Almost done
            
            attack_chains = self.attack_linker.cluster_anomalies(all_anomalies)
            self.chain_count = len(attack_chains)
            
            # Store attack chains
            for chain in attack_chains:
                try:
                    chain_id = self.storage.store_attack_chain(
                        name=chain['name'],
                        anomaly_ids=chain['anomaly_ids'],
                        start_time=chain['start_time'],
                        end_time=chain['end_time'],
                        severity=chain['severity'],
                        confidence=chain['confidence'],
                        mitre_techniques=chain['mitre_techniques']
                    )
                except Exception as e:
                    logger.error(f"Error storing attack chain: {str(e)}")
            
            # Complete
            self.status_update.emit("Scan complete")
            self.progress_update.emit(100)
            
            # Emit completion signal
            self.scan_complete.emit(self.anomaly_count, self.chain_count)
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            self.scan_error.emit(str(e)) 