import csv
import json
import os
import re
import hashlib
from typing import Dict, List, Any, Optional, Iterator, Tuple, Union, BinaryIO
from pathlib import Path
import gzip

from ..utils.logger import get_logger

logger = get_logger()


class LogIngestor:
    """Handles ingestion of various log file formats."""
    
    def __init__(self):
        """Initialize the log ingestor."""
        pass
    
    def detect_format(self, file_path: str) -> str:
        """Detect the format of a log file.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            String representing the detected format ('json', 'csv', 'syslog')
            
        Raises:
            ValueError: If the format cannot be detected
        """
        file_path = Path(file_path)
        file_ext = file_path.suffix.lower()
        
        # Check if the file is gzipped
        is_gzipped = file_ext == '.gz'
        if is_gzipped:
            file_ext = Path(file_path.stem).suffix.lower()
        
        # Try to detect format based on extension
        if file_ext in ('.json', '.jsonl'):
            return 'json'
        elif file_ext == '.csv':
            return 'csv'
        elif file_ext in ('.log', '.syslog'):
            return 'syslog'
        
        # If can't determine by extension, try to read a bit of the file
        try:
            opener = gzip.open if is_gzipped else open
            with opener(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                
                # Check if it's JSON
                if first_line.startswith('{') and first_line.endswith('}'):
                    return 'json'
                elif first_line.startswith('[') and first_line.endswith(']'):
                    return 'json'
                
                # Check if it's CSV
                if ',' in first_line and first_line.count(',') > 2:
                    # Check if there are headers that look like CSV
                    headers = first_line.split(',')
                    if all(re.match(r'^[a-zA-Z0-9_]+$', h.strip()) for h in headers):
                        return 'csv'
                
                # Default to syslog for text-based logs
                return 'syslog'
                
        except Exception as e:
            logger.error(f"Error detecting file format: {str(e)}")
            raise ValueError(f"Unable to detect format of file {file_path}: {str(e)}")
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA-256 hash of the file
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read and update hash in chunks to avoid loading large files into memory
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {str(e)}")
            return ""
    
    def _read_json_logs(self, file_path: str) -> Iterator[Dict[str, Any]]:
        """Read logs from a JSON file.
        
        Args:
            file_path: Path to the JSON log file
            
        Yields:
            Log entries as dictionaries
        """
        file_path = Path(file_path)
        is_gzipped = file_path.suffix.lower() == '.gz'
        opener = gzip.open if is_gzipped else open
        
        with opener(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            first_char = f.read(1)
            f.seek(0)  # Reset to beginning of file
            
            # Check if the file contains a JSON array
            if first_char == '[':
                logs = json.load(f)
                for log in logs:
                    yield log
            # Check if each line is a separate JSON object (JSONL format)
            else:
                for line in f:
                    line = line.strip()
                    if line:  # Skip empty lines
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Error parsing JSON line: {line[:100]}... - {str(e)}")
                            continue
    
    def _read_csv_logs(self, file_path: str) -> Iterator[Dict[str, Any]]:
        """Read logs from a CSV file.
        
        Args:
            file_path: Path to the CSV log file
            
        Yields:
            Log entries as dictionaries
        """
        file_path = Path(file_path)
        is_gzipped = file_path.suffix.lower() == '.gz'
        opener = gzip.open if is_gzipped else open
        
        with opener(file_path, 'rt', encoding='utf-8', errors='ignore', newline='') as f:
            # Try to sniff the CSV dialect
            try:
                sample = f.read(4096)
                f.seek(0)  # Reset to beginning of file
                dialect = csv.Sniffer().sniff(sample)
                reader = csv.DictReader(f, dialect=dialect)
            except:
                # Fall back to defaults if sniffing fails
                reader = csv.DictReader(f)
            
            if not reader.fieldnames:
                raise ValueError("CSV file has no headers")
                
            for row in reader:
                yield {k: v for k, v in row.items()}
    
    def _read_syslog_logs(self, file_path: str) -> Iterator[Dict[str, Any]]:
        """Read logs from a syslog file.
        
        Args:
            file_path: Path to the syslog file
            
        Yields:
            Log entries as dictionaries
        """
        file_path = Path(file_path)
        is_gzipped = file_path.suffix.lower() == '.gz'
        opener = gzip.open if is_gzipped else open
        
        # Regular expression to parse syslog format
        # This handles common syslog formats, may need adjustment for specific formats
        syslog_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>[^\s]+)\s+'
            r'(?P<application>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)'
        )
        
        with opener(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                match = syslog_pattern.match(line)
                if match:
                    log_entry = match.groupdict()
                    log_entry['line_number'] = line_number
                    log_entry['raw_message'] = line
                    yield log_entry
                else:
                    # If the line doesn't match the pattern, store it as raw message
                    yield {
                        'timestamp': None,
                        'hostname': None,
                        'application': None,
                        'pid': None,
                        'message': line,
                        'line_number': line_number,
                        'raw_message': line
                    }
    
    def ingest_file(self, file_path: str, format_override: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Ingest a log file and return its contents.
        
        Args:
            file_path: Path to the log file
            format_override: Optional format override ('json', 'csv', 'syslog')
            
        Returns:
            Tuple of (list of log entries, file metadata)
        """
        try:
            file_path = os.path.abspath(file_path)
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            filename = os.path.basename(file_path)
            
            # Calculate file hash for deduplication
            file_hash = self.calculate_file_hash(file_path)
            
            # Detect or use the provided format
            log_format = format_override or self.detect_format(file_path)
            
            logger.info(f"Ingesting {log_format} log file: {filename} ({file_size} bytes)")
            
            # Read logs based on format
            logs = []
            if log_format == 'json':
                logs = list(self._read_json_logs(file_path))
            elif log_format == 'csv':
                logs = list(self._read_csv_logs(file_path))
            elif log_format == 'syslog':
                logs = list(self._read_syslog_logs(file_path))
            else:
                raise ValueError(f"Unsupported log format: {log_format}")
                
            metadata = {
                'filename': filename,
                'file_path': file_path,
                'file_size': file_size,
                'file_hash': file_hash,
                'log_type': log_format,
                'records_count': len(logs)
            }
            
            logger.info(f"Successfully ingested {len(logs)} log entries")
            return logs, metadata
            
        except Exception as e:
            logger.error(f"Error ingesting log file {file_path}: {str(e)}")
            raise 