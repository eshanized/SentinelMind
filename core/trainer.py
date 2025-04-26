import os
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import concurrent.futures
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.config import get_config
from .ingestor import LogIngestor
from .parser import LogParser
from .feature_extractor import FeatureExtractor
from .anomaly_detector import AnomalyDetector

logger = get_logger()
config = get_config()


class ModelTrainer:
    """Trains machine learning models for anomaly detection."""
    
    def __init__(self, model_type: str = "isolation_forest"):
        """Initialize the model trainer.
        
        Args:
            model_type: Type of model to train ('isolation_forest' or 'autoencoder')
        """
        self.model_type = model_type
        self.ingestor = LogIngestor()
        self.parser = LogParser()
        self.feature_extractor = FeatureExtractor()
        self.detector = AnomalyDetector(model_type=model_type, load_model=False)
        
        # Initialize training metadata
        self.training_metadata = {
            'model_type': model_type,
            'started_at': None,
            'completed_at': None,
            'files_processed': 0,
            'logs_processed': 0,
            'features_extracted': 0,
            'errors': []
        }
    
    def train_from_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train models from a list of log entries.
        
        Args:
            logs: List of raw log entries
            
        Returns:
            Training metadata dictionary
        """
        self.training_metadata['started_at'] = datetime.now().isoformat()
        
        try:
            # Parse logs
            logger.info(f"Parsing {len(logs)} log entries")
            normalized_logs = self.parser.parse_logs(logs)
            
            # Extract features
            logger.info("Extracting features from normalized logs")
            features_df, feature_metadata = self.feature_extractor.extract_features(normalized_logs)
            
            if features_df.empty:
                raise ValueError("No features could be extracted from logs")
                
            self.training_metadata['features_extracted'] = len(features_df.columns)
            
            # Train the model
            logger.info(f"Training {self.model_type} model")
            self.detector.train(features_df)
            
            # Update metadata
            self.training_metadata['logs_processed'] = len(logs)
            self.training_metadata['completed_at'] = datetime.now().isoformat()
            self.training_metadata['success'] = True
            
            logger.info(f"Model training completed successfully")
            return self.training_metadata
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            self.training_metadata['success'] = False
            self.training_metadata['errors'].append(str(e))
            self.training_metadata['completed_at'] = datetime.now().isoformat()
            return self.training_metadata
    
    def train_from_file(self, file_path: str) -> Dict[str, Any]:
        """Train models from a single log file.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Training metadata dictionary
        """
        self.training_metadata['started_at'] = datetime.now().isoformat()
        
        try:
            # Ingest the file
            logger.info(f"Ingesting log file: {file_path}")
            logs, metadata = self.ingestor.ingest_file(file_path)
            
            self.training_metadata['files_processed'] = 1
            self.training_metadata['file_types'] = [metadata['log_type']]
            
            # Train from the ingested logs
            result = self.train_from_logs(logs)
            
            # Add file metadata
            result['file_metadata'] = metadata
            
            return result
            
        except Exception as e:
            logger.error(f"Error training from file {file_path}: {str(e)}")
            self.training_metadata['success'] = False
            self.training_metadata['errors'].append(str(e))
            self.training_metadata['completed_at'] = datetime.now().isoformat()
            return self.training_metadata
    
    def train_from_directory(self, dir_path: str, recursive: bool = True) -> Dict[str, Any]:
        """Train models from all log files in a directory.
        
        Args:
            dir_path: Path to the directory containing log files
            recursive: Whether to recursively search subdirectories
            
        Returns:
            Training metadata dictionary
        """
        self.training_metadata['started_at'] = datetime.now().isoformat()
        
        try:
            # Find all log files
            log_files = []
            file_types = set()
            
            # Walk through directory
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    # Check if file has a log extension
                    if file.endswith(('.log', '.json', '.csv', '.jsonl', '.syslog', '.gz')):
                        log_files.append(os.path.join(root, file))
                
                # Skip subdirectories if not recursive
                if not recursive:
                    break
            
            if not log_files:
                logger.warning(f"No log files found in {dir_path}")
                self.training_metadata['success'] = False
                self.training_metadata['errors'].append(f"No log files found in {dir_path}")
                self.training_metadata['completed_at'] = datetime.now().isoformat()
                return self.training_metadata
            
            # Process files and combine logs
            all_logs = []
            max_workers = min(config.get("max_threads", 4), len(log_files))
            
            logger.info(f"Processing {len(log_files)} log files with {max_workers} workers")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {
                    executor.submit(self.ingestor.ingest_file, file_path): file_path 
                    for file_path in log_files
                }
                
                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        logs, metadata = future.result()
                        all_logs.extend(logs)
                        file_types.add(metadata['log_type'])
                        logger.info(f"Processed {len(logs)} entries from {file_path}")
                    except Exception as e:
                        logger.error(f"Error processing {file_path}: {str(e)}")
                        self.training_metadata['errors'].append(f"Error processing {file_path}: {str(e)}")
            
            # Update metadata
            self.training_metadata['files_processed'] = len(log_files)
            self.training_metadata['file_types'] = list(file_types)
            
            # Train from all logs
            if all_logs:
                logger.info(f"Training with {len(all_logs)} log entries from {len(log_files)} files")
                result = self.train_from_logs(all_logs)
                return result
            else:
                logger.warning("No valid logs found for training")
                self.training_metadata['success'] = False
                self.training_metadata['errors'].append("No valid logs found for training")
                self.training_metadata['completed_at'] = datetime.now().isoformat()
                return self.training_metadata
                
        except Exception as e:
            logger.error(f"Error training from directory {dir_path}: {str(e)}")
            self.training_metadata['success'] = False
            self.training_metadata['errors'].append(str(e))
            self.training_metadata['completed_at'] = datetime.now().isoformat()
            return self.training_metadata 