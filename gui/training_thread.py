import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime
import time

from PyQt6.QtCore import QThread, pyqtSignal

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.core.trainer import ModelTrainer

logger = get_logger()
config = get_config()


class TrainingThread(QThread):
    """Thread for training machine learning models."""
    
    # Define signals
    status_update = pyqtSignal(str)
    progress_update = pyqtSignal(int)
    log_update = pyqtSignal(str)
    training_complete = pyqtSignal(bool, dict)  # success, metadata
    training_error = pyqtSignal(str)
    
    def __init__(self, data_path: str, model_type: str = "isolation_forest", recursive: bool = True, force: bool = False):
        """Initialize the training thread.
        
        Args:
            data_path: Path to training data file or directory
            model_type: Type of model to train
            recursive: Whether to recursively process directories
            force: Whether to force retraining if a model exists
        """
        super().__init__()
        
        self.data_path = data_path
        self.model_type = model_type
        self.recursive = recursive
        self.force = force
        
        # Initialize trainer
        self.trainer = None
        
    def run(self):
        """Run the training thread."""
        try:
            # Initialize trainer
            self.status_update.emit("Initializing trainer...")
            self.log_update.emit(f"Initializing trainer for {self.model_type} model...")
            self.trainer = ModelTrainer(model_type=self.model_type)
            
            # Check if training data is a file or directory
            if os.path.isfile(self.data_path):
                # Train from file
                self.status_update.emit(f"Training from file: {self.data_path}")
                self.log_update.emit(f"Training from file: {self.data_path}")
                self.progress_update.emit(10)  # Initial progress
                
                # Start training
                metadata = self.trainer.train_from_file(self.data_path)
                
            else:
                # Train from directory
                self.status_update.emit(f"Training from directory: {self.data_path}")
                self.log_update.emit(f"Training from directory: {self.data_path}")
                self.log_update.emit(f"Recursive mode: {self.recursive}")
                self.progress_update.emit(10)  # Initial progress
                
                # Start training
                metadata = self.trainer.train_from_directory(self.data_path, recursive=self.recursive)
            
            # Check training result
            success = metadata.get('success', False)
            
            if success:
                # Log training details
                self.log_update.emit(f"Files processed: {metadata.get('files_processed', 0)}")
                self.log_update.emit(f"Logs processed: {metadata.get('logs_processed', 0)}")
                self.log_update.emit(f"Features extracted: {metadata.get('features_extracted', 0)}")
                
                if 'file_types' in metadata:
                    self.log_update.emit(f"File types: {', '.join(metadata.get('file_types', []))}")
                
                # Calculate training duration
                if 'started_at' in metadata and 'completed_at' in metadata:
                    try:
                        start = datetime.fromisoformat(metadata['started_at'])
                        end = datetime.fromisoformat(metadata['completed_at'])
                        duration = (end - start).total_seconds()
                        self.log_update.emit(f"Training duration: {duration:.2f} seconds")
                    except:
                        pass
                
                # Complete
                self.status_update.emit("Training complete")
                self.progress_update.emit(100)
                
                # Emit completion signal
                self.training_complete.emit(True, metadata)
                
            else:
                # Log errors
                if 'errors' in metadata and metadata['errors']:
                    for error in metadata['errors']:
                        self.log_update.emit(f"Error: {error}")
                
                # Emit completion signal with failure
                self.status_update.emit("Training failed")
                self.progress_update.emit(0)
                self.training_complete.emit(False, metadata)
            
        except Exception as e:
            logger.error(f"Error during training: {str(e)}")
            self.training_error.emit(str(e)) 