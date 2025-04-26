import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QGridLayout, QFrame, QProgressBar, QFileDialog, QComboBox,
    QLineEdit, QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QSpinBox, QDoubleSpinBox, QCheckBox, QMessageBox,
    QDialogButtonBox, QTextEdit
)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.gui.training_thread import TrainingThread

logger = get_logger()
config = get_config()


class TrainingDialog(QDialog):
    """Dialog for training machine learning models."""
    
    def __init__(self, parent=None):
        """Initialize the training dialog.
        
        Args:
            parent: The parent widget
        """
        super().__init__(parent)
        
        # Set dialog properties
        self.setWindowTitle("Train Machine Learning Models")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)
        
        # Initialize variables
        self.training_thread = None
        self.training_running = False
        self.data_path = ""
        
        # Create UI
        self._create_ui()
        
        logger.info("Training dialog initialized")
    
    def _create_ui(self):
        """Create the UI components."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        
        # Create training options group
        options_group = QGroupBox("Training Options")
        options_layout = QFormLayout(options_group)
        
        # Create data path input
        data_layout = QHBoxLayout()
        self.data_path_input = QLineEdit()
        self.data_path_input.setReadOnly(True)
        self.data_path_input.setPlaceholderText("Select log file or directory...")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_data)
        data_layout.addWidget(self.data_path_input)
        data_layout.addWidget(browse_button)
        options_layout.addRow("Training Data:", data_layout)
        
        # Create model type selection
        self.model_type_combo = QComboBox()
        self.model_type_combo.addItems(["isolation_forest", "autoencoder"])
        options_layout.addRow("Model Type:", self.model_type_combo)
        
        # Create recursive option for directories
        self.recursive_checkbox = QCheckBox("Process subdirectories recursively")
        self.recursive_checkbox.setChecked(True)
        options_layout.addRow("", self.recursive_checkbox)
        
        # Create force retrain option
        self.force_checkbox = QCheckBox("Force retraining (overwrite existing model)")
        self.force_checkbox.setChecked(False)
        options_layout.addRow("", self.force_checkbox)
        
        # Add options group to main layout
        main_layout.addWidget(options_group)
        
        # Create training status group
        status_group = QGroupBox("Training Status")
        status_layout = QVBoxLayout(status_group)
        
        # Create training progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar)
        
        # Create training status label
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        
        # Create log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)
        status_layout.addWidget(self.log_output)
        
        # Add status group to main layout
        main_layout.addWidget(status_group)
        
        # Create button box
        button_box = QDialogButtonBox()
        
        # Create train button
        self.train_button = QPushButton("Start Training")
        self.train_button.clicked.connect(self.start_training)
        button_box.addButton(self.train_button, QDialogButtonBox.ButtonRole.ActionRole)
        
        # Create cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_training)
        self.cancel_button.setEnabled(False)
        button_box.addButton(self.cancel_button, QDialogButtonBox.ButtonRole.RejectRole)
        
        # Create close button
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        button_box.addButton(self.close_button, QDialogButtonBox.ButtonRole.AcceptRole)
        
        # Add button box to main layout
        main_layout.addWidget(button_box)
    
    def browse_data(self):
        """Open a file dialog to select training data."""
        # Show file dialog
        options = QFileDialog.Option.ShowDirsOnly
        
        # Get file or directory
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Training Data Directory",
            "",
            options
        )
        
        # If user cancelled, try file selection instead
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Training Data File",
                "",
                "Log Files (*.log *.json *.csv *.jsonl *.syslog);;All Files (*.*)"
            )
        
        if path:
            self.set_data_path(path)
    
    def set_data_path(self, data_path: str):
        """Set the training data path.
        
        Args:
            data_path: The path to the training data
        """
        self.data_path = data_path
        self.data_path_input.setText(data_path)
    
    def start_training(self):
        """Start training the model."""
        # Check if a path is selected
        if not self.data_path:
            QMessageBox.warning(
                self,
                "No Data Selected",
                "Please select a log file or directory for training."
            )
            return
            
        # Check if training is already running
        if self.training_running:
            return
            
        # Update UI
        self.training_running = True
        self.train_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.close_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing training...")
        self.log_output.clear()
        
        # Get training options
        model_type = self.model_type_combo.currentText()
        recursive = self.recursive_checkbox.isChecked()
        force = self.force_checkbox.isChecked()
        
        # Create training thread
        self.training_thread = TrainingThread(
            data_path=self.data_path,
            model_type=model_type,
            recursive=recursive,
            force=force
        )
        
        # Connect signals
        self.training_thread.status_update.connect(self.update_status)
        self.training_thread.progress_update.connect(self.update_progress)
        self.training_thread.log_update.connect(self.update_log)
        self.training_thread.training_complete.connect(self.training_completed)
        self.training_thread.training_error.connect(self.training_error)
        
        # Start training thread
        self.training_thread.start()
    
    def cancel_training(self):
        """Cancel the running training."""
        if self.training_thread and self.training_running:
            # Terminate the thread
            self.training_thread.terminate()
            
            # Update UI
            self.training_running = False
            self.train_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            self.close_button.setEnabled(True)
            self.status_label.setText("Training cancelled")
            self.update_log("Training cancelled by user")
    
    def update_status(self, status: str):
        """Update the training status.
        
        Args:
            status: The current status text
        """
        self.status_label.setText(status)
    
    def update_progress(self, progress: int):
        """Update the training progress.
        
        Args:
            progress: The current progress value (0-100)
        """
        self.progress_bar.setValue(progress)
    
    def update_log(self, message: str):
        """Update the log output.
        
        Args:
            message: The log message to add
        """
        self.log_output.append(message)
        
        # Scroll to bottom
        self.log_output.verticalScrollBar().setValue(
            self.log_output.verticalScrollBar().maximum()
        )
    
    def training_completed(self, success: bool, metadata: Dict[str, Any]):
        """Handle training completion.
        
        Args:
            success: Whether training was successful
            metadata: Training metadata dictionary
        """
        # Update UI
        self.training_running = False
        self.train_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.close_button.setEnabled(True)
        
        if success:
            # Update progress
            self.progress_bar.setValue(100)
            
            # Update status
            self.status_label.setText("Training completed successfully")
            
            # Update log
            self.update_log("Training completed successfully")
            self.update_log(f"Model type: {metadata.get('model_type', 'unknown')}")
            self.update_log(f"Files processed: {metadata.get('files_processed', 0)}")
            self.update_log(f"Logs processed: {metadata.get('logs_processed', 0)}")
            self.update_log(f"Features extracted: {metadata.get('features_extracted', 0)}")
            
            # Show success message
            QMessageBox.information(
                self,
                "Training Complete",
                "Model training completed successfully."
            )
        else:
            # Update status
            self.status_label.setText("Training failed")
            
            # Update log
            self.update_log("Training failed")
            
            if 'errors' in metadata and metadata['errors']:
                for error in metadata['errors']:
                    self.update_log(f"Error: {error}")
    
    def training_error(self, error_message: str):
        """Handle training error.
        
        Args:
            error_message: Error message
        """
        # Update UI
        self.training_running = False
        self.train_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.close_button.setEnabled(True)
        
        # Update status
        self.status_label.setText(f"Error: {error_message}")
        
        # Update log
        self.update_log(f"Error: {error_message}")
        
        # Show error message
        QMessageBox.critical(
            self,
            "Training Error",
            f"An error occurred during training:\n\n{error_message}"
        )