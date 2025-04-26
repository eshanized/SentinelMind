import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QGridLayout, QFrame, QProgressBar, QFileDialog, QComboBox,
    QLineEdit, QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QSpinBox, QDoubleSpinBox, QCheckBox, QMessageBox,
    QSplitter, QScrollArea
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QThread
from PyQt6.QtGui import QFont

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.gui.scan_thread import ScanThread

logger = get_logger()
config = get_config()


class ScanTab(QWidget):
    """The scan tab for scanning log files for threats."""
    
    def __init__(self, parent):
        """Initialize the scan tab.
        
        Args:
            parent: The parent widget (MainWindow)
        """
        super().__init__(parent)
        
        # Store reference to main window
        self.main_window = parent
        
        # Initialize variables
        self.scan_thread = None
        self.scan_running = False
        self.file_path = ""
        
        # Create UI
        self._create_ui()
        
        logger.info("Scan tab initialized")
    
    def _create_ui(self):
        """Create the UI components."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        
        # Create scan options group
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout(options_group)
        
        # Create file path input
        file_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("Select a log file...")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path_input)
        file_layout.addWidget(browse_button)
        options_layout.addRow("Log File:", file_layout)
        
        # Create model type selection
        self.model_type_combo = QComboBox()
        self.model_type_combo.addItems(["isolation_forest", "autoencoder"])
        options_layout.addRow("Model Type:", self.model_type_combo)
        
        # Create threshold input
        self.threshold_spinner = QDoubleSpinBox()
        self.threshold_spinner.setRange(0.0, 1.0)
        self.threshold_spinner.setSingleStep(0.05)
        self.threshold_spinner.setValue(config.get("anomaly_threshold", 0.8))
        options_layout.addRow("Detection Threshold:", self.threshold_spinner)
        
        # Add options group to main layout
        main_layout.addWidget(options_group)
        
        # Create scan status group
        status_group = QGroupBox("Scan Status")
        status_layout = QVBoxLayout(status_group)
        
        # Create scan progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar)
        
        # Create scan status label
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        
        # Add status group to main layout
        main_layout.addWidget(status_group)
        
        # Create scan results group
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        # Create results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Timestamp", "Source IP", "Username", "Event Type", "Severity", "Action"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setAlternatingRowColors(True)
        results_layout.addWidget(self.results_table)
        
        # Add results group to main layout
        main_layout.addWidget(results_group)
        
        # Create button layout
        button_layout = QHBoxLayout()
        
        # Create scan button
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        # Create cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)
        button_layout.addWidget(self.cancel_button)
        
        # Create export button
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        button_layout.addWidget(self.export_button)
        
        # Add button layout to main layout
        main_layout.addLayout(button_layout)
        
        # Set stretch factors for groups
        main_layout.setStretchFactor(results_group, 1)
    
    def browse_file(self):
        """Open a file dialog to select a log file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Log File",
            "",
            "Log Files (*.log *.json *.csv *.jsonl *.syslog);;All Files (*.*)"
        )
        
        if file_path:
            self.set_file_path(file_path)
    
    def set_file_path(self, file_path: str):
        """Set the log file path.
        
        Args:
            file_path: The path to the log file
        """
        self.file_path = file_path
        self.file_path_input.setText(file_path)
    
    def start_scan(self):
        """Start scanning the log file."""
        # Check if a file is selected
        if not self.file_path:
            QMessageBox.warning(
                self,
                "No File Selected",
                "Please select a log file to scan."
            )
            return
            
        # Check if scan is already running
        if self.scan_running:
            return
            
        # Update UI
        self.scan_running = True
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.export_button.setEnabled(False)
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing scan...")
        
        # Get scan options
        model_type = self.model_type_combo.currentText()
        threshold = self.threshold_spinner.value()
        
        # Create scan thread
        self.scan_thread = ScanThread(
            file_path=self.file_path,
            model_type=model_type,
            threshold=threshold
        )
        
        # Connect signals
        self.scan_thread.status_update.connect(self.update_status)
        self.scan_thread.progress_update.connect(self.update_progress)
        self.scan_thread.anomaly_detected.connect(self.add_anomaly)
        self.scan_thread.scan_complete.connect(self.scan_completed)
        self.scan_thread.scan_error.connect(self.scan_error)
        
        # Start scan thread
        self.scan_thread.start()
    
    def cancel_scan(self):
        """Cancel the running scan."""
        if self.scan_thread and self.scan_running:
            # Terminate the thread
            self.scan_thread.terminate()
            
            # Update UI
            self.scan_running = False
            self.scan_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            self.status_label.setText("Scan cancelled")
    
    def export_results(self):
        """Export scan results to a file."""
        self.main_window.export_results()
    
    def update_status(self, status: str):
        """Update the scan status.
        
        Args:
            status: The current status text
        """
        self.status_label.setText(status)
    
    def update_progress(self, progress: int):
        """Update the scan progress.
        
        Args:
            progress: The current progress value (0-100)
        """
        self.progress_bar.setValue(progress)
    
    def add_anomaly(self, anomaly: Dict[str, Any]):
        """Add an anomaly to the results table.
        
        Args:
            anomaly: Anomaly data dictionary
        """
        # Get current row count
        row = self.results_table.rowCount()
        
        # Insert a new row
        self.results_table.insertRow(row)
        
        # Format timestamp
        timestamp = anomaly.get("timestamp", "")
        try:
            if timestamp:
                import dateutil.parser
                dt = dateutil.parser.parse(timestamp)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        
        # Add cells
        self.results_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.results_table.setItem(row, 1, QTableWidgetItem(anomaly.get("source_ip", "")))
        self.results_table.setItem(row, 2, QTableWidgetItem(anomaly.get("username", "")))
        self.results_table.setItem(row, 3, QTableWidgetItem(anomaly.get("event_type", "")))
        
        # Format severity
        severity = anomaly.get("severity", 0)
        severity_item = QTableWidgetItem(f"{severity:.2f}")
        if severity >= 0.8:
            severity_item.setBackground(Qt.GlobalColor.red)
            severity_item.setForeground(Qt.GlobalColor.white)
        elif severity >= 0.5:
            severity_item.setBackground(Qt.GlobalColor.yellow)
        self.results_table.setItem(row, 4, severity_item)
        
        # Add action
        self.results_table.setItem(row, 5, QTableWidgetItem(anomaly.get("action", "")))
    
    def scan_completed(self, anomaly_count: int, chain_count: int):
        """Handle scan completion.
        
        Args:
            anomaly_count: Number of anomalies detected
            chain_count: Number of attack chains identified
        """
        # Update UI
        self.scan_running = False
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.export_button.setEnabled(True)
        self.progress_bar.setValue(100)
        
        # Update status
        if anomaly_count > 0:
            self.status_label.setText(
                f"Scan complete: {anomaly_count} anomalies detected, "
                f"{chain_count} attack chains identified."
            )
        else:
            self.status_label.setText("Scan complete: No anomalies detected.")
        
        # Refresh main window data
        self.main_window.refresh_data()
    
    def scan_error(self, error_message: str):
        """Handle scan error.
        
        Args:
            error_message: Error message
        """
        # Update UI
        self.scan_running = False
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        
        # Update status
        self.status_label.setText(f"Error: {error_message}")
        
        # Show error message
        QMessageBox.critical(
            self,
            "Scan Error",
            f"An error occurred during the scan:\n\n{error_message}"
        ) 