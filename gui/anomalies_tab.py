import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QGridLayout, QFrame, QProgressBar, QFileDialog, QComboBox,
    QLineEdit, QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QSpinBox, QDoubleSpinBox, QCheckBox, QMessageBox,
    QSplitter, QScrollArea, QTabWidget, QTextEdit, QApplication
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.core.storage import StorageHandler

logger = get_logger()
config = get_config()


class AnomaliesTab(QWidget):
    """The anomalies tab displaying detected anomalies."""
    
    def __init__(self, parent):
        """Initialize the anomalies tab.
        
        Args:
            parent: The parent widget (MainWindow)
        """
        super().__init__(parent)
        
        # Store reference to main window
        self.main_window = parent
        
        # Initialize storage
        self.storage = StorageHandler()
        
        # Initialize selected anomaly
        self.selected_anomaly = None
        
        # Create UI
        self._create_ui()
        
        logger.info("Anomalies tab initialized")
    
    def _create_ui(self):
        """Create the UI components."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        
        # Create filter group
        filter_group = QGroupBox("Filter Anomalies")
        filter_layout = QHBoxLayout(filter_group)
        
        # Create filter controls
        filter_layout.addWidget(QLabel("Minimum Severity:"))
        self.severity_filter = QDoubleSpinBox()
        self.severity_filter.setRange(0.0, 1.0)
        self.severity_filter.setSingleStep(0.1)
        self.severity_filter.setValue(0.5)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addWidget(QLabel("Source IP:"))
        self.ip_filter = QLineEdit()
        filter_layout.addWidget(self.ip_filter)
        
        filter_layout.addWidget(QLabel("Username:"))
        self.username_filter = QLineEdit()
        filter_layout.addWidget(self.username_filter)
        
        filter_layout.addWidget(QLabel("Event Type:"))
        self.event_type_filter = QComboBox()
        self.event_type_filter.addItem("All")
        filter_layout.addWidget(self.event_type_filter)
        
        # Create apply filter button
        self.apply_filter_button = QPushButton("Apply Filters")
        self.apply_filter_button.clicked.connect(self.apply_filters)
        filter_layout.addWidget(self.apply_filter_button)
        
        # Create clear filter button
        self.clear_filter_button = QPushButton("Clear Filters")
        self.clear_filter_button.clicked.connect(self.clear_filters)
        filter_layout.addWidget(self.clear_filter_button)
        
        # Add filter group to main layout
        main_layout.addWidget(filter_group)
        
        # Create splitter for table and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Create anomalies table
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(7)
        self.anomalies_table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Source IP", "Username", "Event Type", "Severity", "Action"
        ])
        self.anomalies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.anomalies_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.anomalies_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.anomalies_table.setAlternatingRowColors(True)
        self.anomalies_table.setSortingEnabled(True)
        self.anomalies_table.itemSelectionChanged.connect(self.selection_changed)
        
        # Add table to splitter
        splitter.addWidget(self.anomalies_table)
        
        # Create detail view
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        
        # Create detail tabs
        detail_tabs = QTabWidget()
        
        # Create summary tab
        summary_tab = QWidget()
        summary_layout = QFormLayout(summary_tab)
        
        self.detail_timestamp = QLineEdit()
        self.detail_timestamp.setReadOnly(True)
        summary_layout.addRow("Timestamp:", self.detail_timestamp)
        
        self.detail_source_ip = QLineEdit()
        self.detail_source_ip.setReadOnly(True)
        summary_layout.addRow("Source IP:", self.detail_source_ip)
        
        self.detail_dest_ip = QLineEdit()
        self.detail_dest_ip.setReadOnly(True)
        summary_layout.addRow("Destination IP:", self.detail_dest_ip)
        
        self.detail_username = QLineEdit()
        self.detail_username.setReadOnly(True)
        summary_layout.addRow("Username:", self.detail_username)
        
        self.detail_event_type = QLineEdit()
        self.detail_event_type.setReadOnly(True)
        summary_layout.addRow("Event Type:", self.detail_event_type)
        
        self.detail_action = QLineEdit()
        self.detail_action.setReadOnly(True)
        summary_layout.addRow("Action:", self.detail_action)
        
        self.detail_resource = QLineEdit()
        self.detail_resource.setReadOnly(True)
        summary_layout.addRow("Resource:", self.detail_resource)
        
        self.detail_status = QLineEdit()
        self.detail_status.setReadOnly(True)
        summary_layout.addRow("Status:", self.detail_status)
        
        self.detail_severity = QLineEdit()
        self.detail_severity.setReadOnly(True)
        summary_layout.addRow("Severity:", self.detail_severity)
        
        self.detail_algorithm = QLineEdit()
        self.detail_algorithm.setReadOnly(True)
        summary_layout.addRow("Detection Algorithm:", self.detail_algorithm)
        
        # Add summary tab
        detail_tabs.addTab(summary_tab, "Summary")
        
        # Create raw data tab
        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        
        self.raw_data_text = QTextEdit()
        self.raw_data_text.setReadOnly(True)
        raw_layout.addWidget(self.raw_data_text)
        
        # Add raw data tab
        detail_tabs.addTab(raw_tab, "Raw Data")
        
        # Add tabs to detail layout
        detail_layout.addWidget(detail_tabs)
        
        # Add detail widget to splitter
        splitter.addWidget(detail_widget)
        
        # Set splitter sizes
        splitter.setSizes([600, 300])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
        
        # Create status bar
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.count_label = QLabel("0 anomalies")
        status_layout.addWidget(self.count_label)
        
        # Add status bar to main layout
        main_layout.addLayout(status_layout)
        
        # Set stretch factor for main components
        main_layout.setStretchFactor(splitter, 1)
    
    def refresh_data(self):
        """Refresh the anomalies data."""
        # Build filters
        filters = {}
        
        if self.severity_filter.value() > 0:
            filters["min_severity"] = self.severity_filter.value()
            
        if self.ip_filter.text():
            filters["source_ip"] = self.ip_filter.text()
            
        if self.username_filter.text():
            filters["username"] = self.username_filter.text()
            
        if self.event_type_filter.currentText() != "All":
            filters["event_type"] = self.event_type_filter.currentText()
        
        try:
            # Show busy cursor
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            
            # Get anomalies from storage
            anomalies = self.storage.get_anomalies(
                limit=config.get("gui.table_page_size", 100),
                filters=filters
            )
            
            # Update event type filter options
            self._update_event_type_filter()
            
            # Update table
            self._update_anomalies_table(anomalies)
            
            # Update status
            self.status_label.setText(f"Data refreshed at {datetime.now().strftime('%H:%M:%S')}")
            self.count_label.setText(f"{len(anomalies)} anomalies")
            
        except Exception as e:
            logger.error(f"Error refreshing anomalies data: {str(e)}")
            self.status_label.setText(f"Error: {str(e)}")
            
        finally:
            # Restore cursor
            QApplication.restoreOverrideCursor()
    
    def _update_event_type_filter(self):
        """Update the event type filter options."""
        try:
            # Remember current selection
            current_selection = self.event_type_filter.currentText()
            
            # Clear the combo box
            self.event_type_filter.clear()
            
            # Add "All" option
            self.event_type_filter.addItem("All")
            
            # Get all anomalies to extract event types
            anomalies = self.storage.get_anomalies(limit=1000)
            
            # Extract unique event types
            event_types = set()
            for anomaly in anomalies:
                event_type = anomaly.get("event_type")
                if event_type:
                    event_types.add(event_type)
            
            # Add event types to combo box
            for event_type in sorted(event_types):
                self.event_type_filter.addItem(event_type)
            
            # Restore selection if possible
            index = self.event_type_filter.findText(current_selection)
            if index >= 0:
                self.event_type_filter.setCurrentIndex(index)
            
        except Exception as e:
            logger.error(f"Error updating event type filter: {str(e)}")
    
    def _update_anomalies_table(self, anomalies: List[Dict[str, Any]]):
        """Update the anomalies table with new data.
        
        Args:
            anomalies: List of anomaly dictionaries
        """
        # Clear the table
        self.anomalies_table.setRowCount(0)
        
        # Add rows for each anomaly
        for row, anomaly in enumerate(anomalies):
            self.anomalies_table.insertRow(row)
            
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
            self.anomalies_table.setItem(row, 0, QTableWidgetItem(str(anomaly.get("id", ""))))
            self.anomalies_table.setItem(row, 1, QTableWidgetItem(timestamp))
            self.anomalies_table.setItem(row, 2, QTableWidgetItem(anomaly.get("source_ip", "")))
            self.anomalies_table.setItem(row, 3, QTableWidgetItem(anomaly.get("username", "")))
            self.anomalies_table.setItem(row, 4, QTableWidgetItem(anomaly.get("event_type", "")))
            
            # Format severity
            severity = anomaly.get("severity", 0)
            severity_item = QTableWidgetItem(f"{severity:.2f}")
            if severity >= 0.8:
                severity_item.setBackground(Qt.GlobalColor.red)
                severity_item.setForeground(Qt.GlobalColor.white)
            elif severity >= 0.5:
                severity_item.setBackground(Qt.GlobalColor.yellow)
            self.anomalies_table.setItem(row, 5, severity_item)
            
            # Add action
            self.anomalies_table.setItem(row, 6, QTableWidgetItem(anomaly.get("action", "")))
            
            # Store the full anomaly data in the ID item
            self.anomalies_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, anomaly)
    
    def selection_changed(self):
        """Handle table selection changes."""
        selected_rows = self.anomalies_table.selectedItems()
        if not selected_rows:
            self._clear_details()
            return
            
        # Get the anomaly data from the ID cell
        id_item = self.anomalies_table.item(selected_rows[0].row(), 0)
        if not id_item:
            self._clear_details()
            return
            
        anomaly = id_item.data(Qt.ItemDataRole.UserRole)
        if not anomaly:
            self._clear_details()
            return
            
        self.selected_anomaly = anomaly
        self._update_details()
    
    def _clear_details(self):
        """Clear the detail view."""
        self.detail_timestamp.setText("")
        self.detail_source_ip.setText("")
        self.detail_dest_ip.setText("")
        self.detail_username.setText("")
        self.detail_event_type.setText("")
        self.detail_action.setText("")
        self.detail_resource.setText("")
        self.detail_status.setText("")
        self.detail_severity.setText("")
        self.detail_algorithm.setText("")
        self.raw_data_text.setText("")
    
    def _update_details(self):
        """Update the detail view with the selected anomaly."""
        if not self.selected_anomaly:
            self._clear_details()
            return
            
        # Update summary fields
        self.detail_timestamp.setText(self.selected_anomaly.get("timestamp", ""))
        self.detail_source_ip.setText(self.selected_anomaly.get("source_ip", ""))
        self.detail_dest_ip.setText(self.selected_anomaly.get("destination_ip", ""))
        self.detail_username.setText(self.selected_anomaly.get("username", ""))
        self.detail_event_type.setText(self.selected_anomaly.get("event_type", ""))
        self.detail_action.setText(self.selected_anomaly.get("action", ""))
        self.detail_resource.setText(self.selected_anomaly.get("resource", ""))
        self.detail_status.setText(self.selected_anomaly.get("status", ""))
        
        severity = self.selected_anomaly.get("severity", 0)
        self.detail_severity.setText(f"{severity:.2f}")
        
        self.detail_algorithm.setText(self.selected_anomaly.get("detection_algorithm", ""))
        
        # Update raw data tab
        import json
        raw_data = self.selected_anomaly.get("raw_data", {})
        if raw_data:
            self.raw_data_text.setText(json.dumps(raw_data, indent=2))
        else:
            self.raw_data_text.setText("")
    
    def apply_filters(self):
        """Apply the current filters and refresh the data."""
        self.refresh_data()
    
    def clear_filters(self):
        """Clear all filters and refresh the data."""
        self.severity_filter.setValue(0.0)
        self.ip_filter.setText("")
        self.username_filter.setText("")
        self.event_type_filter.setCurrentIndex(0)  # "All"
        
        self.refresh_data() 