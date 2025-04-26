import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QGridLayout, QFrame, QProgressBar, QFileDialog, QComboBox,
    QLineEdit, QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QSpinBox, QDoubleSpinBox, QCheckBox, QMessageBox,
    QSplitter, QScrollArea, QTabWidget, QTextEdit, QTreeWidget, QTreeWidgetItem, QApplication
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QColor

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.core.storage import StorageHandler

logger = get_logger()
config = get_config()


class AttackChainsTab(QWidget):
    """The attack chains tab displaying potential attack chains."""
    
    def __init__(self, parent):
        """Initialize the attack chains tab.
        
        Args:
            parent: The parent widget (MainWindow)
        """
        super().__init__(parent)
        
        # Store reference to main window
        self.main_window = parent
        
        # Initialize storage
        self.storage = StorageHandler()
        
        # Initialize selected chain
        self.selected_chain = None
        
        # Create UI
        self._create_ui()
        
        logger.info("Attack chains tab initialized")
    
    def _create_ui(self):
        """Create the UI components."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        
        # Create splitter for table and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Create chains table
        self.chains_table = QTableWidget()
        self.chains_table.setColumnCount(7)
        self.chains_table.setHorizontalHeaderLabels([
            "ID", "Name", "Start Time", "End Time", "Severity", "Confidence", "Anomalies"
        ])
        self.chains_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.chains_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.chains_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.chains_table.setAlternatingRowColors(True)
        self.chains_table.setSortingEnabled(True)
        self.chains_table.itemSelectionChanged.connect(self.selection_changed)
        
        # Add table to splitter
        splitter.addWidget(self.chains_table)
        
        # Create detail view
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        
        # Create detail tabs
        detail_tabs = QTabWidget()
        
        # Create summary tab
        summary_tab = QWidget()
        summary_layout = QFormLayout(summary_tab)
        
        self.detail_name = QLineEdit()
        self.detail_name.setReadOnly(True)
        summary_layout.addRow("Name:", self.detail_name)
        
        self.detail_entity = QLineEdit()
        self.detail_entity.setReadOnly(True)
        summary_layout.addRow("Entity:", self.detail_entity)
        
        time_layout = QHBoxLayout()
        
        self.detail_start_time = QLineEdit()
        self.detail_start_time.setReadOnly(True)
        time_layout.addWidget(QLabel("Start:"))
        time_layout.addWidget(self.detail_start_time)
        
        self.detail_end_time = QLineEdit()
        self.detail_end_time.setReadOnly(True)
        time_layout.addWidget(QLabel("End:"))
        time_layout.addWidget(self.detail_end_time)
        
        self.detail_duration = QLineEdit()
        self.detail_duration.setReadOnly(True)
        time_layout.addWidget(QLabel("Duration:"))
        time_layout.addWidget(self.detail_duration)
        
        summary_layout.addRow("Timeline:", time_layout)
        
        score_layout = QHBoxLayout()
        
        self.detail_severity = QLineEdit()
        self.detail_severity.setReadOnly(True)
        score_layout.addWidget(QLabel("Severity:"))
        score_layout.addWidget(self.detail_severity)
        
        self.detail_confidence = QLineEdit()
        self.detail_confidence.setReadOnly(True)
        score_layout.addWidget(QLabel("Confidence:"))
        score_layout.addWidget(self.detail_confidence)
        
        self.detail_risk_level = QLineEdit()
        self.detail_risk_level.setReadOnly(True)
        score_layout.addWidget(QLabel("Risk Level:"))
        score_layout.addWidget(self.detail_risk_level)
        
        summary_layout.addRow("Risk Scores:", score_layout)
        
        # Add MITRE techniques section
        mitre_layout = QVBoxLayout()
        mitre_layout.addWidget(QLabel("MITRE ATT&CK Techniques:"))
        
        self.mitre_techniques_list = QTreeWidget()
        self.mitre_techniques_list.setHeaderLabels(["Technique", "Description"])
        self.mitre_techniques_list.setColumnWidth(0, 150)
        self.mitre_techniques_list.setAlternatingRowColors(True)
        mitre_layout.addWidget(self.mitre_techniques_list)
        
        # Add link to MITRE ATT&CK
        mitre_link_layout = QHBoxLayout()
        mitre_link_layout.addWidget(QLabel("View in MITRE ATT&CK:"))
        
        self.mitre_link_button = QPushButton("Open in Browser")
        self.mitre_link_button.clicked.connect(self.open_mitre_link)
        mitre_link_layout.addWidget(self.mitre_link_button)
        mitre_link_layout.addStretch()
        
        mitre_layout.addLayout(mitre_link_layout)
        
        summary_layout.addRow("MITRE Mapping:", QWidget())  # Placeholder
        summary_layout.addRow("", QWidget())  # Spacer
        
        # Add layout to QWidget to use in FormLayout
        mitre_widget = QWidget()
        mitre_widget.setLayout(mitre_layout)
        summary_layout.addRow("", mitre_widget)
        
        # Add summary tab
        detail_tabs.addTab(summary_tab, "Summary")
        
        # Create anomalies tab
        anomalies_tab = QWidget()
        anomalies_layout = QVBoxLayout(anomalies_tab)
        
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(6)
        self.anomalies_table.setHorizontalHeaderLabels([
            "Timestamp", "Source IP", "Username", "Event Type", "Action", "Severity"
        ])
        self.anomalies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.anomalies_table.setAlternatingRowColors(True)
        
        anomalies_layout.addWidget(self.anomalies_table)
        
        # Add anomalies tab
        detail_tabs.addTab(anomalies_tab, "Anomalies")
        
        # Create risk factors tab
        risk_tab = QWidget()
        risk_layout = QVBoxLayout(risk_tab)
        
        self.risk_factors_list = QTreeWidget()
        self.risk_factors_list.setHeaderLabels(["Risk Factor", "Impact"])
        self.risk_factors_list.setColumnWidth(0, 400)
        self.risk_factors_list.setAlternatingRowColors(True)
        
        risk_layout.addWidget(self.risk_factors_list)
        
        # Add risk factors tab
        detail_tabs.addTab(risk_tab, "Risk Factors")
        
        # Add tabs to detail layout
        detail_layout.addWidget(detail_tabs)
        
        # Add detail widget to splitter
        splitter.addWidget(detail_widget)
        
        # Set splitter sizes
        splitter.setSizes([500, 400])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
        
        # Create status bar
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.count_label = QLabel("0 attack chains")
        status_layout.addWidget(self.count_label)
        
        # Add status bar to main layout
        main_layout.addLayout(status_layout)
        
        # Set stretch factor for main components
        main_layout.setStretchFactor(splitter, 1)
    
    def refresh_data(self):
        """Refresh the attack chains data."""
        try:
            # Show busy cursor
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            
            # Get attack chains from storage
            chains = self.storage.get_attack_chains(
                limit=config.get("gui.table_page_size", 100),
                include_anomalies=True
            )
            
            # Update table
            self._update_chains_table(chains)
            
            # Update status
            self.status_label.setText(f"Data refreshed at {datetime.now().strftime('%H:%M:%S')}")
            self.count_label.setText(f"{len(chains)} attack chains")
            
        except Exception as e:
            logger.error(f"Error refreshing attack chains data: {str(e)}")
            self.status_label.setText(f"Error: {str(e)}")
            
        finally:
            # Restore cursor
            QApplication.restoreOverrideCursor()
    
    def _update_chains_table(self, chains: List[Dict[str, Any]]):
        """Update the attack chains table with new data.
        
        Args:
            chains: List of attack chain dictionaries
        """
        # Clear the table
        self.chains_table.setRowCount(0)
        
        # Add rows for each chain
        for row, chain in enumerate(chains):
            self.chains_table.insertRow(row)
            
            # Format timestamps
            start_time = chain.get("start_time", "")
            try:
                if start_time:
                    import dateutil.parser
                    dt = dateutil.parser.parse(start_time)
                    start_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
                
            end_time = chain.get("end_time", "")
            try:
                if end_time:
                    import dateutil.parser
                    dt = dateutil.parser.parse(end_time)
                    end_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
            
            # Add cells
            self.chains_table.setItem(row, 0, QTableWidgetItem(str(chain.get("id", ""))))
            self.chains_table.setItem(row, 1, QTableWidgetItem(chain.get("name", "")))
            self.chains_table.setItem(row, 2, QTableWidgetItem(start_time))
            self.chains_table.setItem(row, 3, QTableWidgetItem(end_time))
            
            # Format severity
            severity = chain.get("severity", 0)
            severity_item = QTableWidgetItem(f"{severity:.2f}")
            if severity >= 0.8:
                severity_item.setBackground(Qt.GlobalColor.red)
                severity_item.setForeground(Qt.GlobalColor.white)
            elif severity >= 0.5:
                severity_item.setBackground(Qt.GlobalColor.yellow)
            self.chains_table.setItem(row, 4, severity_item)
            
            # Format confidence
            confidence = chain.get("confidence", 0)
            self.chains_table.setItem(row, 5, QTableWidgetItem(f"{confidence:.2f}"))
            
            # Add anomaly count
            anomaly_count = len(chain.get("anomalies", []))
            self.chains_table.setItem(row, 6, QTableWidgetItem(str(anomaly_count)))
            
            # Store the full chain data in the ID item
            self.chains_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, chain)
    
    def selection_changed(self):
        """Handle table selection changes."""
        selected_rows = self.chains_table.selectedItems()
        if not selected_rows:
            self._clear_details()
            return
            
        # Get the chain data from the ID cell
        id_item = self.chains_table.item(selected_rows[0].row(), 0)
        if not id_item:
            self._clear_details()
            return
            
        chain = id_item.data(Qt.ItemDataRole.UserRole)
        if not chain:
            self._clear_details()
            return
            
        self.selected_chain = chain
        self._update_details()
    
    def _clear_details(self):
        """Clear the detail view."""
        self.detail_name.setText("")
        self.detail_entity.setText("")
        self.detail_start_time.setText("")
        self.detail_end_time.setText("")
        self.detail_duration.setText("")
        self.detail_severity.setText("")
        self.detail_confidence.setText("")
        self.detail_risk_level.setText("")
        
        self.mitre_techniques_list.clear()
        self.anomalies_table.setRowCount(0)
        self.risk_factors_list.clear()
    
    def _update_details(self):
        """Update the detail view with the selected chain."""
        if not self.selected_chain:
            self._clear_details()
            return
            
        # Update summary fields
        self.detail_name.setText(self.selected_chain.get("name", ""))
        
        # Format entity
        entity_type = self.selected_chain.get("entity_type", "")
        entity_value = self.selected_chain.get("entity_value", "")
        if entity_type and entity_value:
            self.detail_entity.setText(f"{entity_type}: {entity_value}")
        else:
            self.detail_entity.setText("")
            
        # Format timestamps
        start_time = self.selected_chain.get("start_time", "")
        end_time = self.selected_chain.get("end_time", "")
        
        try:
            if start_time:
                import dateutil.parser
                dt = dateutil.parser.parse(start_time)
                self.detail_start_time.setText(dt.strftime("%Y-%m-%d %H:%M:%S"))
            else:
                self.detail_start_time.setText("")
                
            if end_time:
                import dateutil.parser
                dt_end = dateutil.parser.parse(end_time)
                self.detail_end_time.setText(dt_end.strftime("%Y-%m-%d %H:%M:%S"))
                
                # Calculate duration
                if start_time:
                    dt_start = dateutil.parser.parse(start_time)
                    duration_seconds = (dt_end - dt_start).total_seconds()
                    if duration_seconds < 60:
                        self.detail_duration.setText(f"{duration_seconds:.1f} seconds")
                    elif duration_seconds < 3600:
                        self.detail_duration.setText(f"{duration_seconds / 60:.1f} minutes")
                    else:
                        self.detail_duration.setText(f"{duration_seconds / 3600:.1f} hours")
                else:
                    self.detail_duration.setText("")
            else:
                self.detail_end_time.setText("")
                self.detail_duration.setText("")
                
        except Exception as e:
            logger.error(f"Error formatting timestamps: {str(e)}")
            self.detail_start_time.setText(start_time)
            self.detail_end_time.setText(end_time)
            self.detail_duration.setText("")
        
        # Format risk scores
        severity = self.selected_chain.get("severity", 0)
        self.detail_severity.setText(f"{severity:.2f}")
        
        confidence = self.selected_chain.get("confidence", 0)
        self.detail_confidence.setText(f"{confidence:.2f}")
        
        # Determine risk level
        risk_level = "Low"
        if severity >= 0.8:
            risk_level = "Critical"
        elif severity >= 0.6:
            risk_level = "High"
        elif severity >= 0.4:
            risk_level = "Medium"
            
        self.detail_risk_level.setText(risk_level)
        
        # Update MITRE techniques
        self._update_mitre_techniques()
        
        # Update anomalies table
        self._update_anomalies_table()
        
        # Update risk factors
        self._update_risk_factors()
    
    def _update_mitre_techniques(self):
        """Update the MITRE techniques list."""
        # Clear the list
        self.mitre_techniques_list.clear()
        
        if not self.selected_chain:
            return
            
        # Get MITRE techniques
        techniques = self.selected_chain.get("mitre_techniques", [])
        
        if not techniques:
            # Add empty item
            item = QTreeWidgetItem(["No techniques identified"])
            self.mitre_techniques_list.addTopLevelItem(item)
            return
            
        # MITRE technique descriptions (simplified)
        mitre_descriptions = {
            "TA0001": "Initial Access - Techniques to gain initial access to the network",
            "TA0002": "Execution - Techniques that result in code execution",
            "TA0003": "Persistence - Techniques to maintain presence in the system",
            "TA0004": "Privilege Escalation - Techniques to gain higher privileges",
            "TA0005": "Defense Evasion - Techniques to avoid detection",
            "TA0006": "Credential Access - Techniques to steal credentials",
            "TA0007": "Discovery - Techniques to explore the environment",
            "TA0008": "Lateral Movement - Techniques to move through the environment",
            "TA0009": "Collection - Techniques to gather data of interest",
            "TA0010": "Exfiltration - Techniques to steal data",
            "TA0011": "Command and Control - Techniques to communicate with controllers",
            "TA0040": "Impact - Techniques to disrupt operations"
        }
        
        # Add each technique
        for technique in techniques:
            description = mitre_descriptions.get(technique, "Unknown technique")
            item = QTreeWidgetItem([technique, description])
            
            # Color high-risk techniques
            if technique in ["TA0006", "TA0008", "TA0010"]:  # Credential access, lateral movement, exfiltration
                item.setBackground(0, QColor(255, 200, 200))
                
            self.mitre_techniques_list.addTopLevelItem(item)
    
    def _update_anomalies_table(self):
        """Update the anomalies table."""
        # Clear the table
        self.anomalies_table.setRowCount(0)
        
        if not self.selected_chain:
            return
            
        # Get anomalies
        anomalies = self.selected_chain.get("anomalies", [])
        
        if not anomalies:
            return
            
        # Sort anomalies by timestamp
        try:
            import dateutil.parser
            anomalies = sorted(
                anomalies,
                key=lambda a: dateutil.parser.parse(a.get("timestamp", "1970-01-01T00:00:00"))
            )
        except Exception as e:
            logger.error(f"Error sorting anomalies: {str(e)}")
        
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
            self.anomalies_table.setItem(row, 0, QTableWidgetItem(timestamp))
            self.anomalies_table.setItem(row, 1, QTableWidgetItem(anomaly.get("source_ip", "")))
            self.anomalies_table.setItem(row, 2, QTableWidgetItem(anomaly.get("username", "")))
            self.anomalies_table.setItem(row, 3, QTableWidgetItem(anomaly.get("event_type", "")))
            self.anomalies_table.setItem(row, 4, QTableWidgetItem(anomaly.get("action", "")))
            
            # Format severity
            severity = anomaly.get("severity", 0)
            severity_item = QTableWidgetItem(f"{severity:.2f}")
            if severity >= 0.8:
                severity_item.setBackground(Qt.GlobalColor.red)
                severity_item.setForeground(Qt.GlobalColor.white)
            elif severity >= 0.5:
                severity_item.setBackground(Qt.GlobalColor.yellow)
            self.anomalies_table.setItem(row, 5, severity_item)
    
    def _update_risk_factors(self):
        """Update the risk factors list."""
        # Clear the list
        self.risk_factors_list.clear()
        
        if not self.selected_chain:
            return
            
        # Get risk factors (if available)
        risk_factors = self.selected_chain.get("risk_factors", [])
        
        # If no explicit risk factors, generate some based on available data
        if not risk_factors:
            risk_factors = []
            
            # Check for high severity
            severity = self.selected_chain.get("severity", 0)
            if severity >= 0.8:
                risk_factors.append("High severity score")
                
            # Check for critical techniques
            techniques = self.selected_chain.get("mitre_techniques", [])
            high_risk_techniques = {"TA0006", "TA0008", "TA0010"}
            if any(t in high_risk_techniques for t in techniques):
                risk_factors.append("High-risk MITRE ATT&CK techniques detected")
                
            # Check time span
            try:
                start_time = self.selected_chain.get("start_time")
                end_time = self.selected_chain.get("end_time")
                if start_time and end_time:
                    import dateutil.parser
                    dt_start = dateutil.parser.parse(start_time)
                    dt_end = dateutil.parser.parse(end_time)
                    duration_seconds = (dt_end - dt_start).total_seconds()
                    
                    if duration_seconds < 60:
                        risk_factors.append("Very rapid attack progression (< 1 minute)")
                    elif duration_seconds < 300:
                        risk_factors.append("Rapid attack progression (< 5 minutes)")
            except Exception as e:
                logger.error(f"Error calculating duration: {str(e)}")
                
            # Check anomaly count
            anomaly_count = len(self.selected_chain.get("anomalies", []))
            if anomaly_count > 10:
                risk_factors.append(f"Large number of related anomalies ({anomaly_count})")
        
        # Add risk factors to the list
        if not risk_factors:
            # Add empty item
            item = QTreeWidgetItem(["No significant risk factors identified", "Low"])
            self.risk_factors_list.addTopLevelItem(item)
            return
            
        for factor in risk_factors:
            item = QTreeWidgetItem([factor, "High"])
            item.setBackground(0, QColor(255, 200, 200))
            self.risk_factors_list.addTopLevelItem(item)
            
        # Add base information as well
        anomaly_count = len(self.selected_chain.get("anomalies", []))
        item = QTreeWidgetItem([f"Chain contains {anomaly_count} anomalies", "Medium" if anomaly_count > 5 else "Low"])
        if anomaly_count > 5:
            item.setBackground(0, QColor(255, 255, 200))
        self.risk_factors_list.addTopLevelItem(item)
        
        techniques = self.selected_chain.get("mitre_techniques", [])
        item = QTreeWidgetItem([f"Chain maps to {len(techniques)} MITRE techniques", "Medium" if len(techniques) > 2 else "Low"])
        if len(techniques) > 2:
            item.setBackground(0, QColor(255, 255, 200))
        self.risk_factors_list.addTopLevelItem(item)
    
    def open_mitre_link(self):
        """Open the MITRE ATT&CK website for the selected technique."""
        if not self.selected_chain:
            return
            
        # Get selected technique
        selected_items = self.mitre_techniques_list.selectedItems()
        if not selected_items:
            # If no technique is selected, show MITRE ATT&CK main site
            url = "https://attack.mitre.org/"
        else:
            # Get the technique ID from the first column
            technique_id = selected_items[0].text(0)
            
            # Check if it's a valid technique ID
            if technique_id.startswith("TA"):
                url = f"https://attack.mitre.org/tactics/{technique_id}/"
            else:
                url = "https://attack.mitre.org/"
        
        # Open the URL in the default browser
        import webbrowser
        webbrowser.open(url)