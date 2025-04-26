import os
import sys
from datetime import datetime
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, 
    QPushButton, QFileDialog, QMessageBox, QStatusBar, QToolBar, 
    QDialog, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QComboBox, QApplication, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QDateTime, QTimer
from PyQt6.QtGui import QIcon, QAction, QFont

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.gui.dashboard_tab import DashboardTab
from sentinelmind.gui.scan_tab import ScanTab
from sentinelmind.gui.anomalies_tab import AnomaliesTab
from sentinelmind.gui.attack_chains_tab import AttackChainsTab
from sentinelmind.gui.training_dialog import TrainingDialog
from sentinelmind.gui.scan_thread import ScanThread
from sentinelmind.core.storage import StorageHandler

logger = get_logger()
config = get_config()


class MainWindow(QMainWindow):
    """Main window for the SentinelMind application."""
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()
        
        # Set window properties
        self.setWindowTitle("SentinelMind: AI-Powered Threat Hunting Engine")
        self.setGeometry(100, 100, 
                         config.get("gui.window_width", 1200),
                         config.get("gui.window_height", 800))
        
        # Initialize storage
        self.storage = StorageHandler()
        
        # Create UI
        self._create_ui()
        self._create_menu()
        self._create_toolbar()
        self._create_status_bar()
        
        # Set up refresh timer
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(config.get("gui.refresh_interval", 5000))  # Default 5 seconds
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start()
        
        # Initialize data
        self.refresh_data()
        
        logger.info("GUI main window initialized")
    
    def _create_ui(self):
        """Create the UI components."""
        # Create central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.dashboard_tab = DashboardTab(self)
        self.tab_widget.addTab(self.dashboard_tab, "Dashboard")
        
        self.scan_tab = ScanTab(self)
        self.tab_widget.addTab(self.scan_tab, "Scan")
        
        self.anomalies_tab = AnomaliesTab(self)
        self.tab_widget.addTab(self.anomalies_tab, "Anomalies")
        
        self.attack_chains_tab = AttackChainsTab(self)
        self.tab_widget.addTab(self.attack_chains_tab, "Attack Chains")
    
    def _create_menu(self):
        """Create the menu bar."""
        # Create menu bar
        menu_bar = self.menuBar()
        
        # File menu
        file_menu = menu_bar.addMenu("&File")
        
        # Open log file action
        open_action = QAction("&Open Log File...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_log_file)
        file_menu.addAction(open_action)
        
        # Export results action
        export_action = QAction("&Export Results...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menu_bar.addMenu("&Tools")
        
        # Train models action
        train_action = QAction("&Train Models...", self)
        train_action.triggered.connect(self.train_models)
        tools_menu.addAction(train_action)
        
        # Refresh data action
        refresh_action = QAction("&Refresh Data", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_data)
        tools_menu.addAction(refresh_action)
        
        # Help menu
        help_menu = menu_bar.addMenu("&Help")
        
        # About action
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def _create_toolbar(self):
        """Create the toolbar."""
        # Create toolbar
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setIconSize(QSize(32, 32))
        self.addToolBar(self.toolbar)
        
        # Add actions
        # Scan action
        scan_action = QAction("Scan Log", self)
        scan_action.triggered.connect(self.open_log_file)
        self.toolbar.addAction(scan_action)
        
        # Train action
        train_action = QAction("Train Models", self)
        train_action.triggered.connect(self.train_models)
        self.toolbar.addAction(train_action)
        
        # Export action
        export_action = QAction("Export Results", self)
        export_action.triggered.connect(self.export_results)
        self.toolbar.addAction(export_action)
        
        # Add spacer
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.toolbar.addWidget(spacer)
        
        # Add refresh button
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_data)
        self.toolbar.addAction(refresh_action)
    
    def _create_status_bar(self):
        """Create the status bar."""
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Add status label
        self.status_label = QLabel("Ready")
        self.status_bar.addPermanentWidget(self.status_label)
        
        # Add database info label
        self.db_label = QLabel("")
        self.status_bar.addWidget(self.db_label)
    
    def open_log_file(self):
        """Open a log file for scanning."""
        # Show file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Log File",
            "",
            "Log Files (*.log *.json *.csv *.jsonl *.syslog);;All Files (*.*)"
        )
        
        if file_path:
            # Switch to scan tab
            self.tab_widget.setCurrentWidget(self.scan_tab)
            
            # Set file path and start scan
            self.scan_tab.set_file_path(file_path)
            self.scan_tab.start_scan()
    
    def export_results(self):
        """Export results to a file."""
        # Show file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*.*)"
        )
        
        if not file_path:
            return
            
        # Determine format based on extension
        export_format = "json"
        if file_path.lower().endswith(".csv"):
            export_format = "csv"
            
        try:
            # Show busy cursor
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            
            # Export results
            output_path = self.storage.export_findings(
                output_path=file_path,
                export_format=export_format,
                include_chains=True,
                include_anomalies=True
            )
            
            # Show success message
            QMessageBox.information(
                self,
                "Export Successful",
                f"Results exported to {output_path}"
            )
            
        except Exception as e:
            # Show error message
            QMessageBox.critical(
                self,
                "Export Error",
                f"Error exporting results: {str(e)}"
            )
            logger.error(f"Error exporting results: {str(e)}")
            
        finally:
            # Restore cursor
            QApplication.restoreOverrideCursor()
    
    def train_models(self):
        """Open the training dialog."""
        dialog = TrainingDialog(self)
        dialog.exec()
        
        # Refresh data after training
        self.refresh_data()
    
    def show_about(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About SentinelMind",
            "SentinelMind: AI-Powered Threat Hunting Engine\n\n"
            "A professional-grade security tool designed to detect anomalies and "
            "advanced persistent threats (APTs) from security log files using AI/ML techniques.\n\n"
            "Version: 1.0.0"
        )
    
    def refresh_data(self):
        """Refresh data in all tabs."""
        try:
            # Get database stats
            stats = self.storage.get_stats()
            
            # Update status bar
            self.db_label.setText(
                f"Database: {stats.get('anomalies_count', 0)} anomalies, "
                f"{stats.get('attack_chains_count', 0)} attack chains"
            )
            
            # Update tabs
            self.dashboard_tab.refresh_data()
            self.anomalies_tab.refresh_data()
            self.attack_chains_tab.refresh_data()
            
            # Update status
            self.status_label.setText(f"Last update: {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            logger.error(f"Error refreshing data: {str(e)}")
            self.status_label.setText(f"Error: {str(e)}")
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop refresh timer
        self.refresh_timer.stop()
        
        # Accept the event and close the window
        event.accept() 