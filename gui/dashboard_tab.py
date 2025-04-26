import os
import sys
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QGridLayout, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont

import matplotlib
matplotlib.use('QtAgg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import numpy as np

from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.core.storage import StorageHandler

logger = get_logger()
config = get_config()


class StatCard(QFrame):
    """A card displaying a statistic with a title and value."""
    
    def __init__(self, title: str, value: str, parent=None):
        """Initialize the stat card.
        
        Args:
            title: The title of the statistic
            value: The value of the statistic
            parent: The parent widget
        """
        super().__init__(parent)
        
        # Set frame properties
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Create title label
        self.title_label = QLabel(title)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(10)
        self.title_label.setFont(font)
        
        # Create value label
        self.value_label = QLabel(value)
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        self.value_label.setFont(font)
        
        # Add widgets to layout
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
    
    def update_value(self, value: str):
        """Update the value displayed in the card.
        
        Args:
            value: The new value to display
        """
        self.value_label.setText(value)


class MatplotlibCanvas(FigureCanvas):
    """Matplotlib canvas for embedding plots in PyQt widgets."""
    
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        """Initialize the canvas.
        
        Args:
            parent: The parent widget
            width: The width of the figure in inches
            height: The height of the figure in inches
            dpi: The resolution in dots per inch
        """
        # Create figure and axes
        self.fig = Figure(figsize=(width, height), dpi=dpi, tight_layout=True)
        self.axes = self.fig.add_subplot(111)
        
        # Initialize canvas
        super().__init__(self.fig)
        self.setParent(parent)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.updateGeometry()


class DashboardTab(QWidget):
    """The dashboard tab displaying overview and statistics."""
    
    def __init__(self, parent):
        """Initialize the dashboard tab.
        
        Args:
            parent: The parent widget (MainWindow)
        """
        super().__init__(parent)
        
        # Store reference to main window
        self.main_window = parent
        
        # Initialize storage
        self.storage = StorageHandler()
        
        # Create UI
        self._create_ui()
        
        logger.info("Dashboard tab initialized")
    
    def _create_ui(self):
        """Create the UI components."""
        # Create main layout
        main_layout = QVBoxLayout(self)
        
        # Create title label
        title_label = QLabel("Dashboard")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Create grid layout for stat cards
        stats_layout = QGridLayout()
        stats_layout.setContentsMargins(10, 10, 10, 10)
        stats_layout.setSpacing(20)
        
        # Create stat cards
        self.anomalies_card = StatCard("Anomalies Detected", "0")
        stats_layout.addWidget(self.anomalies_card, 0, 0)
        
        self.chains_card = StatCard("Attack Chains", "0")
        stats_layout.addWidget(self.chains_card, 0, 1)
        
        self.high_severity_card = StatCard("High Severity Anomalies", "0")
        stats_layout.addWidget(self.high_severity_card, 0, 2)
        
        self.avg_severity_card = StatCard("Average Severity", "0.00")
        stats_layout.addWidget(self.avg_severity_card, 0, 3)
        
        # Add stats layout to main layout
        main_layout.addLayout(stats_layout)
        
        # Create charts layout
        charts_layout = QHBoxLayout()
        
        # Create severity distribution chart
        severity_widget = QWidget()
        severity_layout = QVBoxLayout(severity_widget)
        severity_title = QLabel("Severity Distribution")
        severity_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        severity_layout.addWidget(severity_title)
        
        self.severity_canvas = MatplotlibCanvas(self)
        severity_layout.addWidget(self.severity_canvas)
        
        # Create event type distribution chart
        event_widget = QWidget()
        event_layout = QVBoxLayout(event_widget)
        event_title = QLabel("Event Type Distribution")
        event_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        event_layout.addWidget(event_title)
        
        self.event_canvas = MatplotlibCanvas(self)
        event_layout.addWidget(self.event_canvas)
        
        # Add charts to layout
        charts_layout.addWidget(severity_widget)
        charts_layout.addWidget(event_widget)
        
        # Add charts layout to main layout
        main_layout.addLayout(charts_layout)
        
        # Create anomaly timeline chart
        timeline_widget = QWidget()
        timeline_layout = QVBoxLayout(timeline_widget)
        timeline_title = QLabel("Anomaly Timeline")
        timeline_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        timeline_layout.addWidget(timeline_title)
        
        self.timeline_canvas = MatplotlibCanvas(self, height=3)
        timeline_layout.addWidget(self.timeline_canvas)
        
        # Add timeline to main layout
        main_layout.addWidget(timeline_widget)
        
        # Set stretch factors
        main_layout.setStretchFactor(timeline_widget, 1)
    
    def refresh_data(self):
        """Refresh the dashboard data."""
        try:
            # Get database stats
            stats = self.storage.get_stats()
            
            # Update stat cards
            self.anomalies_card.update_value(str(stats.get("anomalies_count", 0)))
            self.chains_card.update_value(str(stats.get("attack_chains_count", 0)))
            self.high_severity_card.update_value(str(stats.get("high_severity_anomalies", 0)))
            avg_severity = stats.get("avg_anomaly_severity", 0)
            self.avg_severity_card.update_value(f"{avg_severity:.2f}")
            
            # Get anomalies for charts
            anomalies = self.storage.get_anomalies(limit=1000)
            
            # Update severity distribution chart
            self._update_severity_chart(anomalies)
            
            # Update event type distribution chart
            self._update_event_type_chart(anomalies)
            
            # Update timeline chart
            self._update_timeline_chart(anomalies)
            
        except Exception as e:
            logger.error(f"Error refreshing dashboard data: {str(e)}")
    
    def _update_severity_chart(self, anomalies: List[Dict[str, Any]]):
        """Update the severity distribution chart.
        
        Args:
            anomalies: List of anomaly dictionaries
        """
        # Clear the chart
        self.severity_canvas.axes.clear()
        
        if not anomalies:
            self.severity_canvas.draw()
            return
            
        # Extract severity values
        severities = [a.get("severity", 0) for a in anomalies]
        
        # Create severity bins
        bins = [0, 0.2, 0.4, 0.6, 0.8, 1.0]
        labels = ["Very Low", "Low", "Medium", "High", "Critical"]
        
        # Count anomalies in each bin
        counts = np.zeros(len(labels))
        for severity in severities:
            bin_index = min(int(severity * 5), 4)
            counts[bin_index] += 1
        
        # Create bar chart
        bars = self.severity_canvas.axes.bar(labels, counts, color='#5A8BE5')
        
        # Add value labels above bars
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                self.severity_canvas.axes.text(
                    bar.get_x() + bar.get_width() / 2.,
                    height,
                    '%d' % int(height),
                    ha='center',
                    va='bottom'
                )
        
        # Set title and labels
        self.severity_canvas.axes.set_ylabel("Count")
        
        # Update chart
        self.severity_canvas.draw()
    
    def _update_event_type_chart(self, anomalies: List[Dict[str, Any]]):
        """Update the event type distribution chart.
        
        Args:
            anomalies: List of anomaly dictionaries
        """
        # Clear the chart
        self.event_canvas.axes.clear()
        
        if not anomalies:
            self.event_canvas.draw()
            return
            
        # Extract event types
        event_types = [a.get("event_type", "unknown") for a in anomalies]
        event_types = [et if et else "unknown" for et in event_types]
        
        # Count each event type
        event_counts = {}
        for et in event_types:
            event_counts[et] = event_counts.get(et, 0) + 1
        
        # Sort by count (descending)
        sorted_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Take top 5 event types
        top_events = sorted_events[:5]
        
        # Extract labels and counts
        labels = [e[0] for e in top_events]
        counts = [e[1] for e in top_events]
        
        # Create bar chart
        bars = self.event_canvas.axes.bar(labels, counts, color='#5A8BE5')
        
        # Add value labels above bars
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                self.event_canvas.axes.text(
                    bar.get_x() + bar.get_width() / 2.,
                    height,
                    '%d' % int(height),
                    ha='center',
                    va='bottom'
                )
        
        # Set title and labels
        self.event_canvas.axes.set_ylabel("Count")
        
        # Rotate x-axis labels for readability
        self.event_canvas.axes.set_xticklabels(labels, rotation=45, ha='right')
        
        # Update chart
        self.event_canvas.draw()
    
    def _update_timeline_chart(self, anomalies: List[Dict[str, Any]]):
        """Update the anomaly timeline chart.
        
        Args:
            anomalies: List of anomaly dictionaries
        """
        # Clear the chart
        self.timeline_canvas.axes.clear()
        
        if not anomalies:
            self.timeline_canvas.draw()
            return
            
        try:
            # Extract timestamps and severities
            timestamps = []
            severities = []
            
            for anomaly in anomalies:
                if anomaly.get("timestamp"):
                    timestamps.append(anomaly["timestamp"])
                    severities.append(anomaly.get("severity", 0))
            
            if not timestamps:
                self.timeline_canvas.draw()
                return
                
            # Convert timestamps to datetime objects
            import dateutil.parser
            datetimes = [dateutil.parser.parse(ts) for ts in timestamps]
            
            # Sort by timestamp
            sorted_data = sorted(zip(datetimes, severities))
            datetimes = [dt for dt, _ in sorted_data]
            severities = [sev for _, sev in sorted_data]
            
            # Create scatter plot
            colors = ['#3498db', '#f39c12', '#e74c3c']  # Blue, Orange, Red
            
            # Map severities to colors
            scatter_colors = []
            for sev in severities:
                if sev < 0.4:
                    scatter_colors.append(colors[0])  # Low severity
                elif sev < 0.7:
                    scatter_colors.append(colors[1])  # Medium severity
                else:
                    scatter_colors.append(colors[2])  # High severity
            
            # Create scatter plot
            self.timeline_canvas.axes.scatter(datetimes, severities, c=scatter_colors, alpha=0.7)
            
            # Set title and labels
            self.timeline_canvas.axes.set_xlabel("Timestamp")
            self.timeline_canvas.axes.set_ylabel("Severity")
            self.timeline_canvas.axes.set_ylim(0, 1)
            
            # Format x-axis ticks
            self.timeline_canvas.fig.autofmt_xdate()
            
            # Set grid
            self.timeline_canvas.axes.grid(True, linestyle='--', alpha=0.7)
            
            # Update chart
            self.timeline_canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating timeline chart: {str(e)}")
            self.timeline_canvas.draw() 