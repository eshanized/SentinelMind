import sys
import os
import signal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor

# Add the parent directory to the path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Initialize
from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config
from sentinelmind.gui.main_window import MainWindow

logger = get_logger()
config = get_config()


def load_stylesheet(app):
    """Load the application stylesheet."""
    style_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "resources", 
        "style.qss"
    )
    
    if os.path.exists(style_path):
        with open(style_path, "r") as f:
            style = f.read()
            app.setStyleSheet(style)
            logger.info(f"Applied stylesheet from {style_path}")
    else:
        logger.warning(f"Stylesheet not found at {style_path}")
        # Fall back to basic dark palette if stylesheet isn't found
        set_dark_theme(app)


def set_dark_theme(app):
    """Set dark theme for the application using Qt's palette."""
    dark_palette = QPalette()
    
    # Set colors
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    
    # Apply palette
    app.setPalette(dark_palette)
    app.setStyleSheet("QToolTip { color: #ffffff; background-color: #2a2a2a; border: 1px solid white; }")


def main():
    """Main entry point for the GUI."""
    # Enable Ctrl+C to work
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("SentinelMind")
    
    # Apply stylesheet or theme
    if config.get("default_dark_mode", True):
        load_stylesheet(app)
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Start event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main() 