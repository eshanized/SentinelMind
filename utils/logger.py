import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional


class Logger:
    """Centralized logging utility for SentinelMind."""
    
    _instance: Optional['Logger'] = None
    _initialized: bool = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.logger = logging.getLogger('sentinelmind')
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_format)
        
        # File handler (rotating to prevent huge log files)
        file_handler = RotatingFileHandler(
            'logs/sentinelmind.log', 
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)  # More verbose for file logs
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
        file_handler.setFormatter(file_format)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
        self._initialized = True
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance.
        
        Returns:
            logging.Logger: The configured logger instance
        """
        return self.logger


def get_logger() -> logging.Logger:
    """Convenience function to get the logger instance.
    
    Returns:
        logging.Logger: The configured logger instance
    """
    return Logger().get_logger() 