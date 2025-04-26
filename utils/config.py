import json
import os
from typing import Any, Dict, Optional
from pathlib import Path


class Config:
    """Configuration manager for SentinelMind."""
    
    _instance: Optional['Config'] = None
    _initialized: bool = False
    
    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sentinelmind")
    CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.config: Dict[str, Any] = {
            "models_dir": "models",
            "db_file": "sentinelmind.db",
            "anomaly_threshold": 0.8,
            "attack_chain_time_window": 3600,  # 1 hour in seconds
            "default_dark_mode": True,
            "max_threads": 4,
            "log_level": "INFO",
            "mitre_attack_url": "https://attack.mitre.org/techniques/",
            "gui": {
                "window_width": 1200,
                "window_height": 800,
                "table_page_size": 50,
                "refresh_interval": 5000,  # 5 seconds
                "chart_height": 400,
                "chart_width": 600,
            }
        }
        
        # Ensure the config directory exists
        os.makedirs(self.CONFIG_DIR, exist_ok=True)
        
        # Load existing config if it exists
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    user_config = json.load(f)
                    # Update default config with user values
                    self._deep_update(self.config, user_config)
            except Exception as e:
                print(f"Error loading config: {e}")
        
        # Save the config
        self.save()
        
        self._initialized = True
    
    def _deep_update(self, d: Dict[str, Any], u: Dict[str, Any]) -> None:
        """Deep update dictionary."""
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._deep_update(d[k], v)
            else:
                d[k] = v
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            key: The configuration key to retrieve
            default: Default value if the key doesn't exist
            
        Returns:
            The configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.
        
        Args:
            key: The configuration key to set
            value: The value to set
        """
        keys = key.split('.')
        config = self.config
        
        for i, k in enumerate(keys[:-1]):
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        self.save()
    
    def save(self) -> None:
        """Save the configuration to file."""
        try:
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get_model_path(self, model_name: str) -> str:
        """Get the full path to a model.
        
        Args:
            model_name: The name of the model
            
        Returns:
            The full path to the model
        """
        return os.path.join(self.get("models_dir"), f"{model_name}.pkl")
    
    def get_db_path(self) -> str:
        """Get the full path to the database.
        
        Returns:
            The full path to the database
        """
        return self.get("db_file")


def get_config() -> Config:
    """Convenience function to get the config instance.
    
    Returns:
        Config: The configuration manager instance
    """
    return Config() 