"""
Configuration management for Taggr Solution.

Loads settings from config.json with fallback to environment variables.
"""

import json
import os
from typing import Any, Optional


class classConfiguration:
    """
    Centralized configuration manager.
    
    Loads configuration from config.json at project root,
    with fallback to environment variables for missing values.
    """
    
    def __init__(self):
        """Initialize configuration by loading from config.json."""
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), '..', 'config.json'
        )
        try:
            with open(config_path, 'r') as f:
                self.config_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.config_data = {}
        
        # Defaults with environment variable fallback
        defaults = {
            "REGION": os.environ.get('REGION', 'us-east-1'),
            "IAM_ROOT_ROLE": os.environ.get('IAM_ROOT_ROLE', ''),
            "IAM_CHILD_ROLE": os.environ.get('IAM_CHILD_ROLE', ''),
            "MAX_WORKERS": int(os.environ.get('MAX_WORKERS', 10)),
            "DB_PATH": os.environ.get('DB_PATH', '../dbstore/tagger.db')
        }
        
        for key, value in defaults.items():
            if key not in self.config_data:
                self.config_data[key] = value
    
    def get_config(self, key: str, default: Optional[Any] = None) -> Any:
        """
        Get any configuration value by key.
        
        Args:
            key: Configuration key name
            default: Fallback value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config_data.get(key, default)
