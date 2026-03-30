import json
import logging
from datetime import datetime
from typing import Any, Dict

class classLogging:
    def __init__(self, name: str = "generic", instance: str = "default"):
        self.name = name
        self.instance = instance
        
        # Configure logger
        self.logger = logging.getLogger(f"{name}_{instance}")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.WARNING)
    
    def write(self, module: str, log_type: str, message: Any):
        """Write log entry to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {
            "time": timestamp,
            "type": log_type,
            "object": self.name,
            "instance": self.instance,
            "module": module,
            "message": str(message)
        }
        
        if log_type.lower() == "error":
            self.logger.error(json.dumps(log_entry))
        elif log_type.lower() == "warn":
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))
    
    def debug(self, module: str, log_type: str, message: Any):
        """Write debug entry to file"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "time": timestamp,
            "module": module,
            "type": log_type,
            "message": str(message)
        }
        
        try:
            with open("debug.log", "a") as f:
                f.write(f"\n{json.dumps(log_entry)}")
        except Exception as e:
            self.logger.error(f"Failed to write debug log: {e}")
