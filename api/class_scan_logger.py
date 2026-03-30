"""
Scan-specific logging utility for Discovery and Tagging processes.
Creates separate log files per scan_id in logs/ directory.
"""

import os
import logging
from datetime import datetime
from pathlib import Path


class ScanLogger:
    """
    Manages logging for individual scan processes.
    Creates log files in format: logs/{scan_id}.log
    """
    
    def __init__(self, scan_id: str, process_type: str):
        """
        Initialize scan logger.
        
        Args:
            scan_id: Unique identifier for the scan process
            process_type: Type of process ('discovery' or 'tagger')
        """
        self.scan_id = scan_id
        self.process_type = process_type
        self.log_dir = Path("logs")
        self.log_file = self.log_dir / f"{scan_id}.log"
        
        # Create logs directory if it doesn't exist
        self.log_dir.mkdir(exist_ok=True)
        
        # Create logger
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """
        Set up logger with file handler.
        
        Returns:
            Configured logger instance
        """
        # Create logger with unique name
        logger_name = f"scan_{self.scan_id}"
        logger = logging.getLogger(logger_name)
        
        # Avoid adding handlers multiple times
        if logger.handlers:
            return logger
        
        logger.setLevel(logging.INFO)
        
        # Create file handler
        file_handler = logging.FileHandler(self.log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - [%(process_type)s] - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
        
        return logger
    
    def info(self, message: str):
        """Log info message."""
        self.logger.info(message, extra={'process_type': self.process_type})
    
    def warning(self, message: str):
        """Log warning message."""
        self.logger.warning(message, extra={'process_type': self.process_type})
    
    def error(self, message: str):
        """Log error message."""
        self.logger.error(message, extra={'process_type': self.process_type})
    
    def success(self, message: str):
        """Log success message (as INFO level)."""
        self.logger.info(f"SUCCESS: {message}", extra={'process_type': self.process_type})
    
    def close(self):
        """Close logger handlers."""
        handlers = self.logger.handlers[:]
        for handler in handlers:
            handler.close()
            self.logger.removeHandler(handler)
    
    @staticmethod
    def get_log_file_path(scan_id: str) -> Path:
        """
        Get the log file path for a given scan_id.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Path to log file
        """
        return Path("logs") / f"{scan_id}.log"
    
    @staticmethod
    def log_exists(scan_id: str) -> bool:
        """
        Check if log file exists for a scan_id.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            True if log file exists
        """
        log_file = ScanLogger.get_log_file_path(scan_id)
        return log_file.exists()
    
    @staticmethod
    def read_log(scan_id: str, lines: int = None) -> str:
        """
        Read log file content in reverse order (newest first).
        
        Args:
            scan_id: Scan identifier
            lines: Number of lines to read from end (tail mode). None = all lines
            
        Returns:
            Log file content with newest lines first
        """
        log_file = ScanLogger.get_log_file_path(scan_id)
        
        if not log_file.exists():
            return ""
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                
                if lines is None:
                    # Return all lines in reverse order (newest first)
                    return ''.join(reversed(all_lines))
                else:
                    # Return last N lines in reverse order (newest first)
                    selected_lines = all_lines[-lines:]
                    return ''.join(reversed(selected_lines))
        except Exception as e:
            return f"Error reading log file: {str(e)}"
        except Exception as e:
            return f"Error reading log file: {str(e)}"
    
    @staticmethod
    def get_log_stats(scan_id: str) -> dict:
        """
        Get statistics about the log file.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Dictionary with log statistics
        """
        log_file = ScanLogger.get_log_file_path(scan_id)
        
        if not log_file.exists():
            return {
                'exists': False,
                'size': 0,
                'lines': 0,
                'errors': 0,
                'warnings': 0,
                'success': 0
            }
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                return {
                    'exists': True,
                    'size': log_file.stat().st_size,
                    'lines': len(lines),
                    'errors': content.count('- ERROR -'),
                    'warnings': content.count('- WARNING -'),
                    'success': content.count('SUCCESS:')
                }
        except Exception as e:
            return {
                'exists': True,
                'size': 0,
                'lines': 0,
                'errors': 0,
                'warnings': 0,
                'success': 0,
                'error': str(e)
            }


# Example usage:
if __name__ == "__main__":
    # Create logger for a scan
    logger = ScanLogger("20260321123456", "discovery")
    
    logger.info("Starting discovery process")
    logger.info("Discovered 150 resources in us-east-1")
    logger.success("Discovery completed successfully")
    logger.error("Failed to discover resources in eu-west-1: Connection timeout")
    
    logger.close()
    
    # Read log
    print(ScanLogger.read_log("20260321123456"))
    
    # Get stats
    print(ScanLogger.get_log_stats("20260321123456"))
