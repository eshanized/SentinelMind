import re
import json
import dateutil.parser
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
import ipaddress

from ..utils.logger import get_logger

logger = get_logger()


class LogParser:
    """Parses and normalizes log data from various formats."""
    
    # Common timestamp formats to try parsing
    TIMESTAMP_FORMATS = [
        '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO 8601 with milliseconds and Z
        '%Y-%m-%dT%H:%M:%S.%f',    # ISO 8601 with milliseconds
        '%Y-%m-%dT%H:%M:%SZ',      # ISO 8601 with Z
        '%Y-%m-%dT%H:%M:%S',       # ISO 8601
        '%Y-%m-%d %H:%M:%S.%f',    # Datetime with milliseconds
        '%Y-%m-%d %H:%M:%S',       # Standard datetime
        '%b %d %H:%M:%S',          # Syslog format (Mmm DD HH:MM:SS)
        '%d/%b/%Y:%H:%M:%S %z',    # Apache format
    ]
    
    # Common field names for mapping
    TIMESTAMP_FIELDS = ['timestamp', 'time', 'date', 'datetime', 'event_time', '@timestamp', 'log_time']
    IP_FIELDS = ['ip', 'source_ip', 'src_ip', 'dest_ip', 'destination_ip', 'client_ip', 'server_ip', 'host_ip', 'remote_ip']
    USERNAME_FIELDS = ['username', 'user', 'user_name', 'account', 'user_id', 'userid']
    ACTION_FIELDS = ['action', 'operation', 'method', 'activity', 'event_type', 'command']
    STATUS_FIELDS = ['status', 'result', 'status_code', 'response_code', 'error_code']
    RESOURCE_FIELDS = ['resource', 'object', 'target', 'path', 'url', 'endpoint', 'file']
    
    def __init__(self):
        """Initialize the log parser."""
        # Common patterns
        self.ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
    def normalize_timestamp(self, timestamp_str: str) -> Optional[str]:
        """Normalize timestamp to ISO 8601 format.
        
        Args:
            timestamp_str: Timestamp string in various formats
            
        Returns:
            Normalized timestamp in ISO 8601 format, or None if parsing fails
        """
        if not timestamp_str:
            return None
            
        # Try dateutil parser first (handles many formats)
        try:
            dt = dateutil.parser.parse(timestamp_str)
            return dt.isoformat()
        except (ValueError, TypeError):
            pass
            
        # Try specific formats
        for fmt in self.TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.isoformat()
            except (ValueError, TypeError):
                continue
                
        # If all parsing attempts fail
        logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return None
    
    def is_valid_ip(self, ip_str: str) -> bool:
        """Check if a string is a valid IP address.
        
        Args:
            ip_str: String to check
            
        Returns:
            True if valid IP address, False otherwise
        """
        if not isinstance(ip_str, str):
            return False
            
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
            
    def find_field_value(self, log_entry: Dict[str, Any], possible_fields: List[str], default: Any = None) -> Any:
        """Find the first matching field from a list of possible field names.
        
        Args:
            log_entry: Log entry dictionary
            possible_fields: List of possible field names to check
            default: Default value if no matching field is found
            
        Returns:
            The value of the first matching field, or the default value
        """
        # Check direct field matches first
        for field in possible_fields:
            if field in log_entry and log_entry[field] is not None:
                return log_entry[field]
                
        # Check for fields with case insensitivity
        log_lower = {k.lower(): v for k, v in log_entry.items()}
        for field in possible_fields:
            if field.lower() in log_lower and log_lower[field.lower()] is not None:
                return log_lower[field.lower()]
                
        return default
    
    def extract_ips_from_text(self, text: str) -> List[str]:
        """Extract IP addresses from text.
        
        Args:
            text: Text to extract IPs from
            
        Returns:
            List of extracted IP addresses
        """
        if not isinstance(text, str):
            return []
            
        # IPv4 pattern
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ipv4_matches = re.findall(ipv4_pattern, text)
        
        # Filter to valid IPs
        valid_ips = [ip for ip in ipv4_matches if self.is_valid_ip(ip)]
        
        return valid_ips
    
    def parse_log_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and normalize a log entry.
        
        Args:
            log_entry: Raw log entry dictionary
            
        Returns:
            Normalized log entry dictionary
        """
        # Create a normalized structure
        normalized = {
            'timestamp': None,
            'event_type': None,
            'source_ip': None,
            'destination_ip': None,
            'username': None,
            'user_id': None,
            'resource': None,
            'action': None,
            'status': None,
            'raw_data': log_entry  # Keep the original data
        }
        
        # Extract timestamp
        timestamp = self.find_field_value(log_entry, self.TIMESTAMP_FIELDS)
        if timestamp:
            normalized['timestamp'] = self.normalize_timestamp(str(timestamp))
        
        # Extract IP addresses
        source_ip = self.find_field_value(log_entry, self.IP_FIELDS)
        if source_ip and self.is_valid_ip(str(source_ip)):
            normalized['source_ip'] = str(source_ip)
            
        # Look for additional IP fields for destination
        dest_fields = ['dest_ip', 'destination_ip', 'target_ip', 'server_ip']
        destination_ip = self.find_field_value(log_entry, dest_fields)
        if destination_ip and self.is_valid_ip(str(destination_ip)):
            normalized['destination_ip'] = str(destination_ip)
            
        # Try to extract IPs from message or raw text if not found directly
        message = self.find_field_value(log_entry, ['message', 'msg', 'content', 'raw_message'])
        if message and not (normalized['source_ip'] and normalized['destination_ip']):
            extracted_ips = self.extract_ips_from_text(str(message))
            if extracted_ips and not normalized['source_ip']:
                normalized['source_ip'] = extracted_ips[0]
                if len(extracted_ips) > 1 and not normalized['destination_ip']:
                    normalized['destination_ip'] = extracted_ips[1]
        
        # Extract username and user ID
        username = self.find_field_value(log_entry, self.USERNAME_FIELDS)
        if username:
            normalized['username'] = str(username)
            
        user_id = self.find_field_value(log_entry, ['user_id', 'userid', 'uid', 'account_id'])
        if user_id:
            normalized['user_id'] = str(user_id)
            
        # Extract action/operation
        action = self.find_field_value(log_entry, self.ACTION_FIELDS)
        if action:
            normalized['action'] = str(action)
            
        # Extract status
        status = self.find_field_value(log_entry, self.STATUS_FIELDS)
        if status:
            normalized['status'] = str(status)
            
        # Extract resource
        resource = self.find_field_value(log_entry, self.RESOURCE_FIELDS)
        if resource:
            normalized['resource'] = str(resource)
            
        # Extract event type
        event_type = self.find_field_value(log_entry, ['event_type', 'type', 'category', 'log_type'])
        if event_type:
            normalized['event_type'] = str(event_type)
        else:
            # Try to infer event type from context
            if normalized['action'] in ['login', 'logout', 'authenticate', 'auth']:
                normalized['event_type'] = 'authentication'
            elif normalized['action'] in ['create', 'update', 'delete', 'modify', 'change']:
                normalized['event_type'] = 'data_modification'
            elif normalized['action'] in ['access', 'view', 'read', 'get', 'list']:
                normalized['event_type'] = 'data_access'
            elif normalized['action'] in ['execute', 'run', 'start', 'stop', 'command']:
                normalized['event_type'] = 'process_execution'
            
        return normalized
    
    def parse_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse and normalize a list of log entries.
        
        Args:
            logs: List of raw log entries
            
        Returns:
            List of normalized log entries
        """
        normalized_logs = []
        
        for log_entry in logs:
            try:
                normalized = self.parse_log_entry(log_entry)
                normalized_logs.append(normalized)
            except Exception as e:
                logger.error(f"Error parsing log entry: {str(e)}")
                # Include the raw entry anyway to avoid data loss
                normalized_logs.append({
                    'timestamp': None,
                    'event_type': None,
                    'source_ip': None,
                    'destination_ip': None,
                    'username': None,
                    'user_id': None,
                    'resource': None,
                    'action': None,
                    'status': None,
                    'raw_data': log_entry,
                    'parse_error': str(e)
                })
                
        return normalized_logs 