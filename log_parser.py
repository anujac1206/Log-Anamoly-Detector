import pandas as pd
import re
from datetime import datetime
from typing import List, Dict, Tuple
import io

class LogParser:
    """Parse various security log formats into a standardized structure."""
    
    def __init__(self):
        self.log_patterns = {
            'auth_syslog': r'(\w+ \d+ \d{2}:\d{2}:\d{2}).*sshd.*(?:Invalid user|Failed password) for (?:invalid user )?(\w+) from (\S+)',
            'apache_auth': r'^(\S+)\s+\S+\s+(\S+)\s+\[(.+?)\]\s+"(?:GET|POST|HEAD|PUT|DELETE)\s+\S+\s+\S+"\s+(\d{3})\s+\d+',
            'windows_event': r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*EventID:\s+(\d+).*User:\s+(\S+).*Source IP:\s+(\S+)',
            'fail2ban': r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*Ban\s+(\S+)\s+for\s+(\S+)',
        }
    
    def parse_csv(self, file_content: str) -> pd.DataFrame:
        """Parse CSV log file."""
        try:
            df = pd.read_csv(io.StringIO(file_content))
            return self._standardize_dataframe(df)
        except Exception as e:
            raise ValueError(f"Failed to parse CSV: {str(e)}")
    
    def parse_syslog(self, file_content: str) -> pd.DataFrame:
        """Parse syslog format logs (common on Linux SSH)."""
        logs = []
        
        for line in file_content.split('\n'):
            if not line.strip():
                continue
                
            # Try SSH failed login
            match = re.search(self.log_patterns['auth_syslog'], line)
            if match:
                timestamp, username, source_ip = match.groups()
                logs.append({
                    'timestamp': timestamp,
                    'username': username,
                    'source_ip': source_ip,
                    'status': 'FAILED',
                    'event_type': 'AUTH_FAILURE'
                })
            
            # Try successful login
            elif 'Accepted' in line:
                match = re.search(r'(\w+ \d+ \d{2}:\d{2}:\d{2}).*Accepted (?:password|publickey) for (\w+) from (\S+)', line)
                if match:
                    timestamp, username, source_ip = match.groups()
                    logs.append({
                        'timestamp': timestamp,
                        'username': username,
                        'source_ip': source_ip,
                        'status': 'SUCCESS',
                        'event_type': 'AUTH_SUCCESS'
                    })
        
        return pd.DataFrame(logs)
        
    def parse_apache(self, file_content: str) -> pd.DataFrame:
        """Parse Apache Access/Auth logs."""
        logs = []
        
        for line in file_content.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(self.log_patterns['apache_auth'], line)
            if match:
                source_ip, username, timestamp, status_code = match.groups()
                
                # Check for failed authorization (HTTP 401 Unauthorized or 403 Forbidden)
                if status_code in ['401', '403']:
                    status = 'FAILED'
                    event_type = 'AUTH_FAILURE'
                else:
                    status = 'SUCCESS'
                    event_type = 'AUTH_SUCCESS'
                
                # If username is '-', set it to unknown
                if username == '-':
                    username = 'unknown'
                    
                logs.append({
                    'timestamp': timestamp,
                    'username': username,
                    'source_ip': source_ip,
                    'status': status,
                    'event_type': event_type
                })
                
        return pd.DataFrame(logs)
        
    def parse_windows(self, file_content: str) -> pd.DataFrame:
        """Parse Windows security event logs."""
        logs = []
        
        for line in file_content.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(self.log_patterns['windows_event'], line)
            if match:
                timestamp, event_id, username, source_ip = match.groups()
                
                # EventID 4625 = Failed Logon, EventID 4624 = Successful Logon
                if event_id == '4625':
                    status = 'FAILED'
                    event_type = 'AUTH_FAILURE'
                else:
                    status = 'SUCCESS'
                    event_type = 'AUTH_SUCCESS'
                    
                logs.append({
                    'timestamp': timestamp,
                    'username': username,
                    'source_ip': source_ip,
                    'status': status,
                    'event_type': event_type
                })
                
        return pd.DataFrame(logs)
        
    def parse_fail2ban(self, file_content: str) -> pd.DataFrame:
        """Parse Fail2Ban logs."""
        logs = []
        
        for line in file_content.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(self.log_patterns['fail2ban'], line)
            if match:
                timestamp, jail, source_ip = match.groups()
                
                logs.append({
                    'timestamp': timestamp,
                    'username': f'ban_jail_{jail}',
                    'source_ip': source_ip,
                    'status': 'FAILED',
                    'event_type': 'AUTH_FAILURE'
                })
                
        return pd.DataFrame(logs)
    
    def parse_raw_text(self, file_content: str) -> pd.DataFrame:
        """Parse raw text logs with flexible patterns."""
        logs = []
        
        for line in file_content.split('\n'):
            if not line.strip():
                continue
            
            parsed = self._extract_fields_from_line(line)
            if parsed:
                logs.append(parsed)
        
        if not logs:
            raise ValueError("Could not parse log file. Ensure it contains IP addresses and usernames.")
        
        return pd.DataFrame(logs)
    
    def _extract_fields_from_line(self, line: str) -> Dict:
        """Extract fields from a single log line."""
        result = {}
        
        # Extract timestamp
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',
            r'(\w+ \d{1,2} \d{2}:\d{2}:\d{2})',
            r'(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                result['timestamp'] = match.group(1)
                break
        
        if 'timestamp' not in result:
            result['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Extract IP address
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            result['source_ip'] = ip_match.group(0)
        else:
            return None
        
        # Extract username
        username_patterns = [
            r'for (?:invalid user )?(\w+)',
            r'user[=:]?\s+(\w+)',
            r'User[=:]?\s+(\w+)',
            r'(?:Failed|Invalid)\s+(?:password|user)\s+for\s+(\w+)',
        ]
        
        for pattern in username_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                result['username'] = match.group(1)
                break
        
        if 'username' not in result:
            result['username'] = 'unknown'
        
        # Determine status
        if any(keyword in line.lower() for keyword in ['failed', 'invalid', 'denied', 'rejected', 'error', 'ban']):
            result['status'] = 'FAILED'
            result['event_type'] = 'AUTH_FAILURE'
        elif any(keyword in line.lower() for keyword in ['accepted', 'success', 'granted', 'allowed']):
            result['status'] = 'SUCCESS'
            result['event_type'] = 'AUTH_SUCCESS'
        else:
            result['status'] = 'UNKNOWN'
            result['event_type'] = 'AUTH_ATTEMPT'
        
        return result
    
    def _standardize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize dataframe columns."""
        column_mapping = {
            'ip': 'source_ip',
            'source_ip': 'source_ip',
            'source': 'source_ip',
            'client': 'source_ip',
            'user': 'username',
            'username': 'username',
            'account': 'username',
            'time': 'timestamp',
            'timestamp': 'timestamp',
            'date': 'timestamp',
            'result': 'status',
            'status': 'status',
            'outcome': 'status',
        }
        
        # Rename columns if they exist
        for old_col, new_col in column_mapping.items():
            for col in df.columns:
                if old_col.lower() in col.lower() and new_col not in df.columns:
                    df = df.rename(columns={col: new_col})
                    break
        
        # Ensure required columns exist
        required_cols = ['timestamp', 'source_ip', 'username', 'status']
        for col in required_cols:
            if col not in df.columns:
                df[col] = 'unknown'
                
        # Make sure event_type exists or create it
        if 'event_type' not in df.columns:
            df['event_type'] = df['status'].apply(lambda s: 'AUTH_SUCCESS' if str(s).upper() == 'SUCCESS' else 'AUTH_FAILURE')
        
        return df[required_cols + ['event_type']].copy()
    
    def parse_file(self, file_content: str, file_type: str) -> pd.DataFrame:
        """Parse log file based on type."""
        if file_type == 'csv':
            return self.parse_csv(file_content)
        elif file_type == 'syslog':
            return self.parse_syslog(file_content)
        elif file_type == 'apache':
            return self.parse_apache(file_content)
        elif file_type == 'windows':
            return self.parse_windows(file_content)
        elif file_type == 'fail2ban':
            return self.parse_fail2ban(file_content)
        else:
            return self.parse_raw_text(file_content)


def infer_log_type(filename: str) -> str:
    """Infer log type from filename."""
    filename_lower = filename.lower()
    if filename_lower.endswith('.csv'):
        return 'csv'
    elif any(x in filename_lower for x in ['syslog', 'auth.log', 'secure']):
        return 'syslog'
    elif any(x in filename_lower for x in ['apache', 'access', 'httpd']):
        return 'apache'
    elif any(x in filename_lower for x in ['windows', 'event', 'security.evtx']):
        return 'windows'
    elif 'fail2ban' in filename_lower:
        return 'fail2ban'
    else:
        return 'text'
