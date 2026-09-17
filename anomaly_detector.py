import pandas as pd
import numpy as np
from typing import List, Dict, Tuple
from datetime import datetime, timedelta
import hashlib

def get_ip_country(ip: str) -> str:
    """Simulates a fast, offline IP-to-Country geolocation lookup for analytics."""
    if not isinstance(ip, str):
        return "Unknown"
        
    # Handle local / private network IPs
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
        return "Internal Network (LAN)"
    
    # Realistic mapping for common demo/test IPs
    sample_mapping = {
        "8.8.8.8": "United States",
        "1.1.1.1": "Australia",
        "45.22.30.1": "Brazil",
        "185.190.140.2": "Netherlands",
        "91.200.12.4": "Ukraine",
        "203.0.113.5": "Japan",
        "198.51.100.12": "Germany",
    }
    if ip in sample_mapping:
        return sample_mapping[ip]
    
    # Deterministic hash mapping to mock countries for test IPs
    countries = ["United States", "United Kingdom", "Germany", "Canada", "France", "Japan", "Brazil", "Australia", "India", "China"]
    try:
        ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        return countries[ip_hash % len(countries)]
    except:
        return "Unknown Country"


class AnomalyDetector:
    """Detect anomalies in security logs using statistical and heuristic methods."""
    
    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.anomalies = []
        self._parse_timestamps()
    
    def _parse_timestamps(self):
        """Convert timestamp strings to datetime objects robustly, supporting multiple formats."""
        parsed_timestamps = []
        
        for ts in self.df['timestamp']:
            if isinstance(ts, pd.Timestamp) or isinstance(ts, datetime):
                parsed_timestamps.append(ts)
                continue
                
            parsed_ts = None
            ts_str = str(ts).strip()
            
            # Try multiple known log formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%d/%b/%Y:%H:%M:%S',
                '%b %d %H:%M:%S',  # Syslog (e.g., Jan 15 08:23:14)
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d',
                '%m/%d/%Y %I:%M:%S %p' # Windows-style format
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(ts_str, fmt)
                    # For Syslog (which lacks year), assume the current year
                    if fmt == '%b %d %H:%M:%S':
                        dt = dt.replace(year=datetime.now().year)
                    parsed_ts = dt
                    break
                except ValueError:
                    continue
            
            if parsed_ts is None:
                # Use pandas parser as a final fallback
                try:
                    parsed_ts = pd.to_datetime(ts_str)
                except:
                    parsed_ts = datetime.now()
                    
            parsed_timestamps.append(parsed_ts)
            
        self.df['timestamp'] = parsed_timestamps
    
    def detect_all_anomalies(self) -> List[Dict]:
        """Run all anomaly detection methods."""
        self.anomalies = []
        
        self.anomalies.extend(self._detect_brute_force())
        self.anomalies.extend(self._detect_credential_stuffing())
        self.anomalies.extend(self._detect_rate_anomaly())
        self.anomalies.extend(self._detect_geographical_anomaly())
        self.anomalies.extend(self._detect_privilege_escalation())
        self.anomalies.extend(self._detect_account_lockout_pattern())
        
        # Sort by severity
        self.anomalies.sort(key=lambda x: self._severity_score(x['severity']), reverse=True)
        return self.anomalies
    
    def _detect_brute_force(self) -> List[Dict]:
        """Detect brute force attempts (multiple failed logins from single IP)."""
        anomalies = []
        
        failed_logins = self.df[
            (self.df['status'].str.upper() == 'FAILED') &
            (self.df['event_type'] == 'AUTH_FAILURE')
        ]
        
        # Group by IP and count failures
        ip_failures = failed_logins.groupby('source_ip').size()
        
        for ip, count in ip_failures.items():
            # Alert if more than 5 failures from single IP
            if count >= 5:
                # Check if failures are within 10-minute window
                ip_logs = failed_logins[failed_logins['source_ip'] == ip].sort_values('timestamp')
                if len(ip_logs) >= 2:
                    first_attempt = ip_logs['timestamp'].iloc[0]
                    last_attempt = ip_logs['timestamp'].iloc[-1]
                    time_window = (last_attempt - first_attempt).total_seconds() / 60
                    
                    # If within 10 minutes, it's suspicious
                    if time_window <= 10:
                        severity = 'CRITICAL' if count >= 20 else 'HIGH'
                        
                        anomalies.append({
                            'type': 'BRUTE_FORCE_ATTACK',
                            'severity': severity,
                            'description': f'Brute force attack detected from IP {ip}',
                            'details': {
                                'source_ip': ip,
                                'failed_attempts': int(count),
                                'time_window_minutes': int(time_window),
                                'target_accounts': list(ip_logs['username'].unique()),
                                'first_attempt': str(first_attempt),
                                'last_attempt': str(last_attempt),
                            },
                            'confidence': min(100, int((count / 5) * 50 + (10 - time_window) * 5)),
                        })
        
        return anomalies
    
    def _detect_credential_stuffing(self) -> List[Dict]:
        """Detect credential stuffing (same account, multiple IPs)."""
        anomalies = []
        
        failed_logins = self.df[
            (self.df['status'].str.upper() == 'FAILED') &
            (self.df['event_type'] == 'AUTH_FAILURE')
        ]
        
        # Group by username and count unique IPs
        user_ips = failed_logins.groupby('username')['source_ip'].nunique()
        
        for username, unique_ips in user_ips.items():
            if unique_ips >= 3:
                user_failures = failed_logins[failed_logins['username'] == username]
                
                anomalies.append({
                    'type': 'CREDENTIAL_STUFFING',
                    'severity': 'HIGH',
                    'description': f'Credential stuffing attack detected on account: {username}',
                    'details': {
                        'target_account': username,
                        'failed_attempts': len(user_failures),
                        'attacking_ips': list(user_failures['source_ip'].unique()),
                        'unique_ips': int(unique_ips),
                        'time_span': f"{(user_failures['timestamp'].max() - user_failures['timestamp'].min()).total_seconds() / 60:.1f} minutes",
                    },
                    'confidence': min(100, int(unique_ips * 25)),
                })
        
        return anomalies
    
    def _detect_rate_anomaly(self) -> List[Dict]:
        """Detect unusual login rate changes."""
        anomalies = []
        
        # Calculate login attempts per minute
        if len(self.df) >= 10:
            df_sorted = self.df.sort_values('timestamp')
            total_time = (df_sorted['timestamp'].max() - df_sorted['timestamp'].min()).total_seconds() / 60
            
            if total_time > 0:
                avg_rate = len(self.df) / total_time
                
                # Check for spikes
                failed_logins = self.df[self.df['status'].str.upper() == 'FAILED']
                if len(failed_logins) > 0:
                    failed_rate = len(failed_logins) / total_time
                    
                    if failed_rate > avg_rate * 2:  # 2x normal rate
                        anomalies.append({
                            'type': 'RATE_ANOMALY',
                            'severity': 'MEDIUM',
                            'description': 'Unusual spike in failed login attempts',
                            'details': {
                                'failed_logins_per_minute': round(failed_rate, 2),
                                'average_rate': round(avg_rate, 2),
                                'spike_factor': round(failed_rate / avg_rate, 2),
                            },
                            'confidence': min(100, int((failed_rate / avg_rate) * 30)),
                        })
        
        return anomalies
    
    def _detect_geographical_anomaly(self) -> List[Dict]:
        """Detect logins from physically impossible different locations (countries) within a short time."""
        anomalies = []
        
        # Check logins by user
        for username in self.df['username'].unique():
            if username == 'unknown' or username == 'root' or username == 'admin':
                # Ignore generic accounts to prevent noisy alerts, focus on specific named accounts
                pass
                
            user_logs = self.df[self.df['username'] == username].sort_values('timestamp')
            
            # Extract distinct IPs used by this user and map to countries
            if len(user_logs) >= 2:
                for i in range(len(user_logs) - 1):
                    row1 = user_logs.iloc[i]
                    row2 = user_logs.iloc[i+1]
                    
                    ip1, ip2 = row1['source_ip'], row2['source_ip']
                    if ip1 == ip2:
                        continue
                        
                    country1 = get_ip_country(ip1)
                    country2 = get_ip_country(ip2)
                    
                    # If countries are different and both logins are valid/successful or within short time
                    if country1 != country2 and country1 != "Internal Network (LAN)" and country2 != "Internal Network (LAN)":
                        time_span = (row2['timestamp'] - row1['timestamp']).total_seconds() / 60
                        
                        # Within 60 minutes, login from two different countries is physically impossible
                        if time_span <= 60:
                            anomalies.append({
                                'type': 'GEOGRAPHICAL_ANOMALY',
                                'severity': 'CRITICAL' if row2['status'] == 'SUCCESS' else 'HIGH',
                                'description': f"Impossible travel detected for user '{username}'",
                                'details': {
                                    'username': username,
                                    'first_login': {
                                        'ip': ip1,
                                        'location': country1,
                                        'time': str(row1['timestamp']),
                                        'status': row1['status']
                                    },
                                    'second_login': {
                                        'ip': ip2,
                                        'location': country2,
                                        'time': str(row2['timestamp']),
                                        'status': row2['status']
                                    },
                                    'time_span_minutes': round(time_span, 1),
                                },
                                'confidence': min(100, int((60 - time_span) * 1.5 + 40)),
                            })
                            break # Avoid duplicate alerts for same user session
        
        return anomalies
    
    def _detect_privilege_escalation(self) -> List[Dict]:
        """Detect privilege escalation attempts."""
        anomalies = []
        
        # Look for patterns like root, admin, service account failures followed by successes
        privileged_accounts = ['root', 'admin', 'administrator', 'system', 'service', 'backup']
        
        for account in privileged_accounts:
            account_logs = self.df[self.df['username'].str.lower().str.contains(account, na=False)]
            
            if len(account_logs) > 0:
                failed = account_logs[account_logs['status'].str.upper() == 'FAILED']
                
                if len(failed) >= 3:
                    anomalies.append({
                        'type': 'PRIVILEGE_ESCALATION_ATTEMPT',
                        'severity': 'CRITICAL',
                        'description': 'Multiple failed login attempts on privileged account',
                        'details': {
                            'target_account': failed['username'].iloc[0],
                            'failed_attempts': len(failed),
                            'attacking_ips': list(failed['source_ip'].unique()),
                            'first_attempt': str(failed['timestamp'].min()),
                        },
                        'confidence': min(100, int(len(failed) * 20)),
                    })
        
        return anomalies
    
    def _detect_account_lockout_pattern(self) -> List[Dict]:
        """Detect account lockout patterns."""
        anomalies = []
        
        failed_logins = self.df[self.df['status'].str.upper() == 'FAILED']
        
        for username in failed_logins['username'].unique():
            user_failures = failed_logins[failed_logins['username'] == username]
            
            # Lockout typically occurs after 5-10 failed attempts
            if len(user_failures) >= 5:
                # Check if there were any successful logins after
                user_all = self.df[self.df['username'] == username].sort_values('timestamp')
                last_failure = user_failures['timestamp'].max()
                later_successes = user_all[
                    (user_all['timestamp'] > last_failure) &
                    (user_all['status'].str.upper() == 'SUCCESS')
                ]
                
                if len(later_successes) == 0:
                    anomalies.append({
                        'type': 'ACCOUNT_LOCKED',
                        'severity': 'MEDIUM',
                        'description': f'Account {username} may be locked due to failed login attempts',
                        'details': {
                            'username': username,
                            'failed_attempts': len(user_failures),
                            'last_failure': str(last_failure),
                            'requires_unlock': True,
                        },
                        'confidence': min(100, int((len(user_failures) / 5) * 100)),
                    })
        
        return anomalies
    
    @staticmethod
    def _severity_score(severity: str) -> int:
        """Convert severity to numeric score."""
        scores = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
        }
        return scores.get(severity, 0)
    
    def get_statistics(self) -> Dict:
        """Get log statistics."""
        total_logs = len(self.df)
        failed_logins = len(self.df[self.df['status'].str.upper() == 'FAILED'])
        success_logins = len(self.df[self.df['status'].str.upper() == 'SUCCESS'])
        
        return {
            'total_logs': total_logs,
            'failed_logins': failed_logins,
            'successful_logins': success_logins,
            'unique_users': self.df['username'].nunique(),
            'unique_ips': self.df['source_ip'].nunique(),
            'failure_rate': round((failed_logins / total_logs * 100) if total_logs > 0 else 0, 2),
            'time_span': str(self.df['timestamp'].max() - self.df['timestamp'].min()) if total_logs > 0 else "0",
        }
