import re
import csv
from datetime import datetime
from collections import defaultdict

class LogParser:
    """Parse various log formats into structured data."""

    # Regex patterns for different log formats
    PATTERNS = [
        # Standard auth.log format
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+sshd\[\d+\]:\s+(\w+)\s+password\s+for\s+(\S+)\s+from\s+(\S+)',
        # Alternative format
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+sshd\[\d+\]:\s+Accepted\s+\w+\s+for\s+(\S+)\s+from\s+(\S+)',
        # Simple format
        r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\S+)\s+(\S+)\s+(success|failed)',
        # CSV-like format
        r'^(\d{4}-\d{2}-\d{2}),\s*(\d{2}:\d{2}:\d{2}),\s*(\S+),\s*(\S+),\s*(success|failed)',
    ]

    def __init__(self):
        self.parsed_logs = []
        self.errors = []

    def parse_file(self, filepath):
        """Parse a log file and return structured data."""
        self.parsed_logs = []
        self.errors = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            self.errors.append(f"Error reading file: {str(e)}")
            return []

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            parsed = self._parse_line(line)
            if parsed:
                self.parsed_logs.append(parsed)
            else:
                # Try CSV format
                parsed = self._parse_csv_line(line)
                if parsed:
                    self.parsed_logs.append(parsed)
                else:
                    self.errors.append(f"Line {line_num}: Could not parse - {line[:100]}")

        return self.parsed_logs

    def _parse_line(self, line):
        """Try to parse a single log line."""
        # Try standard auth log format
        # Jul 28 09:00:12 server sshd[1234]: Failed password for admin from 192.168.1.20
        match = re.search(
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+sshd\[\d+\]:\s+(\w+)\s+\w+\s+for\s+(\S+)\s+from\s+(\S+)',
            line
        )
        if match:
            date_str, status, username, ip = match.groups()
            status = 'failed' if 'fail' in status.lower() else 'success'
            dt = self._parse_date(date_str)
            return {
                'username': username,
                'ip_address': ip,
                'login_date': dt.date() if dt else datetime.now().date(),
                'login_time': dt.time() if dt else datetime.now().time(),
                'status': status,
                'message': line
            }

        # Try accepted format
        match = re.search(
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+sshd\[\d+\]:\s+Accepted\s+\w+\s+for\s+(\S+)\s+from\s+(\S+)',
            line
        )
        if match:
            date_str, username, ip = match.groups()
            dt = self._parse_date(date_str)
            return {
                'username': username,
                'ip_address': ip,
                'login_date': dt.date() if dt else datetime.now().date(),
                'login_time': dt.time() if dt else datetime.now().time(),
                'status': 'success',
                'message': line
            }

        # Try simple format: 2026-07-28 09:00:12 admin 192.168.1.20 failed
        match = re.search(
            r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(success|failed)',
            line
        )
        if match:
            date_str, time_str, username, ip, status = match.groups()
            dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            return {
                'username': username,
                'ip_address': ip,
                'login_date': dt.date(),
                'login_time': dt.time(),
                'status': status,
                'message': line
            }

        return None

    def _parse_csv_line(self, line):
        """Try to parse CSV format."""
        try:
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 5:
                date_str = parts[0]
                time_str = parts[1]
                username = parts[2]
                ip = parts[3]
                status = parts[4].lower()

                if status in ('success', 'failed'):
                    dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                    return {
                        'username': username,
                        'ip_address': ip,
                        'login_date': dt.date(),
                        'login_time': dt.time(),
                        'status': status,
                        'message': line
                    }
        except:
            pass
        return None

    def _parse_date(self, date_str):
        """Parse date string like 'Jul 28 09:00:12'."""
        try:
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {date_str}", "%Y %b %d %H:%M:%S")
            return dt
        except:
            return None
