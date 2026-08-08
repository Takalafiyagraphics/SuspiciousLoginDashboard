from datetime import datetime, timedelta
from collections import defaultdict
from utils.models import Alert

class ThreatDetector:
    """Detect suspicious login activities."""

    def __init__(self, db_session):
        self.db = db_session
        self.suspicious_ips = set()
        self.known_ips = set()  # In production, load from config

    def analyze_logs(self, logs):
        """Analyze parsed logs and generate alerts."""
        alerts = []

        # Group by IP
        ip_logs = defaultdict(list)
        for log in logs:
            ip_logs[log['ip_address']].append(log)

        # Group by username
        user_logs = defaultdict(list)
        for log in logs:
            user_logs[log['username']].append(log)

        # Detection 1: More than 5 failed logins from one IP
        for ip, ip_log_list in ip_logs.items():
            failed = [l for l in ip_log_list if l['status'] == 'failed']
            if len(failed) > 5:
                alert = self._create_alert(
                    ip, failed[0]['username'],
                    'Critical',
                    f"Brute-force attack detected: {len(failed)} failed login attempts from IP {ip}"
                )
                alerts.append(alert)
                for l in failed:
                    l['risk_level'] = 'Critical'

        # Detection 2: Successful login after repeated failures
        for ip, ip_log_list in ip_logs.items():
            sorted_logs = sorted(ip_log_list, key=lambda x: datetime.combine(x['login_date'], x['login_time']))
            consecutive_failed = 0
            for log in sorted_logs:
                if log['status'] == 'failed':
                    consecutive_failed += 1
                elif log['status'] == 'success' and consecutive_failed >= 3:
                    alert = self._create_alert(
                        ip, log['username'],
                        'High',
                        f"Successful login after {consecutive_failed} failed attempts from IP {ip}"
                    )
                    alerts.append(alert)
                    log['risk_level'] = 'High'
                    consecutive_failed = 0
                else:
                    consecutive_failed = 0

        # Detection 3: Root login
        for log in logs:
            if log['username'] == 'root' and log['status'] == 'success':
                alert = self._create_alert(
                    log['ip_address'], 'root',
                    'Critical',
                    f"Root account login detected from {log['ip_address']}"
                )
                alerts.append(alert)
                log['risk_level'] = 'Critical'

        # Detection 4: Admin login
        for log in logs:
            if log['username'] in ('admin', 'administrator') and log['status'] == 'success':
                existing = [a for a in alerts if a['ip_address'] == log['ip_address'] and 'admin' in a['reason'].lower()]
                if not existing:
                    alert = self._create_alert(
                        log['ip_address'], log['username'],
                        'Medium',
                        f"Admin account login from {log['ip_address']}"
                    )
                    alerts.append(alert)
                if log['risk_level'] == 'Low':
                    log['risk_level'] = 'Medium'

        # Detection 5: Login between midnight and 5 AM
        for log in logs:
            hour = log['login_time'].hour
            if 0 <= hour < 5:
                alert = self._create_alert(
                    log['ip_address'], log['username'],
                    'Medium',
                    f"Suspicious login at {log['login_time'].strftime('%H:%M')} (off-hours) from {log['ip_address']}"
                )
                alerts.append(alert)
                if log['risk_level'] == 'Low':
                    log['risk_level'] = 'Medium'

        # Detection 6: Unknown IP (simulated - in production, check against whitelist)
        suspicious_ip_ranges = ['10.0.0.', '172.16.', '192.168.']
        for log in logs:
            ip = log['ip_address']
            is_internal = any(ip.startswith(prefix) for prefix in suspicious_ip_ranges)
            if not is_internal and log['status'] == 'failed':
                alert = self._create_alert(
                    ip, log['username'],
                    'High',
                    f"Failed login from external IP {ip}"
                )
                alerts.append(alert)
                if log['risk_level'] in ('Low', 'Medium'):
                    log['risk_level'] = 'High'

        # Detection 7: Repeated attacks within 5 minutes
        for ip, ip_log_list in ip_logs.items():
            sorted_logs = sorted(ip_log_list, key=lambda x: datetime.combine(x['login_date'], x['login_time']))
            for i in range(len(sorted_logs) - 2):
                current_time = datetime.combine(sorted_logs[i]['login_date'], sorted_logs[i]['login_time'])
                count = 1
                for j in range(i + 1, len(sorted_logs)):
                    next_time = datetime.combine(sorted_logs[j]['login_date'], sorted_logs[j]['login_time'])
                    if (next_time - current_time) <= timedelta(minutes=5):
                        count += 1
                    else:
                        break

                if count >= 3:
                    alert = self._create_alert(
                        ip, sorted_logs[i]['username'],
                        'High',
                        f"Rapid-fire attack: {count} attempts within 5 minutes from IP {ip}"
                    )
                    if not any(a['reason'] == alert['reason'] for a in alerts):
                        alerts.append(alert)
                    for k in range(i, min(i + count, len(sorted_logs))):
                        if sorted_logs[k]['risk_level'] in ('Low', 'Medium'):
                            sorted_logs[k]['risk_level'] = 'High'
                    break

        return alerts

    def _create_alert(self, ip, username, severity, reason):
        return {
            'ip_address': ip,
            'username': username,
            'severity': severity,
            'reason': reason
        }

    def save_alerts(self, alerts):
        """Save alerts to database."""
        for alert_data in alerts:
            alert = Alert(
                ip_address=alert_data['ip_address'],
                username=alert_data['username'],
                severity=alert_data['severity'],
                reason=alert_data['reason']
            )
            self.db.add(alert)
        self.db.commit()
