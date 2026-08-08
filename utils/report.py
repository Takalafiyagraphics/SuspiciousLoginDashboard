import os
from datetime import datetime
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

class ReportGenerator:
    """Generate PDF and CSV reports."""

    def __init__(self, reports_folder):
        self.reports_folder = reports_folder

    def generate_pdf(self, logs, alerts, filename):
        """Generate a comprehensive PDF report."""
        filepath = os.path.join(self.reports_folder, filename)
        doc = SimpleDocTemplate(filepath, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#0d6efd'),
            spaceAfter=12,
            spaceBefore=12
        )

        story = []

        # Title
        story.append(Paragraph("Suspicious Login Analysis Report", title_style))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        total_logs = len(logs)
        successful = sum(1 for l in logs if l.status == 'success')
        failed = sum(1 for l in logs if l.status == 'failed')
        unique_ips = len(set(l.ip_address for l in logs))

        summary_data = [
            ['Metric', 'Value'],
            ['Total Login Attempts', str(total_logs)],
            ['Successful Logins', str(successful)],
            ['Failed Logins', str(failed)],
            ['Unique IP Addresses', str(unique_ips)],
            ['Total Alerts', str(len(alerts))],
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        # Top Attacking IPs
        story.append(Paragraph("Top Attacking IP Addresses", heading_style))
        failed_logs = [l for l in logs if l.status == 'failed']
        ip_counts = Counter(l.ip_address for l in failed_logs)
        top_ips = ip_counts.most_common(10)

        if top_ips:
            ip_data = [['IP Address', 'Failed Attempts', 'Risk Level']]
            for ip, count in top_ips:
                risk = 'Critical' if count > 10 else 'High' if count > 5 else 'Medium'
                ip_data.append([ip, str(count), risk])

            ip_table = Table(ip_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc3545')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(ip_table)
        else:
            story.append(Paragraph("No failed login attempts detected.", styles['Normal']))

        story.append(Spacer(1, 0.3*inch))

        # Suspicious Users
        story.append(Paragraph("Suspicious User Accounts", heading_style))
        user_counts = Counter(l.username for l in failed_logs)
        suspicious_users = [(u, c) for u, c in user_counts.most_common(10) if c >= 3]

        if suspicious_users:
            user_data = [['Username', 'Failed Attempts', 'Status']]
            for user, count in suspicious_users:
                status = 'Blocked' if count > 10 else 'Monitored'
                user_data.append([user, str(count), status])

            user_table = Table(user_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            user_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fd7e14')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(user_table)
        else:
            story.append(Paragraph("No suspicious user activity detected.", styles['Normal']))

        story.append(PageBreak())

        # Alerts Summary
        story.append(Paragraph("Security Alerts", heading_style))
        if alerts:
            alert_data = [['Severity', 'IP Address', 'Username', 'Reason']]
            for alert in alerts[:20]:  # Top 20 alerts
                alert_data.append([
                    alert.severity,
                    alert.ip_address,
                    alert.username,
                    alert.reason[:60] + '...' if len(alert.reason) > 60 else alert.reason
                ])

            alert_table = Table(alert_data, colWidths=[1.2*inch, 1.5*inch, 1.2*inch, 2.5*inch])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6c757d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(alert_table)
        else:
            story.append(Paragraph("No alerts generated.", styles['Normal']))

        story.append(Spacer(1, 0.3*inch))

        # Recommendations
        story.append(Paragraph("Security Recommendations", heading_style))
        recommendations = [
            "1. Implement IP-based rate limiting on SSH and other services.",
            "2. Enable multi-factor authentication (MFA) for all admin accounts.",
            "3. Configure fail2ban to automatically block IPs with repeated failed attempts.",
            "4. Disable root login via SSH and use sudo for administrative tasks.",
            "5. Review and update firewall rules regularly.",
            "6. Monitor off-hours login activity and set up automated alerts.",
            "7. Implement geolocation-based access controls.",
            "8. Regularly audit user accounts and remove unused credentials.",
        ]

        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))

        doc.build(story)
        return filepath

    def generate_csv(self, logs, filename):
        """Generate CSV report."""
        import csv
        filepath = os.path.join(self.reports_folder, filename)

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Username', 'IP Address', 'Date', 'Time', 'Status', 'Risk Level', 'Message'])

            for log in logs:
                writer.writerow([
                    log.id,
                    log.username,
                    log.ip_address,
                    log.login_date.strftime('%Y-%m-%d'),
                    log.login_time.strftime('%H:%M:%S'),
                    log.status,
                    log.risk_level,
                    log.message or ''
                ])

        return filepath
