import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
from collections import Counter

def generate_chart_base64(fig):
    """Convert matplotlib figure to base64 string."""
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', dpi=100, facecolor='#1a1a2e')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return img_base64

def create_success_vs_failed_chart(logs):
    """Create pie chart for successful vs failed logins."""
    if not logs:
        return None

    status_counts = Counter([log.status for log in logs])

    fig, ax = plt.subplots(figsize=(6, 4), facecolor='#1a1a2e')
    ax.set_facecolor('#1a1a2e')

    colors = ['#198754', '#dc3545']
    labels = ['Successful', 'Failed']
    sizes = [status_counts.get('success', 0), status_counts.get('failed', 0)]

    if sum(sizes) == 0:
        return None

    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                                       startangle=90, textprops={'color': 'white'})
    ax.set_title('Successful vs Failed Logins', color='white', fontsize=14, fontweight='bold')

    return generate_chart_base64(fig)

def create_top_ips_chart(logs, top_n=10):
    """Create bar chart for top attacking IP addresses."""
    if not logs:
        return None

    failed_logs = [log for log in logs if log.status == 'failed']
    ip_counts = Counter([log.ip_address for log in failed_logs])
    top_ips = ip_counts.most_common(top_n)

    if not top_ips:
        return None

    fig, ax = plt.subplots(figsize=(10, 5), facecolor='#1a1a2e')
    ax.set_facecolor('#1a1a2e')

    ips = [ip for ip, count in top_ips]
    counts = [count for ip, count in top_ips]

    bars = ax.barh(ips, counts, color='#dc3545')
    ax.set_xlabel('Failed Login Attempts', color='white')
    ax.set_ylabel('IP Address', color='white')
    ax.set_title('Top Attacking IP Addresses', color='white', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.invert_yaxis()

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                str(count), va='center', color='white')

    return generate_chart_base64(fig)

def create_risk_distribution_chart(logs):
    """Create bar chart for risk level distribution."""
    if not logs:
        return None

    risk_counts = Counter([log.risk_level for log in logs])

    fig, ax = plt.subplots(figsize=(8, 5), facecolor='#1a1a2e')
    ax.set_facecolor('#1a1a2e')

    levels = ['Low', 'Medium', 'High', 'Critical']
    counts = [risk_counts.get(level, 0) for level in levels]
    colors = ['#198754', '#ffc107', '#fd7e14', '#dc3545']

    bars = ax.bar(levels, counts, color=colors)
    ax.set_xlabel('Risk Level', color='white')
    ax.set_ylabel('Number of Logins', color='white')
    ax.set_title('Risk Level Distribution', color='white', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')

    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    str(count), ha='center', color='white')

    return generate_chart_base64(fig)

def create_hourly_activity_chart(logs):
    """Create line chart for login activity by hour."""
    if not logs:
        return None

    hour_counts = Counter([log.login_time.hour for log in logs])
    hours = list(range(24))
    counts = [hour_counts.get(h, 0) for h in hours]

    fig, ax = plt.subplots(figsize=(12, 4), facecolor='#1a1a2e')
    ax.set_facecolor('#1a1a2e')

    ax.plot(hours, counts, marker='o', color='#0dcaf0', linewidth=2, markersize=4)
    ax.fill_between(hours, counts, alpha=0.3, color='#0dcaf0')
    ax.set_xlabel('Hour of Day', color='white')
    ax.set_ylabel('Number of Logins', color='white')
    ax.set_title('Login Activity by Hour', color='white', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.set_xticks(hours)
    ax.grid(True, alpha=0.2, color='white')

    return generate_chart_base64(fig)
