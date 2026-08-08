import os
from datetime import datetime, date
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect

from config import Config
from utils.models import db, User, LoginLog, Alert, Report
from utils.parser import LogParser
from utils.detector import ThreatDetector
from utils.charts import (create_success_vs_failed_chart, create_top_ips_chart,
                          create_risk_distribution_chart, create_hourly_activity_chart)
from utils.report import ReportGenerator

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

csrf = CSRFProtect(app)

report_generator = ReportGenerator(app.config['REPORTS_FOLDER'])

# Ensure upload and reports directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if not username or not password:
            flash('Please enter both username and password.', 'warning')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            session.permanent = True
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Statistics
    total_logs = LoginLog.query.count()
    successful_logins = LoginLog.query.filter_by(status='success').count()
    failed_logins = LoginLog.query.filter_by(status='failed').count()
    suspicious_logins = LoginLog.query.filter(LoginLog.risk_level.in_(['High', 'Critical'])).count()
    unique_ips = db.session.query(LoginLog.ip_address).distinct().count()
    today = date.today()
    todays_alerts = Alert.query.filter(db.func.date(Alert.created_at) == today).count()

    # Recent alerts
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()

    # Recent activities
    recent_logs = LoginLog.query.order_by(LoginLog.created_at.desc()).limit(10).all()

    # Charts
    all_logs = LoginLog.query.all()
    success_failed_chart = create_success_vs_failed_chart(all_logs)
    top_ips_chart = create_top_ips_chart(all_logs)
    risk_chart = create_risk_distribution_chart(all_logs)
    hourly_chart = create_hourly_activity_chart(all_logs)

    return render_template('dashboard.html',
                           total_logs=total_logs,
                           successful_logins=successful_logins,
                           failed_logins=failed_logins,
                           suspicious_logins=suspicious_logins,
                           unique_ips=unique_ips,
                           todays_alerts=todays_alerts,
                           recent_alerts=recent_alerts,
                           recent_logs=recent_logs,
                           success_failed_chart=success_failed_chart,
                           top_ips_chart=top_ips_chart,
                           risk_chart=risk_chart,
                           hourly_chart=hourly_chart)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            flash('No file selected.', 'warning')
            return redirect(request.url)

        file = request.files['logfile']

        if file.filename == '':
            flash('No file selected.', 'warning')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Parse the log file
            parser = LogParser()
            parsed_logs = parser.parse_file(filepath)

            if not parsed_logs:
                flash('No valid log entries found in the file.', 'warning')
                if parser.errors:
                    for error in parser.errors[:5]:
                        flash(error, 'info')
                return redirect(request.url)

            # Save logs to database
            for log_data in parsed_logs:
                log_entry = LoginLog(
                    username=log_data['username'],
                    ip_address=log_data['ip_address'],
                    login_date=log_data['login_date'],
                    login_time=log_data['login_time'],
                    status=log_data['status'],
                    risk_level=log_data.get('risk_level', 'Low'),
                    message=log_data['message']
                )
                db.session.add(log_entry)

            db.session.commit()

            # Run threat detection
            detector = ThreatDetector(db.session)
            alerts = detector.analyze_logs(parsed_logs)
            detector.save_alerts(alerts)

            flash(f'Successfully uploaded and analyzed {len(parsed_logs)} log entries. {len(alerts)} alerts generated.', 'success')
            return redirect(url_for('logs'))
        else:
            flash('Invalid file type. Allowed: TXT, LOG, CSV', 'danger')

    return render_template('upload.html')

@app.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    per_page = 25
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    risk_filter = request.args.get('risk', '')

    query = LoginLog.query

    if search:
        query = query.filter(
            db.or_(
                LoginLog.username.contains(search),
                LoginLog.ip_address.contains(search),
                LoginLog.message.contains(search)
            )
        )

    if status_filter:
        query = query.filter_by(status=status_filter)

    if risk_filter:
        query = query.filter_by(risk_level=risk_filter)

    logs_pagination = query.order_by(LoginLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('logs.html', logs=logs_pagination, search=search,
                           status_filter=status_filter, risk_filter=risk_filter)

@app.route('/alerts')
@login_required
def alerts():
    page = request.args.get('page', 1, type=int)
    per_page = 25
    severity_filter = request.args.get('severity', '')

    query = Alert.query

    if severity_filter:
        query = query.filter_by(severity=severity_filter)

    alerts_pagination = query.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('alerts.html', alerts=alerts_pagination, severity_filter=severity_filter)

@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    if request.method == 'POST':
        report_type = request.form.get('report_type', 'pdf')
        report_name = request.form.get('report_name', f"Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        all_logs = LoginLog.query.all()
        all_alerts = Alert.query.all()

        if report_type == 'pdf':
            filename = f"{report_name}.pdf"
            filepath = report_generator.generate_pdf(all_logs, all_alerts, filename)
        else:
            filename = f"{report_name}.csv"
            filepath = report_generator.generate_csv(all_logs, filename)

        report = Report(report_name=report_name, generated_on=datetime.now())
        db.session.add(report)
        db.session.commit()

        flash(f'Report generated successfully: {filename}', 'success')
        return redirect(url_for('reports'))

    generated_reports = Report.query.order_by(Report.generated_on.desc()).all()
    return render_template('reports.html', reports=generated_reports)

@app.route('/reports/download/<filename>')
@login_required
def download_report(filename):
    return send_from_directory(app.config['REPORTS_FOLDER'], filename, as_attachment=True)

@app.route('/settings')
@login_required
@admin_required
def settings():
    return render_template('settings.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/export/logs/csv')
@login_required
def export_logs_csv():
    import csv
    from io import StringIO

    all_logs = LoginLog.query.all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'IP Address', 'Date', 'Time', 'Status', 'Risk Level', 'Message'])

    for log in all_logs:
        writer.writerow([
            log.id, log.username, log.ip_address,
            log.login_date.strftime('%Y-%m-%d'),
            log.login_time.strftime('%H:%M:%S'),
            log.status, log.risk_level, log.message or ''
        ])

    output.seek(0)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename=login_logs.csv'
    }

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard statistics."""
    return jsonify({
        'total_logs': LoginLog.query.count(),
        'successful': LoginLog.query.filter_by(status='success').count(),
        'failed': LoginLog.query.filter_by(status='failed').count(),
        'alerts': Alert.query.count(),
        'unique_ips': db.session.query(LoginLog.ip_address).distinct().count()
    })

# ============================================================
# CLI COMMANDS
# ============================================================

@app.cli.command('init-db')
def init_db():
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        print('Database initialized successfully!')

@app.cli.command('create-admin')
def create_admin():
    """Create default admin user."""
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print('Admin user created: username=admin, password=Admin@123')
        else:
            print('Admin user already exists.')

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):
    return render_template('base.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('base.html', error='Internal server error'), 500

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print('Default admin created: admin / Admin@123')

    app.run(debug=True, host='0.0.0.0', port=5000)
