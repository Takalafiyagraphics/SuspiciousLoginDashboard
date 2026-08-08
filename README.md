# Suspicious Login Log Analysis and Alert Dashboard

A comprehensive web-based cybersecurity dashboard built for academic submission that analyzes Linux authentication logs, detects suspicious login activities, generates alerts, and produces downloadable reports.

## Features

- **Log Upload & Parsing**: Upload `.txt`, `.log`, and `.csv` files containing authentication logs
- **Automatic Threat Detection**: 7 detection rules including brute-force, off-hours login, root access, and more
- **Risk Level Assignment**: Low, Medium, High, Critical risk classification
- **Interactive Dashboard**: Real-time statistics, charts, and activity feeds
- **Alert Management**: Color-coded severity levels with filtering and pagination
- **Log Viewer**: Search, sort, filter, and export login records
- **Report Generator**: PDF and CSV reports with charts and recommendations
- **Security Features**: Password hashing, CSRF protection, XSS prevention, SQL injection protection
- **Responsive Design**: Dark cybersecurity theme with mobile support

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3, Flask |
| Frontend | HTML5, CSS3, Bootstrap 5, JavaScript |
| Database | SQLite |
| Charts | Matplotlib |
| Reports | ReportLab (PDF), Pandas (CSV) |

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Step 1: Clone or Extract the Project

```bash
cd SuspiciousLoginDashboard
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Initialize the Database

```bash
python app.py
```

The database will be created automatically on first run, along with a default admin account.

## Running the Project

```bash
python app.py
```

The application will start on `http://localhost:5000`

Open your browser and navigate to: **http://localhost:5000**

## Default Login Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | Admin@123 | Administrator |

## Usage Guide

### 1. Login
- Navigate to the login page
- Enter credentials: `admin` / `Admin@123`
- Click "Sign In"

### 2. Dashboard
- View real-time statistics cards
- Analyze charts: login status, risk distribution, top IPs, hourly activity
- Review recent alerts and login activity

### 3. Upload Logs
- Go to "Upload Logs" in the sidebar
- Drag & drop or browse for `.txt`, `.log`, or `.csv` files
- Click "Upload & Analyze"
- The system will automatically parse and detect threats

### 4. View Logs
- Navigate to "View Logs"
- Use search, status filter, and risk filter
- Export data to CSV
- Paginate through results

### 5. Alerts
- Go to "Alerts" to see all detected threats
- Filter by severity: Critical, High, Medium, Low
- Color-coded for quick identification

### 6. Generate Reports
- Navigate to "Reports"
- Enter report name and select format (PDF or CSV)
- Click "Generate Report"
- Download from the reports table

### 7. Settings (Admin Only)
- Configure security thresholds
- Adjust alert parameters
- Manage database

## Detection Rules

The system automatically detects:

1. **Brute-force attacks**: More than 5 failed logins from one IP
2. **Successful breach**: Login after repeated failures
3. **Root access**: Root account login attempts
4. **Admin activity**: Admin account logins
5. **Off-hours login**: Logins between midnight and 5 AM
6. **External threats**: Failed logins from external IPs
7. **Rapid-fire attacks**: Multiple attempts within 5 minutes

## Project Structure

```
SuspiciousLoginDashboard/
├── app.py                  # Main Flask application
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── database.db            # SQLite database (auto-created)
├── uploads/               # Uploaded log files
├── reports/               # Generated reports
├── sample_logs/           # Sample log files
├── static/
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript files
│   └── images/           # Images and screenshots
├── templates/             # HTML templates
│   ├── base.html         # Base layout
│   ├── login.html        # Login page
│   ├── dashboard.html    # Main dashboard
│   ├── upload.html       # File upload
│   ├── logs.html         # Log viewer
│   ├── alerts.html       # Alerts page
│   ├── reports.html      # Report generator
│   ├── settings.html     # System settings
│   └── profile.html      # User profile
└── utils/
    ├── models.py         # Database models
    ├── parser.py         # Log parser
    ├── detector.py       # Threat detection engine
    ├── charts.py         # Chart generation
    └── report.py         # Report generator
```

## Security Features

- **Password Hashing**: Werkzeug secure password hashing
- **CSRF Protection**: Flask-WTF CSRF tokens on all forms
- **XSS Prevention**: Auto-escaping in Jinja2 templates
- **SQL Injection Protection**: SQLAlchemy ORM parameterized queries
- **Session Security**: HttpOnly cookies, session timeout
- **Secure File Upload**: Filename sanitization, extension validation
- **Input Validation**: Server-side validation on all inputs

## Testing

### Test Login
1. Open browser to `http://localhost:5000`
2. Login with `admin` / `Admin@123`
3. Verify dashboard loads with statistics

### Test Log Upload
1. Go to "Upload Logs"
2. Select `sample_auth_logs.txt` from `sample_logs/` folder
3. Click "Upload & Analyze"
4. Verify logs appear in "View Logs"
5. Check "Alerts" for detected threats

### Test Report Generation
1. Go to "Reports"
2. Enter report name: "Test Report"
3. Select PDF format
4. Click "Generate Report"
5. Download and verify the PDF

## Sample Log Format

The parser supports multiple formats:

**Standard auth.log:**
```
Jul 28 09:00:12 server sshd[1234]: Failed password for admin from 192.168.1.20
```

**Simple format:**
```
2026-07-28 09:00:12 admin 192.168.1.20 failed
```

**CSV format:**
```
2026-07-28, 09:00:12, admin, 192.168.1.20, failed
```

## Future Improvements

- [ ] Integration with real-time syslog streaming
- [ ] Machine learning-based anomaly detection
- [ ] Email/SMS alert notifications
- [ ] Geolocation mapping of IP addresses
- [ ] Multi-user role management
- [ ] API endpoints for external integrations
- [ ] Docker containerization
- [ ] Unit and integration test suite

## License

This project is created for academic purposes as part of a cybersecurity course.

## Author

Built as a cybersecurity academic project demonstrating:
- Secure software development practices
- Log analysis and threat detection
- Full-stack web application development
- Data visualization and reporting
