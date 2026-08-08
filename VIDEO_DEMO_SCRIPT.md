# Suspicious Login Log Analysis and Alert Dashboard
## Video Demonstration Script (2-3 minutes)

---

### 1. PROJECT OVERVIEW (0:00-0:20)

**[Screen: Title card with project name and logo]**

"Welcome to the Suspicious Login Log Analysis and Alert Dashboard - a comprehensive cybersecurity tool built for detecting and analyzing suspicious authentication activities. This web application automatically parses Linux authentication logs, identifies threats, generates alerts, and produces detailed security reports."

---

### 2. LOGIN (0:20-0:35)

**[Screen: Navigate to localhost:5000, show login page]**

"First, we log into the system using secure credentials. The login page features password hashing, session management, and CSRF protection for security."

- Enter username: `admin`
- Enter password: `Admin@123`
- Click "Sign In"
- Dashboard loads

---

### 3. DASHBOARD OVERVIEW (0:35-1:00)

**[Screen: Dashboard with statistics and charts]**

"The main dashboard provides a real-time security overview with six key metrics: total logs, successful logins, failed logins, suspicious activities, unique IP addresses, and today's alerts. The charts section visualizes login status distribution, risk levels, top attacking IPs, and hourly activity patterns."

- Point to each stat card
- Show the four charts
- Scroll through recent alerts and activity feed

---

### 4. UPLOADING LOGS (1:00-1:30)

**[Screen: Navigate to Upload Logs page]**

"Now we upload a sample authentication log file. The system supports TXT, LOG, and CSV formats. Simply drag and drop or browse for the file."

- Click "Upload Logs" in sidebar
- Drag `sample_auth_logs.txt` into upload area
- Click "Upload & Analyze"
- Show success message: "Successfully uploaded and analyzed 214 log entries. 45 alerts generated."

---

### 5. AUTOMATIC ANALYSIS (1:30-1:50)

**[Screen: Show View Logs and Alerts pages]**

"The system automatically parsed all 214 log entries and detected multiple threat patterns including brute-force attacks, root login attempts, off-hours access, and rapid-fire attacks from external IPs."

- Navigate to "View Logs" - show the parsed data table
- Navigate to "Alerts" - show color-coded severity levels
- Point out Critical alerts (red), High alerts (orange)
- Show filtering by severity

---

### 6. REPORTS (1:50-2:15)

**[Screen: Navigate to Reports page]**

"The report generator creates comprehensive PDF and CSV reports containing executive summaries, statistical analysis, top attacking IPs, suspicious users, security alerts, and actionable recommendations."

- Enter report name: "Security Analysis Report"
- Select PDF format
- Click "Generate Report"
- Show generated report in the table
- Click download to show the PDF

---

### 7. CONCLUSION (2:15-2:30)

**[Screen: Return to dashboard]**

"This dashboard demonstrates practical cybersecurity skills including log analysis, threat detection, secure web development, and data visualization. It serves as an effective tool for monitoring authentication security and identifying potential breaches in real-time. Thank you for watching."

---

## Key Features to Highlight During Demo:

1. **Dark cybersecurity theme** - Professional, modern UI
2. **Responsive design** - Works on desktop and mobile
3. **Real-time statistics** - Auto-updating dashboard cards
4. **Color-coded alerts** - Critical (red), High (orange), Medium (yellow), Low (green)
5. **Chart visualization** - Matplotlib-generated charts
6. **Search and filter** - Advanced log filtering capabilities
7. **Export functionality** - CSV export and PDF/CSV reports
8. **Security features** - Password hashing, CSRF, XSS, SQL injection protection
