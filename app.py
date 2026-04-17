import io, os, sys, json, re, time, warnings, hashlib, threading, smtplib, subprocess, zipfile, html as _html
import csv, ipaddress, uuid
from datetime import datetime, timedelta

try:
    import pyotp
    import qrcode
    import qrcode.image.svg
    HAS_2FA = True
except Exception:
    HAS_2FA = False
from pathlib import Path
from functools import wraps
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import numpy as np
import pandas as pd
import joblib
import requests as req_lib
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash, send_file, send_from_directory, Response, stream_with_context)
from werkzeug.utils import secure_filename

warnings.filterwarnings('ignore')

if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetDllDirectoryW(None)
    except Exception:
        pass

app = Flask(__name__)
_secret_key = os.environ.get('SECRET_KEY', '')
if not _secret_key:
    import logging as _logging
    _logging.warning('SECRET_KEY env var not set — using insecure default. Set SECRET_KEY in production.')
    _secret_key = 'sentinel-ids-2025-xK9mP3qR'
app.secret_key = _secret_key
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2 GB
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SESSION_COOKIE_HTTPONLY']  = True
app.config['SESSION_COOKIE_SAMESITE']  = 'Lax'
app.config['SESSION_COOKIE_SECURE']    = os.environ.get('FLASK_ENV') == 'production'

BASE_DIR   = Path(__file__).parent
MODELS_DIR = BASE_DIR / 'models'
OUTPUTS    = BASE_DIR / 'outputs'
HISTORY    = OUTPUTS / 'scan_history.json'
FLOWS_DIR  = OUTPUTS / 'flows'
UPLOAD_DIR = OUTPUTS / 'uploads'
CONFIG_PATH = BASE_DIR / 'config.json'
WATCHLIST_PATH     = OUTPUTS / 'watchlist.json'
IP_CACHE_PATH      = OUTPUTS / 'ip_cache.json'
NOTIFICATIONS_PATH = OUTPUTS / 'notifications.json'
TRIAGE_PATH        = OUTPUTS / 'triage.json'
AUDIT_PATH         = OUTPUTS / 'audit.json'
CASES_PATH         = OUTPUTS / 'cases.json'
CASE_ATTACH_DIR    = OUTPUTS / 'case_attachments'
SCHEDULES_PATH     = OUTPUTS / 'schedules.json'
ALERT_RULES_PATH   = OUTPUTS / 'alert_rules.json'
FP_FEEDBACK_PATH   = OUTPUTS / 'fp_feedback.json'
WHITELIST_PATH     = OUTPUTS / 'whitelist_ips.json'
SESSION_TIMEOUT_MINUTES = 120

for d in [OUTPUTS, FLOWS_DIR, UPLOAD_DIR, CASE_ATTACH_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Config ────────────────────────────────────────────────────────────────────
def get_config():
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}

def _csv_safe(value):
    """Prevent CSV formula injection by prefixing dangerous leading chars."""
    s = str(value) if value is not None else ''
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s

def _safe_write(path, data):
    """Write JSON atomically with retry — handles OneDrive/antivirus file locks.
    Uses a temp file + os.replace so a mid-write failure never corrupts the target."""
    import time, tempfile
    for attempt in range(5):
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix='.tmp')
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(data, f, indent=2)
            except Exception:
                try: os.close(fd)
                except OSError: pass
                raise
            os.replace(tmp_path, path)
            # Restrict permissions so only the owner can read/write (protects API keys & secrets)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass  # Windows may not support this; best-effort
            return
        except PermissionError:
            if tmp_path:
                try: os.unlink(tmp_path)
                except OSError: pass
            if attempt == 4:
                raise
            time.sleep(0.3)
        except Exception:
            if tmp_path:
                try: os.unlink(tmp_path)
                except OSError: pass
            raise

def save_config(cfg):
    _safe_write(CONFIG_PATH, cfg)

_cfg_cache = {}
def reload_config():
    global _cfg_cache
    _cfg_cache = get_config()

reload_config()

def cfg(key, default=None):
    return _cfg_cache.get(key, default)

# ── Auth ──────────────────────────────────────────────────────────────────────
def get_users():
    return cfg('users', {'admin': hashlib.sha256('sentinel2025'.encode()).hexdigest()})

def get_roles():
    return cfg('roles', {'admin': 'admin'})

def _check_session_timeout():
    """Return True if the session has timed out (and clears it). False otherwise."""
    last = session.get('_last_active')
    if last:
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(last)).total_seconds() / 60
        except (ValueError, TypeError):
            elapsed = SESSION_TIMEOUT_MINUTES + 1  # treat corrupt timestamp as expired
        if elapsed > SESSION_TIMEOUT_MINUTES:
            session.clear()
            return True
    session['_last_active'] = datetime.now().isoformat()
    return False

def _is_user_disabled():
    """Return True if the current session user is in the disabled_users list."""
    return session.get('user', '') in get_config().get('disabled_users', [])

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if _check_session_timeout():
            flash(t('flash session expired'), 'error')
            return redirect(url_for('login'))
        if _is_user_disabled():
            session.clear()
            flash(t('flash account disabled'), 'error')
            return redirect(url_for('login'))
        # Refresh role from config on every request so role changes take effect
        # without requiring re-login (prevents stale elevated-role bypass)
        session['role'] = get_roles().get(session.get('user', ''), 'analyst')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if _check_session_timeout():
            flash(t('flash session expired'), 'error')
            return redirect(url_for('login'))
        if _is_user_disabled():
            session.clear()
            flash(t('flash account disabled'), 'error')
            return redirect(url_for('login'))
        roles = get_roles()
        live_role = roles.get(session['user'], 'analyst')
        session['role'] = live_role
        if live_role != 'admin':
            flash(t('flash admin required'), 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def cc_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if _check_session_timeout():
            flash(t('flash session expired'), 'error')
            return redirect(url_for('login'))
        if _is_user_disabled():
            session.clear()
            flash(t('flash account disabled'), 'error')
            return redirect(url_for('login'))
        roles = get_roles()
        live_role = roles.get(session['user'], 'analyst')
        session['role'] = live_role
        if live_role not in ('admin', 'cc_admin'):
            flash(t('flash cc admin required'), 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ── CSRF Protection ───────────────────────────────────────────────────────────
import secrets as _secrets

def _csrf_token():
    """Return the per-session CSRF token, generating one if missing."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = _secrets.token_hex(32)
    return session['_csrf_token']

# Expose to all templates
app.jinja_env.globals['csrf_token'] = _csrf_token

# Routes that don't need CSRF (GET-only flows or API-key-authenticated JSON endpoints)
_CSRF_EXEMPT = {
    'login', 'logout', 'two_fa_verify', 'static',
    'api_predict', 'scan_stream',
}

@app.after_request
def _security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('X-XSS-Protection', '1; mode=block')
    return response

@app.before_request
def _csrf_protect():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    endpoint = request.endpoint or ''
    if endpoint in _CSRF_EXEMPT:
        return
    token = (request.form.get('_csrf_token')
             or request.headers.get('X-CSRF-Token', ''))
    expected = session.get('_csrf_token', '')
    if not expected or not _secrets.compare_digest(token, expected):
        return jsonify(error=t('csrf failed')), 403

# ── i18n ──────────────────────────────────────────────────────────────────────
TRANSLATIONS = {
    'en': {
        # Navigation
        'Dashboard': 'Dashboard', 'New Scan': 'New Scan',
        'Scan History': 'Scan History', 'Watchlist': 'Watchlist', 'Compare Scans': 'Compare Scans',
        'Model': 'Model', 'Admin': 'Admin', 'Settings': 'Settings', 'Logout': 'Logout',
        'API Status': 'API Status', 'Analysis': 'Analysis', 'System': 'System', 'Main': 'Main',
        'Model Online': 'Model Online', 'Model Offline': 'Model Offline',
        # Dashboard
        'Security Operations Center': 'Security Operations Center',
        'Real-time threat intelligence': 'Real-time threat intelligence & network flow analysis',
        'IP Map': 'IP Map', 'Activity': 'Activity', 'PDF': 'PDF',
        'Total Scans': 'Total Scans', 'Flows Analyzed': 'Flows Analyzed',
        'Threats Detected': 'Threats Detected', 'Detection Rate': 'Detection Rate',
        'Threat Level': 'Threat Level', 'Overall posture': 'Overall posture',
        'No active threats detected': 'No active threats detected',
        'Recurring Attackers': 'Recurring Attackers', 'IPs seen in 2+ scans': 'IPs seen in 2+ scans',
        'IP Address': 'IP Address', 'Scan Count': 'Scan Count', 'Total Hits': 'Total Hits',
        'Watch': 'Watch', 'No recurring attackers': 'No recurring attackers detected yet',
        'Severity Distribution': 'Severity Distribution', 'Attack Type Breakdown': 'Attack Type Breakdown',
        'No scan data yet': 'No scan data yet', 'Run First Scan': 'Run First Scan',
        'No threat data yet': 'No threat data yet',
        'Scan Activity Timeline': 'Scan Activity Timeline', 'Last 20 scans': 'Last 20 scans',
        'Run scans to see activity': 'Run scans to see activity over time',
        'Attack Origin Map': 'Attack Origin Map', 'Country distribution': 'Country distribution',
        'Loading map': 'Loading map…', 'Threat Trend': 'Threat Trend',
        'Recent Scans': 'Recent Scans', 'No scans yet': 'No scans yet',
        # Scan page
        'Network Flow Analysis': 'Network Flow Analysis',
        'Upload subtitle': 'Upload a CIC-IDS2017 CSV or PCAP capture file to classify network traffic with the ML model',
        'Upload Traffic Capture': 'Upload Traffic Capture',
        'Model Ready': 'Model Ready', 'Single File': 'Single File', 'Multiple Files': 'Multiple Files',
        'Drop your file here': 'Drop your file here', 'or click to browse': 'or click to browse your files',
        'Expected Format': 'Expected Format', 'Attack Classes': 'Attack Classes',
        'How Scan Works': 'How Scan Works',
        'scan step 1': '1. Upload a CSV or PCAP file containing network traffic flows.',
        'scan step 2': '2. The system extracts and normalizes the required features.',
        'scan step 3': '3. The ML model classifies each flow as Benign or an attack type.',
        'scan step 4': '4. Results are displayed with threat labels, confidence scores, and source IPs.',
        'Model Performance': 'Model Performance', 'Analyze Flows': 'Analyze Flows',
        'Clear': 'Clear', 'Analyze All Files': 'Analyze All Files',
        'Select multiple files': 'Select multiple files',
        'INITIALIZING SCAN': 'INITIALIZING SCAN...', 'LOADING MODELS': 'LOADING MODELS...', 'ANALYZING FLOWS': 'ANALYZING FLOWS...', 'CLASSIFYING THREATS': 'CLASSIFYING THREATS...',
        'only CSV accepted': 'Only CSV, PCAP, or PCAPNG files are accepted.', 'select CSV first': 'Please select a CSV file first.',
        'Processing flows': 'Processing network flows — please wait',
        # History
        'scans recorded': 'scans recorded', 'Search scans': 'Search scans...',
        'Flows': 'Flows', 'Threats': 'Threats', 'Confidence': 'Confidence',
        'No scans on record': 'No scans on record yet.',
        # Result page
        'Total Flows': 'Total Flows', 'Malicious': 'Malicious', 'Benign': 'Benign',
        'Avg Confidence': 'Avg Confidence', 'View Map': 'View Map', 'Explain': 'Explain',
        'PDF Report': 'PDF Report', 'Export CEF': 'Export CEF',
        'Correlation': 'Correlation', 'Export CSV': 'Export CSV',
        'PDF + CSV Report': 'PDF + CSV Report', 'Raw Flows CSV': 'Raw Flows CSV',
        'PDF + CSV': 'PDF + CSV',
        # Settings
        'Settings subtitle': 'SMTP alerts, webhook, AbuseIPDB, VirusTotal & Shodan configuration (admin only)',
        'Email Alerts (SMTP)': 'Email Alerts (SMTP)', 'Test Email': 'Test Email',
        'SMTP Host': 'SMTP Host', 'SMTP Port': 'SMTP Port',
        'SMTP User / From': 'SMTP User / From', 'SMTP Password': 'SMTP Password',
        'Alert Recipient': 'Alert Recipient (To)',
        'Webhook Alerts': 'Webhook Alerts', 'Test Webhook': 'Test Webhook', 'Webhook URL': 'Webhook URL',
        'IP Reputation': 'IP Reputation (AbuseIPDB)', 'AbuseIPDB API Key': 'AbuseIPDB API Key',
        'VirusTotal Lookup': 'VirusTotal IP Lookup', 'VirusTotal API Key': 'VirusTotal API Key',
        'Shodan Host Intel': 'Shodan Host Intel', 'Shodan API Key': 'Shodan API Key',
        'Key configured': 'Key configured', 'Alert Triggers': 'Alert Triggers',
        'Alert on CRITICAL': 'Alert on CRITICAL threats',
        'CRITICAL alert desc': 'Send email/webhook when CRITICAL severity flows are detected',
        'Alert on HIGH': 'Alert on HIGH threats',
        'HIGH alert desc': 'Send email/webhook when HIGH severity flows are detected',
        'Save Settings': 'Save Settings', 'Leave blank': 'Leave blank to keep existing',
        'Sending': 'Sending…',
        # Admin
        'Admin subtitle': 'User management and system overview',
        'Model Status': 'Model Status', 'Config': 'Config', 'Watchlist IPs': 'Watchlist IPs',
        'Users': 'Users', 'Username': 'Username', 'Role': 'Role', 'Status': 'Status',
        'Last Login': 'Last Login', 'Actions': 'Actions',
        'Set': 'Set', 'Enable': 'Enable', 'Disable': 'Disable', 'Remove': 'Remove',
        'Add New User': 'Add New User', 'Password': 'Password',
        'Assign to CC Admin': 'Assign to CC Admin', 'Add User': 'Add User',
        'CC Admin Overview': 'CC Admin Overview',
        'CC Admin Overview subtitle': 'Analysts managed by each CC Admin',
        'analyst(s)': 'analyst(s)', 'Analyst': 'Analyst', 'Promote': 'Promote', 'Move': 'Move',
        'No analysts assigned': 'No analysts assigned yet.',
        'View analyst activity': 'View analyst activity',
        'events': 'events', 'LOGIN': 'LOGIN', 'LOGOUT': 'LOGOUT',
        'Never': 'Never', 'you': 'you',
        # Table columns / common labels
        'Filename': 'Filename', 'Timestamp': 'Timestamp', 'Time': 'Time', 'Top Severity': 'Top Severity',
        'View': 'View', 'View All': 'View All', 'Week': 'Week', 'Month': 'Month',
        'Attack Frequency Heatmap': 'Attack Frequency Heatmap', 'Day x Hour': 'Day × Hour',
        'Less': 'Less', 'More': 'More',
        'No scans yet start': 'No scans yet. Upload a CSV to get started.',
        'Start First Scan': 'Start First Scan',
        'Model not loaded': 'Model not loaded',
        # Nav items (base.html)
        'Correlation nav': 'Correlation', 'IP Map nav': 'IP Map', 'Threat Hunt': 'Threat Hunt',
        'Timeline': 'Timeline', 'Cases': 'Cases', 'Alert Rules': 'Alert Rules',
        'Schedules': 'Schedules', 'Audit Log': 'Audit Log', 'Activity Log': 'Activity Log',
        'Export Dashboard PDF': 'Export Dashboard PDF', 'FP Feedback': 'FP Feedback',
        'IP Whitelist': 'IP Whitelist', 'Change Password': 'Password', 'CC Admin': 'CC Admin',
        '2FA Setup': '2FA Setup', 'Back': 'Back', 'Scan Detail': 'Scan Detail',
        # Result page
        'THREAT LEVEL': 'THREAT LEVEL', 'No Threats Detected': 'No Threats Detected',
        'Low-Level Threats': 'Low-Level Threats Detected',
        'Significant Threats': 'Significant Threats Detected',
        'Critical Threats': 'Critical Threats Detected — Immediate Action Required',
        'Scan ID': 'Scan ID', 'Alert sent': 'Alert sent via email/webhook for detected threats.',
        'Traffic Split': 'Traffic Split', 'Severity Breakdown': 'Severity Breakdown',
        'Threat Timeline': 'Threat Timeline', 'No threat data': 'No threat data',
        'Threat Distribution Chart': 'Threat Distribution Chart',
        'Attack Types': 'Attack Types', 'Click to inspect flows': 'Click to inspect flows',
        'No malicious flows': 'No malicious flows detected',
        'Flow-Level Results': 'Flow-Level Results', 'Search flows': 'Search flows...',
        'Columns': 'Columns', 'FILTER': 'FILTER',
        'All': 'All', 'Critical': 'Critical', 'High': 'High', 'Medium': 'Medium', 'Safe': 'Safe',
        'Classification': 'Classification', 'Src IP': 'Src IP', 'Src Port': 'Src Port',
        'Dst IP': 'Dst IP', 'Dst Port': 'Dst Port', 'Proto': 'Proto',
        'Severity': 'Severity', 'Triage': 'Triage',
        'THREAT': 'THREAT', 'SAFE status': 'SAFE',
        'Investigated': 'Investigated', 'FP': 'FP', 'Confirmed': 'Confirmed',
        'Flow ID': 'Flow ID', 'Anomaly Score': 'Anomaly Score', 'Protocol': 'Protocol',
        'Watchlist Hit': 'Watchlist Hit', 'Yes': 'Yes', 'No': 'No',
        'Lookup WHOIS': 'Lookup WHOIS',
        'Showing first 2000': 'Showing first 2,000 flows. Download CSV for full results.',
        'selected': 'selected', 'Mark Investigated': 'Mark Investigated',
        'Mark False Positive': 'Mark False Positive', 'Mark Confirmed': 'Mark Confirmed',
        'Add to Case': 'Add to Case', 'Cancel': 'Cancel',
        'Add Selected Flows to Case': 'Add Selected Flows to Case',
        'Case ID': 'Case ID', 'Re-scan': 'Re-scan', 'Network Graph': 'Network Graph',
        'threats in': 'threats in', 'analyzed flows': 'analyzed flows',
        'View Full Result': 'View Full Result', 'HIGH SEVERITY': 'HIGH SEVERITY',
        # Common
        'Online': 'Online', 'Offline': 'Offline', 'ACTIVE': 'ACTIVE', 'DISABLED': 'DISABLED',
        # Compare select
        'Compare subtitle': 'Select 2 to 5 scans to compare side-by-side',
        'Select Scans': 'Select Scans', 'Add Scan': 'Add Scan', 'Remove Last': 'Remove Last',
        'Compare btn': 'Compare', 'Need 2 scans': 'You need at least 2 scans in history to compare.',
        'Run a scan': 'Run a scan', 'scans selected': 'scans selected',
        # Compare results
        'Scan Comparison': 'Scan Comparison', 'scans compared': 'scans compared',
        'New Comparison': 'New Comparison', 'Metric Comparison': 'Metric Comparison',
        'Best': 'Best', 'Worst': 'Worst', 'Metric': 'Metric',
        'Malicious Flows': 'Malicious Flows', 'Benign Flows': 'Benign Flows',
        'Avg Confidence %': 'Avg Confidence %', 'No threats': 'No threats',
        # CC Admin page
        'CC Admin Panel title': 'CC Admin Panel',
        'CC Admin page subtitle': 'Manage analyst accounts and monitor activity',
        'Analysts': 'Analysts', 'Add New Analyst': 'Add New Analyst',
        'Add Analyst': 'Add Analyst', 'Analyst Activity Log': 'Analyst Activity Log',
        'Login Logout events': 'Login / Logout events — last 200',
        'Detail': 'Detail', 'No analysts yet': 'No analysts yet.',
        'No login events': 'No login/logout events recorded yet for your analysts.',
        'analyst only note': 'You can only create analyst accounts.',
        # Audit log
        'Analyst Audit Log': 'Analyst Audit Log', 'Search log': 'Search log...',
        'User': 'User', 'Action': 'Action', 'No audit entries': 'No audit entries yet',
        # Model page
        'Model subtitle': 'XGBoost-based IDS model — training report and retrain controls',
        'Reload Models': 'Reload Models', 'Start Retrain': 'Start Retrain',
        'Retraining': 'Retraining…', 'Best Model': 'Best Model', 'Test Accuracy': 'Test Accuracy',
        'Training Report': 'Training Report', 'training report source': 'From outputs/training_report.txt',
        'Live Retrain Log': 'Live Retrain Log',
        'Running': 'Running…', 'Completed': 'Completed',
        'Retrain confirm': 'This will start retraining all models from scratch. This may take a long time. Continue?',
        'retrain already running': 'Retrain already running',
        # Watchlist
        'Watchlist subtitle': 'Monitor specific IPs and subnets across all scans',
        'Import CSV': 'Import CSV', 'Sample CSV': 'Sample CSV', 'Add IP': 'Add IP',
        'Monitored IPs': 'Monitored IPs / Subnets', 'IP / CIDR': 'IP / CIDR',
        'Note': 'Note', 'Added': 'Added', 'Expires': 'Expires',
        'Last Seen': 'Last Seen', 'Hits': 'Hits', 'Rep': 'Rep', 'Alert': 'Alert',
        'Scans btn': 'Scans', 'Edit': 'Edit', 'No IPs in watchlist': 'No IPs in watchlist yet.',
        'Add First IP': 'Add First IP', 'Add IP to Watchlist': 'Add IP to Watchlist',
        'IP Address or CIDR': 'IP Address or CIDR *', 'Note optional': 'Note (optional)',
        'Expires At': 'Expires At (optional)', 'Send alert when detected': 'Send alert when detected',
        'Send alert when this IP': 'Send alert when this IP is detected',
        'Add to Watchlist btn': 'Add to Watchlist', 'Edit Watchlist Entry': 'Edit Watchlist Entry',
        'Save Changes': 'Save Changes', 'Import IPs from CSV': 'Import IPs from CSV',
        'CSV File': 'CSV File *', 'Import': 'Import', 'Search IP or note': 'Search IP or note…',
        # Attack detail
        'Attack Detail title': 'Attack Detail', 'Back to Scan': '← Back to Scan',
        'Add to Watchlist': 'Add to Watchlist', 'Threat Intelligence': 'Threat Intelligence',
        'Detected Flows': 'Detected Flows', 'Of Total Traffic': 'Of Total Traffic',
        'Total Flows in Scan': 'Total Flows in Scan', 'Protocol Breakdown': 'Protocol Breakdown',
        'About This Attack': 'About This Attack', 'Why model flagged': 'Why did the model flag this?',
        'Technique ID': 'Technique ID', 'Technique Name': 'Technique Name', 'Tactic': 'Tactic',
        'Response Playbook': 'Response Playbook',
        'playbook hint': '— click to view incident response steps',
        'Network Flows table': 'Network Flows', 'Filter flows': 'Filter flows…',
        'Source IP': 'Source IP', 'Destination IP': 'Destination IP',
        'Inv': 'Inv', 'Conf': 'Conf', 'No flows found': 'No flows found for this attack type.',
        'Select IPs to add': 'Select IPs to add from this attack:', 'Add Selected': 'Add Selected',
        'WHOIS btn': 'WHOIS',
        # Threat Hunt
        'Threat Hunting': 'Threat Hunting', 'Hunt subtitle': 'Search across all historical scan data',
        'Hunt Query': 'Hunt Query', 'Attack Type': 'Attack Type',
        'Date From': 'Date From', 'Date To': 'Date To',
        'Min Confidence (%)': 'Min Confidence (%)', 'Hunt btn': 'Hunt',
        'Results': 'Results', 'No results': 'No results',
        'matches': 'matches', 'page': 'page', 'File col': 'File',
        'Prev': '‹ Prev', 'Next': 'Next ›', 'No flows matched': 'No flows matched your query.',
        # Notifications
        'Alert Notifications': 'Alert Notifications', 'unread': 'unread',
        'Mark All Read': 'Mark All Read', 'Mark Read': 'Mark Read', 'Delete': 'Delete',
        'View Scan': 'View Scan', 'View Case': 'View Case', 'No notifications': 'No notifications yet',
        'Notifs appear when': 'Notifications appear when scans detect threats',
        # Cases
        'Case Management': 'Case Management', 'cases': 'cases', 'open': 'open',
        'New Case': 'New Case', 'No cases yet': 'No cases yet',
        'Create First Case': 'Create First Case', 'New Investigation Case': 'New Investigation Case',
        'Case Title': 'Case Title *', 'Description': 'Description',
        'Priority': 'Priority', 'Assign To': 'Assign To',
        'Link Scan ID': 'Link Scan ID (optional)', 'SLA Hours': 'SLA Hours (default: 24)',
        'Create Case': 'Create Case', 'Assigned': 'Assigned:', 'Created at': 'Created:',
        'comments': 'comments', 'Open time': 'Open:', 'SLA label': 'SLA',
        'OVERDUE': 'OVERDUE', 'SLA WARNING': 'SLA WARNING', 'ON TRACK': 'ON TRACK',
        'Overdue Cases': 'Overdue Cases', 'overdue cases': 'overdue cases', 'All Cases': 'All Cases',
        'Assignees': 'Assignees', 'Assign To (multiple)': 'Assign To', 'Assigned to': 'Assigned to',
        'Open Cases': 'Open Cases', 'Closed Cases': 'Closed Cases',
        'closed': 'closed', 'No closed cases': 'No closed cases yet.',
        'No open cases': 'No open cases.', 'No results match': 'No cases match your search.',
        'Search cases label': 'Search cases…',
        # History detail
        'Detected Attack Types': 'Detected Attack Types', 'Flow Details': 'Flow Details',
        'Filter flows td': 'Filter flows...',
        # Change password
        'Change Password title': 'Change Password', 'Update password subtitle': 'Update your account password',
        'Password Update': 'Password Update', 'Current Password': 'Current Password',
        'New Password label': 'New Password', 'Confirm New Password': 'Confirm New Password',
        'Update Password': 'Update Password',
        'pw match': 'Passwords match', 'pw no match': 'Passwords do not match',
        'pw weak': 'Weak', 'pw fair': 'Fair', 'pw good': 'Good', 'pw strong': 'Strong', 'pw very strong': 'Very Strong',
        # FP Feedback
        'False Positive Feedback': 'False Positive Feedback',
        'FP subtitle': 'Analyst-reported false positives grouped by label — useful for model retraining',
        'No FP records': 'No false positive feedback records yet.',
        'FP records note': 'FP records are created when analysts mark flows as "False Positive" during triage.',
        # IP Whitelist
        'IP Whitelist title': 'IP Whitelist',
        'Whitelist subtitle': 'Whitelisted IPs and CIDR ranges are suppressed from threat flagging and alerts',
        'Whitelist Entries': 'Whitelist Entries', 'Added By': 'Added By', 'Added At': 'Added At',
        'No whitelisted IPs': 'No whitelisted IPs yet.', 'Add Whitelist Entry': 'Add Whitelist Entry',
        'IP Address or CIDR add': 'IP Address or CIDR *', 'Add btn': 'Add',
        # Login
        'Username label': 'Username', 'Password label': 'Password', 'AUTHENTICATE': 'AUTHENTICATE',
        'System Operational': 'System Operational',
        # Activity Log
        'Activity Log title': 'Activity Log',
        'All system events': 'All system events', 'entries': 'entries',
        'Back to Dashboard': '← Back to Dashboard',
        'Scans Completed': 'Scans Completed', 'Login Events': 'Login Events',
        'Triage Actions': 'Triage Actions', 'Total Events': 'Total Events',
        'All Events': 'All Events',
        'All Actions': 'All Actions', 'Logins filter': 'Logins',
        'Triage filter': 'Triage', 'Alerts filter': 'Alerts', 'Settings filter': 'Settings',
        'No activity recorded': 'No activity recorded yet.',
        'Activity empty note': 'Activity is logged when you run scans, log in, or perform triage actions.',
        'Run First Scan': 'Run First Scan',
        # API Status
        'API Status title': 'API & Service Status', 'Last checked:': 'Last checked:',
        'Refresh': 'Refresh', 'Reset': 'Reset', 'Online stat': 'Online', 'services healthy': 'services healthy',
        'Warnings stat': 'Warnings', 'not configured': 'not configured',
        'Errors stat': 'Errors', 'connection failed': 'connection failed',
        'Total stat': 'Total', 'services checked': 'services checked',
        'Configure': 'Configure',
        # Case Detail
        'Cases breadcrumb': 'Cases', 'Analyst:': 'Analyst:', 'Assigned:': 'Assigned:',
        'by': 'by',
        'Appointed by': 'Appointed by',
        'Case ID:': 'Case ID:', 'Created:': 'Created:', 'comments suffix': 'comments',
        'Back to Cases': '← Back to Cases', 'Export PDF': 'Export PDF', 'Close Case': 'Close Case',
        'Attachments': 'Attachments', 'Any file type allowed': 'Any file type — multiple files allowed',
        'Attachment types hint': 'PDF, TXT, LOG, CSV, JSON, images, Office docs, ZIP, PCAP — multiple files allowed',
        'No attachments yet': 'No attachments yet.',
        'Add Attachments label': 'Add Attachments', 'Upload btn': 'Upload', 'Download btn': 'Download',
        'Attach File label': 'Attach File', 'optional any type': '(optional, any type)',
        'files suffix': 'file(s)',
        'analyst close btn': 'Mark Done & Submit for Review',
        'analyst close confirm': 'Submit this case for CC Admin review?',
        'cc close btn': 'Close After Review',
        'cc close confirm': 'Close this case after review and notify Admin?',
        'permanently close btn': 'Permanently Close',
        'Assignment Priority': 'Assignment & Priority', 'Update btn': 'Update',
        'Priority:': 'Priority:', 'Assigned inline': 'Assigned:',
        'Linked Scans': 'Linked Scans', 'scans suffix': 'scans',
        'File th': 'File', 'Threats th': 'Threats', 'View btn': 'View',
        'Investigation Comments': 'Investigation Comments',
        'No comments yet': 'No comments yet. Add the first comment below.',
        'Add Comment label': 'Add Comment', 'Add Comment btn': 'Add Comment',
        'Add Comment placeholder': 'Investigation findings, actions taken…',
        'Case closed note': 'This case is closed. No new comments can be added.',
        # Case Archive & Return flow
        'Case Archive': 'Case Archive', 'Archive': 'Archive', 'View Archive': 'View Archive',
        'Yearly Cases': 'Yearly Cases', 'Monthly Cases': 'Monthly Cases',
        'No archived cases': 'No archived cases yet.', 'archived cases': 'archived cases',
        'years': 'year(s)', 'month': 'month', 'months': 'months',
        'Closed cases from previous months are automatically archived here.': 'Closed cases from previous months are automatically archived here.',
        'Closed:': 'Closed:', 'CLOSED': 'CLOSED',
        'Return to Analyst': 'Return to Analyst',
        'return analyst confirm': 'Return this case to the analyst for further work?',
        'Return to CC Admin': 'Return to CC Admin',
        'return cc confirm': 'Return this case to CC Admin for re-review?',
        'flash case returned analyst': 'Case returned to analyst for further work.',
        'flash case returned cc': 'Case returned to CC Admin for re-review.',
        'delete comment confirm': 'Delete this comment permanently?',
        'flash comment deleted': 'Comment deleted.',
        'RETURNED badge': 'RETURNED',
        'Returned by notice': 'Returned by',
        'for further work notice': 'for further work',
        'for re-review notice': 'for re-review',
        # Alert Rules
        'Name th': 'Name', 'Created': 'Created', 'Enabled': 'Enabled', 'Disabled': 'Disabled',
        'Alert Rules title': 'Alert Rules',
        'Alert Rules subtitle': 'Trigger email or webhook alerts based on scan conditions',
        'New Rule': 'New Rule',
        'Rules card': 'Rules', 'Condition th': 'Condition',
        'No alert rules': 'No alert rules defined.', 'Create First Rule': 'Create First Rule',
        'Condition Syntax': 'Condition Syntax', 'New Alert Rule': 'New Alert Rule',
        'Rule Name label': 'Rule Name *', 'Condition label': 'Condition *',
        'Action select': 'Action', 'Email option': 'Email', 'Webhook option': 'Webhook',
        'Both option': 'Both', 'Enable immediately': 'Enable immediately',
        'Create Rule btn': 'Create Rule',
        # Scheduled Scans
        'Scheduled Scans title': 'Scheduled Scans',
        'Schedules subtitle': 'Automatically run scans at specified times',
        'New Schedule': 'New Schedule', 'Schedules card': 'Schedules',
        'Time HH MM': 'Time (HH:MM)', 'File Path th': 'File Path',
        'Last Run': 'Last Run',
        'No schedules': 'No schedules configured.', 'Create First Schedule': 'Create First Schedule',
        'Schedule Name label': 'Schedule Name *', 'Time HH MM label': 'Time (HH:MM, 24h) *',
        'File Path label': 'File Path (absolute path to CSV)',
        'Create Schedule btn': 'Create Schedule',
        # Scan Queue
        'Scan Queue title': 'Scan Queue', 'files processing': 'file(s) — processing one by one',
        # Attack Timeline
        'Attack Timeline title': 'Attack Timeline',
        'Timeline subtitle': 'Chronological view of all detected threats across scans',
        'Threat Event Scatter': 'Threat Event Scatter',
        'All Events tl': 'All Events', 'Count th': 'Count', 'Scan th': 'Scan',
        'No attack events': 'No attack events found. Run some scans first.',
        # SHAP
        'SHAP title': 'Model Explainability (SHAP)',
        'Top 10 Features': 'Top 10 Feature Importances',
        'Computing SHAP': 'Computing SHAP values…',
        'Feature Importance Table': 'Feature Importance Table',
        'Feature th': 'Feature', 'Mean SHAP Value': 'Mean |SHAP| Value',
        'Relative Importance': 'Relative Importance',
        # Correlation
        'Correlation title': 'Attack Correlation by Source IP',
        'Correlation note prefix': 'Correlation — scan',
        'Correlated attacker prefix': 'Correlated attacker —',
        'Threat Actors': 'Threat Actors', 'Threat Score formula': 'Threat Score = Flow Count × Severity Rank',
        'Attack Types th': 'Attack Types', 'Flow Count th': 'Flow Count',
        'Max Severity': 'Max Severity', 'Threat Score': 'Threat Score',
        'Watch btn': '🎯 Watch', 'No malicious correlation': 'No malicious flows found in this scan.',
        # Playbooks
        'Playbooks title': 'Incident Response Playbooks',
        'Playbooks subtitle': 'Step-by-step response procedures for each attack type',
        # Scan Live
        'Live Classification title': 'Live Flow Classification',
        'Processed stat': 'Processed', 'Total live stat': 'Total',
        'Threats live stat': 'Threats', 'Benign live stat': 'Benign', 'Phase stat': 'Phase',
        'Pause btn': 'Pause', 'Resume btn': 'Resume', 'Restart btn': 'Restart',
        'Load step': 'Load', 'Features step': 'Features', 'Classify step': 'Classify',
        'Save step': 'Save', 'Speed label': 'Speed',
        'Live Flow Feed': 'Live Flow Feed', 'rows suffix': 'rows',
        'Threats only': 'Threats only', 'Clear btn': 'Clear',
        'Status th': 'Status', 'Waiting classification': 'Waiting for classification results…',
        'Streaming': 'Streaming…', 'Showing last flows': 'Showing last',
        # 2FA Setup
        '2FA title': 'Two-Factor Authentication',
        '2FA subtitle': 'Add an extra layer of security to your account',
        '2FA Enabled card': '2FA Enabled',
        '2FA enabled msg': 'Two-factor authentication is currently enabled on your account.',
        '2FA disable hint': 'You can disable 2FA below. You will need to re-enable it if you want to secure your account again.',
        '2FA disable code hint': 'Enter the code from your authenticator app to confirm',
        'Disable 2FA': 'Disable 2FA',
        'Scan QR Code': 'Scan QR Code',
        'TOTP scan hint': 'Scan with Google Authenticator, Authy, or any TOTP app',
        'Manual secret key': 'Manual secret key:',
        'Verify Enable': 'Verify & Enable',
        '2FA verify hint': 'After scanning the QR code, enter the 6-digit code from your authenticator app to enable 2FA.',
        '6-Digit Code label': '6-Digit Code *', 'Enable 2FA': 'Enable 2FA',
        # 2FA Verify
        '2FA Verification': 'Two-Factor Verification',
        '2FA verify code hint': 'Enter the 6-digit code from your authenticator app to continue.',
        'Verification Code': 'Verification Code', 'Verify btn': 'Verify',
        'Cancel Logout': 'Cancel / Logout',
        # Global Correlation page
        'Global Attack Correlation': 'Global Attack Correlation',
        'unique sources': 'unique sources',
        'Search IP corr': 'Search IP…',
        'Scans Seen': 'Scans Seen',
        'more': 'more',
        'No cross-scan correlations': 'No cross-scan attack correlations found yet.',
        'Run Scans': 'Run Scans',
        # Network Graph page
        'Unique IPs': 'Unique IPs', 'Connections': 'Connections',
        'Attackers': 'Attackers', 'Victims': 'Victims',
        'NODE:': 'NODE:', 'Attacker src': 'Attacker (src)',
        'Victim dst': 'Victim (dst)', 'Both node': 'Both', 'EDGE:': 'EDGE:',
        'Force-Directed IP Topology': 'Force-Directed IP Topology',
        'Building graph': 'Building graph…',
        'No IP connections': 'No IP connections to display',
        'No IP connections hint': 'This scan has no src/dst IP columns or all IPs are private',
        'Role:': 'Role:', 'Attacks:': 'Attacks:',
        # Geo / Dashboard Map pages
        'IP Geolocation Map': 'IP Geolocation Map',
        'Global Threat Distribution': 'Global Threat Distribution',
        'IP List': 'IP List', 'Loading geo data': 'Loading geolocation data…',
        'Lat / Lon': 'Lat / Lon', 'Country': 'Country',
        'Country:': 'Country:', 'Flows:': 'Flows:', 'Status:': 'Status:',
        'MALICIOUS': 'MALICIOUS', 'BENIGN badge': 'BENIGN',
        'auto rotate btn': 'AUTO-ROTATE',
        'globe load failed': '⚠ Failed to load map — check internet connection.',
        'NEW badge': 'NEW',
        'Global IP Geolocation Map': 'Global IP Geolocation Map',
        'dashboard map subtitle': 'Aggregated IPs across all scans — public IPs plotted, all IPs listed below',
        'Public IP Map': 'Public IP Map', 'Loading': 'Loading…',
        'All Attack IPs': 'All Attack IPs', 'Filter IPs': 'Filter IPs…',
        'Malicious only': 'Malicious only', 'Type': 'Type', 'Attack Labels': 'Attack Labels',
        'Malicious IPs': 'Malicious IPs', 'Private IPs': 'Private IPs',
        'No public IPs msg': 'No public IPs to plot — dataset uses private IPs (see table below)',
        'public IPs plotted': 'public IPs plotted',
        'No IP data found': 'No IP data found. Run a scan first.',
        'Failed to load': 'Failed to load',
        # Scan Live page
        'RUNNING badge': 'RUNNING', 'PAUSED badge': 'PAUSED',
        'COMPLETE badge': 'COMPLETE', 'ERROR badge': 'ERROR',
        'INITIALIZING': 'INITIALIZING…', 'Streaming': 'Streaming…', 'Paused': 'Paused',
        'rows': 'rows', 'Showing last 500': 'Showing last 500 flows',
        'THREAT badge': '⚠ THREAT', 'SAFE badge': '✓ SAFE',
        'Complete finished in': 'Complete — finished in', 'redirecting': 'redirecting…',
        # Scan Queue page
        'Queued badge': 'Queued', 'Waiting': 'Waiting…', 'Scanning': 'Scanning…',
        'Done': 'Done', 'View Results': 'View Results →',
        # History Detail / Attack Detail / SHAP
        'SEVERITY': 'SEVERITY', 'SEVERITY ATTACK': 'SEVERITY ATTACK',
        'What is': 'What is',
        'Enter IP to query': 'Enter an IP address and click a provider to query.',
        'SHAP subtitle': 'Top feature importances for malicious flows (XGBoost)',
        'SHAP how to read': 'How to read this:',
        'SHAP explanation': 'SHAP (SHapley Additive exPlanations) values measure each feature\'s contribution to the model\'s predictions. Higher values indicate features that had more influence on classifying flows as malicious. Computed on the first 50 malicious flows using the XGBoost TreeExplainer.',
        'No mal flows scan': 'No malicious flows in this scan.',
        'features shown': 'features shown',
        # Capture
        'Capturing': 'Capturing…', 'Stopped': 'Stopped',
        'Low': 'Low', 'Scan label': 'Scan', 'Select scan': '— Select scan —', 'threats count': 'threats',
        # Topbar titles
        'Case Detail title': 'Case Detail', 'Scan Result': 'Scan Result',
        'Live Analysis title': 'Live Analysis', 'Bucket': 'Bucket',
        # Help texts
        'whitelist IP hint': 'Supports exact IPs (192.168.1.1) and CIDR notation (10.0.0.0/8). Whitelisted IPs will be marked BENIGN during scans.',
        'schedule how it works': 'How it works: The scheduler checks every minute. Set the time in HH:MM format (24h). The file path should be an absolute path to a CSV file on the server. Scans run automatically in the background and results appear in Scan History.',
        'password help text': 'After changing your password, you will remain logged in. Choose a strong password with at least 8 characters mixing letters, numbers, and symbols.',
        'scan column help': 'Column names are auto-matched — extra columns are ignored, missing features default to 0.',
        'condition syntax help': 'Supported conditions: attack_count > N from same IP in 5min — fire when an IP sends more than N malicious flows in a 5-minute window. Adjust the threshold number as needed.',
        'How it works': 'How it works',
        'Supported conditions': 'Supported conditions:',
        'rule fire desc': '— fire when an IP sends more than 100 malicious flows in a 5-minute window',
        'Adjust threshold': 'Adjust the threshold number as needed',
        'alert settings note': 'Email and webhook settings are configured in',
        # JS confirm / alert messages
        'Alert enabled': 'Alert enabled', 'Alert disabled': 'Alert disabled',
        'Re-run confirm': 'Re-run this scan with the original file?',
        'Remove from watchlist confirm': 'Remove {ip} from watchlist?',
        'Permanently remove user': 'Permanently remove {user}?',
        'Promote to CC Admin': 'Promote {user} to CC Admin?',
        'Remove analyst confirm': 'Remove analyst {user}?',
        'Bulk triage error': 'Bulk triage error: ',
        'Please enter Case ID': 'Please enter a Case ID.',
        'Added to case msg': 'Added to case and marked as Investigated.',
        'ERROR prefix': 'ERROR: ',
        'Delete rule confirm': 'Delete rule?',
        'Delete schedule confirm': 'Delete schedule?',
        # Login page
        'Intrusion Detection System': 'Intrusion Detection System',
        'system footer': 'CIC-IDS2017 Dataset · ThresholdClassifier Model',
        'terminal line 1': '> Initializing BASTION...',
        'terminal line 2': '> Loading threat models... [OK]',
        'terminal line 3': '> System ready. Awaiting authentication.',
        # Settings JS
        'Network error': 'Network error',
        'Get API key at': 'Get your API key at',
        'Get free API key at': 'Get your free API key at',
        'free tier checks': '(free tier: 1000 checks/day)',
        'lookups free': '(500 lookups/day free)',
        'free tier available': '(free tier available)',
        # Scan formats
        'Hold Ctrl select': 'Hold Ctrl to select multiple files',
        'file formats supported': '.CSV / .PCAP / .PCAPNG supported',
        'file formats max': '.CSV / .PCAP / .PCAPNG — Max 2 GB',
        'MB selected': 'MB selected',
        # Admin
        'Min 8 characters': 'Min 8 characters',
        'None Unassigned': '— None / Unassigned —',
        # 2FA
        'Disable 2FA confirm': 'Disable 2FA? Your account will be less secure.',
        # Timeline
        'flows label': 'flows',
        # Toast titles
        'toast SUCCESS': 'SUCCESS', 'toast ERROR': 'ERROR', 'toast WARNING': 'WARNING', 'toast INFO': 'INFO',
        # API Status page detail/note strings
        'svc not loaded': 'Not loaded', 'svc not configured': 'Not configured',
        'svc configure settings': 'Configure in Settings',
        'svc connected ip': 'Connected · IP reputation active',
        'svc invalid key': 'Invalid API key (401)',
        'svc connection failed': 'Connection failed',
        'svc unreachable': 'Unreachable',
        'svc model note': 'Loaded from models/best_model.pkl',
        'svc api key not configured': 'API key not configured',
        'svc smtp connected': 'Connected to {host}:{port}',
        'svc smtp alert to': 'Alerts → {email}',
        'svc smtp host': 'Host',
        'svc webhook reachable': 'Reachable',
        'svc storage used': 'used',
        'svc storage free': 'free',
        'svc storage scan files': 'scan files in outputs/flows/',
        'svc could not read': 'Could not read',
        'test email ok': 'Email sent OK',
        'smtp not configured': 'SMTP not configured',
        'webhook responded': 'Webhook responded: {code}',
        'webhook url not configured': 'Webhook URL not configured',
        # Compare
        'SCAN label': 'SCAN',
        # Cases
        'e.g. DDoS Campaign': 'e.g. DDoS Campaign Investigation',
        'Brief description': 'Brief description of the case…',
        'e.g. scan id': 'e.g. 20241201_143022',
        'recurring attacker note': 'Recurring attacker — added from dashboard',
        # JS inline labels — attack_detail / watchlist / capture / shap / case
        'Close case confirm': 'Close this case?',
        'Enter an IP address': 'Enter an IP address',
        'Checking': 'Checking…',
        'Country:': 'Country:',
        'Reports:': 'Reports:',
        'Last reported:': 'Last reported:',
        'Reputation:': 'Reputation:',
        'City:': 'City:',
        'ISP:': 'ISP:',
        'Malicious:': 'Malicious:',
        'Suspicious:': 'Suspicious:',
        'Harmless:': 'Harmless:',
        'AS Owner:': 'AS Owner:',
        'Org:': 'Org:',
        'Open Ports:': 'Open Ports:',
        'Hostnames:': 'Hostnames:',
        'CVEs:': 'CVEs:',
        'Private IP badge': 'PRIVATE IP',
        'N/A rep': 'N/A', 'UTC label': 'UTC',
        'Error: prefix': 'Error: ',
        'Network error prefix': 'Network error: ',
        # API provider messages
        'AbuseIPDB not configured': '⚠ AbuseIPDB API key not set — go to <a href="/settings" style="color:var(--cyan)">Settings</a> to configure it.',
        'VT not configured': '⚠ VirusTotal API key not set — go to <a href="/settings" style="color:var(--cyan)">Settings</a> to configure it.',
        'Shodan not configured': '⚠ Shodan API key not set — go to <a href="/settings" style="color:var(--cyan)">Settings</a> to configure it.',
        'private IP query note': 'Private/reserved IP — not queryable via this service.',
        'Request failed': 'Request failed',
        'VT error prefix': 'VT Error: ',
        'Shodan error prefix': 'Shodan: ',
        'Querying VirusTotal': 'Querying VirusTotal…',
        'Querying Shodan': 'Querying Shodan…',
        'No playbook': 'No playbook available for this attack type.',
        'Failed to load playbook': 'Failed to load playbook.',
        # Dashboard map
        'No geo data yet': 'No geo data yet',
        'Map unavailable': 'Map unavailable',
        'Heatmap data unavailable': 'Heatmap data unavailable',
        'attacks label': 'attacks',
        'No recent threats': 'No recent threats detected — System operational',
        # Remaining UI labels
        'LOADING': 'LOADING',
        'Private badge': 'Private',
        'Public badge': 'Public',
        'Enter IP placeholder': 'Enter IP…',
        'Username placeholder': 'Username',
        'Min 6 characters': 'Minimum 6 characters',
        'Enter case ID placeholder': 'Enter case ID e.g. a1b2c3d4',
        'Select all malicious title': 'Select all malicious flows',
        'Watchlist hit title': 'Watchlist hit',
        'Add tag placeholder': 'Add tag…',
        'triage confirmed': 'confirmed',
        'triage false positive': 'false positive',
        'triage investigated': 'investigated',
        # base.html UI
        'Toggle sidebar': 'Toggle sidebar',
        'Toggle theme': 'Toggle theme',
        'Active threats': 'Active threats',
        'THREATS label': 'THREATS',
        'LIVE FEED': 'LIVE FEED',
        'Loading threat feed': 'Loading threat feed…',
        'Toggle alert title': 'Toggle email alert on hit',
        'HIGH RISK label': 'HIGH RISK',
        'abuse score label': '% abuse score',
        'None label': 'None',
        'None found label': 'None found',
        'Unknown label': 'Unknown',
        'Threats chart': 'Threats',
        'Scans chart': 'Scans',
        # Threat gauge level labels
        'gauge MINIMAL': 'MINIMAL', 'gauge LOW': 'LOW', 'gauge MEDIUM': 'MEDIUM', 'gauge HIGH': 'HIGH', 'gauge CRITICAL': 'CRITICAL',
        'CSV import note': 'CSV must have an <code>ip</code> column. <code>note</code> and <code>threat_level</code> are optional.',
        'Sample CSV download': 'Download the <a href="{url}" style="color:var(--cyan)">Sample CSV</a> to see the expected format.',
        'Login title': 'Login',
        'MALICIOUS badge': 'MALICIOUS',
        'SUSPICIOUS badge': 'SUSPICIOUS',
        'CLEAN badge': 'CLEAN',
        'UNKNOWN badge': 'UNKNOWN',
        # ── Flash messages ─────────────────────────────────────────────────────
        'flash session expired': 'Session expired. Please log in again.',
        'flash admin required': 'Admin access required.',
        'flash cc admin required': 'CC Admin access required.',
        'flash account disabled': 'This account has been disabled. Contact your administrator.',
        'flash invalid credentials': 'Invalid credentials',
        'flash captcha required': 'Please complete the CAPTCHA.',
        'flash captcha failed': 'CAPTCHA verification failed. Please try again.',
        'flash captcha error': 'CAPTCHA service unavailable. Please try again.',
        'Security Check': 'SECURITY CHECK',
        'captcha human verify': 'Human verification required',
        'captcha footer': 'Protected by hCaptcha',
        'flash invalid file type': 'Please upload a valid .csv, .pcap, or .pcapng file.',
        'flash model not loaded': 'Model not loaded — check server logs.',
        'flash pcap failed': 'PCAP conversion failed — check server logs.',
        'flash scan not found': 'Scan not found.',
        'flash access denied scan': 'Access denied — this scan belongs to another analyst.',
        'flash ip added watchlist': 'Added {ip} to watchlist.',
        'flash ip removed watchlist': 'Removed {ip} from watchlist.',
        'flash watchlist updated': 'Updated watchlist entry for {ip}.',
        'flash ip required': 'IP address required.',
        'flash invalid ip': 'Invalid IP address.',
        'flash ip already watchlist': '{ip} is already in watchlist.',
        'flash no file': 'No file uploaded.',
        'flash file empty': 'File is empty.',
        'flash import error': 'Import failed — check server logs.',
        'flash imported ips': 'Imported {n} new IPs.',
        'flash alert rule added': 'Alert rule added.',
        'flash rule deleted': 'Rule deleted.',
        'flash schedule added': 'Schedule added.',
        'flash schedule deleted': 'Schedule deleted.',
        'flash compare min 2': 'Select at least 2 scans to compare.',
        'flash scan id not found': 'Scan {sid} not found.',
        'flash models reloaded': 'Models reloaded.',
        'flash settings saved': 'Settings saved.',
        'flash user pass required': 'Username and password required.',
        'flash invalid username': 'Username must be 1-32 characters (letters, digits, underscore only).',
        'flash password too short': 'Password must be at least 8 characters.',
        'flash invalid file path': 'File path must be within the uploads directory.',
        'flash user exists': 'User {u} already exists.',
        'flash user added': 'User {u} added.',
        'flash cannot remove self': 'Cannot remove yourself.',
        'flash cannot remove last admin': 'Cannot remove the last admin user.',
        'flash invalid recipient email': 'Invalid recipient email address.',
        'flash webhook must use https': 'Webhook URL must use http or https.',
        'flash webhook no localhost': 'Webhook URL must not point to localhost.',
        'flash webhook no private ip': 'Webhook URL must not point to a private/internal address.',
        'flash user removed': 'User {u} removed.',
        'flash cannot disable self': 'Cannot disable yourself.',
        'flash user enabled': 'User {u} enabled.',
        'flash user disabled': 'User {u} disabled.',
        'flash cannot change own role': 'Cannot change your own role.',
        'flash invalid role': 'Invalid role.',
        'flash user not found': 'User {u} not found.',
        'flash role set': '{u} role set to {role}.',
        'flash promoted cc admin': '{u} promoted to CC Admin.',
        'flash analyst moved': '{u} moved to {dest}.',
        'flash title required': 'Title is required.',
        'flash case created': 'Case "{title}" created.',
        'flash case not found': 'Case not found.',
        'flash access denied': 'Access denied.',
        'flash case closed': 'Case closed.',
        'flash case analyst close': 'Case submitted for CC Admin review.',
        'flash case cc close': 'Case reviewed and closed. Admin notified for permanent closure.',
        'flash case updated': 'Case updated.',
        'flash fpdf2 missing': 'fpdf2 not installed. Run: pip install fpdf2',
        'flash no valid files': 'No valid CSV or PCAP files found.',
        'flash file unavailable': 'Original file no longer available.',
        'flash wrong password': 'Current password is incorrect.',
        'flash passwords mismatch': 'New passwords do not match.',
        'flash password changed': 'Password changed successfully.',
        'flash 2fa missing': '2FA requires: pip install pyotp qrcode[pil]',
        'flash 2fa disabled': '2FA disabled.',
        'flash 2fa enabled': '2FA enabled. Please log in again to verify it works.',
        'flash invalid code': 'Invalid verification code.',
        'flash invalid 2fa code': 'Invalid 2FA code.',
        'flash file too large': 'File too large — maximum upload size is 2 GB.',
        'flash analyst added': 'Analyst {u} added.',
        'flash ip whitelist added': '{ip} added to whitelist.',
        'flash entry removed': 'Entry removed.',
        'flash file save error': 'File could not be saved — check disk space and permissions.',
        'flash file type not allowed': 'File type .{ext} is not allowed.',
        'flash notes limit reached': 'Maximum 500 notes per case reached.',
        'unassigned': 'unassigned',
        'IDS Platform': 'IDS Platform',
        'English': 'English',
        'Arabic': 'Arabic',
        'Notifications': 'Notifications',
        'ETA': 'ETA',
        'Event': 'Event',
        'role analyst': 'analyst',
        'role cc_admin': 'cc_admin',
        'role admin': 'admin',
        'ph ip simple': 'e.g. 192.168.1.1',
        'ph ip dest': 'e.g. 10.0.0.1',
        'ph ip range': 'e.g. 192.168.1.100 or 10.0.0.0/8',
        'ph note watchlist': 'e.g. Known attacker, C2 server…',
        'ph whitelist note': 'e.g. Internal scanner, Monitoring server',
        'ph rule name': 'e.g. High-volume attacker',
        'ph rule condition': 'attack_count > 100 from same IP in 5min',
        'ph schedule name': 'e.g. Daily Traffic Scan',
        'ph username example': 'analyst01',
        'View scans for this IP': 'View scans for this IP',
        'Session Expiring': 'Session Expiring',
        'Session warning message': 'Your session will expire in',
        'Stay Logged In': 'Stay Logged In',
        # Remaining untranslated strings
        'XGBoost acc label': 'ThresholdClassifier · 99.9% Acc',
        'CSV format before': 'CSV files exported from ',
        'CSV format after': ' or compatible network flow tools.',
        'Accuracy': 'Accuracy',
        'Macro F1': 'Macro F1',
        'ROC-AUC': 'ROC-AUC',
        'files selected:': 'file(s) selected:',
        'day Mon': 'Mon', 'day Tue': 'Tue', 'day Wed': 'Wed', 'day Thu': 'Thu',
        'day Fri': 'Fri', 'day Sat': 'Sat', 'day Sun': 'Sun',
        'month Jan': 'Jan', 'month Feb': 'Feb', 'month Mar': 'Mar', 'month Apr': 'Apr',
        'month May': 'May', 'month Jun': 'Jun', 'month Jul': 'Jul', 'month Aug': 'Aug',
        'month Sep': 'Sep', 'month Oct': 'Oct', 'month Nov': 'Nov', 'month Dec': 'Dec',
        'run scan first suffix': ' first.',
        'threat singular': 'threat', 'threats plural': 'threats',
        'total label': 'total',
        'entries admin only': 'entries (admin only)',
        'ID th': 'ID',
        'select scan alert': 'Please select a scan for every slot.',
        'different scan alert': 'Each slot must be a different scan.',
        # sentinel.js / WHOIS / watchlist strings
        'whois private IP': 'Private/internal IP — no public WHOIS data',
        'whois no data': 'No data found',
        'whois lookup failed': 'Lookup failed',
        'no IP address': 'No IP address',
        'IP added watchlist toast': 'added to watchlist',
        'watching label': '✓ Watching',
        'failed to add': 'Failed to add',
        'watch label': '🎯 Watch',
        'marked as read': 'Marked as read',
        'select at least one IP': 'Select at least one IP',
        'IPs added watchlist': 'IP(s) added to watchlist',
        'IPs already watchlist': 'IP(s) already in watchlist',
        # sentinel.js triage/tag/notification toasts
        'flow marked as': 'Flow marked as',
        'triage failed': 'Triage failed',
        'tag added': 'Tag added',
        'failed to add tag': 'Failed to add tag',
        'tag removed': 'Tag removed',
        'failed to remove tag': 'Failed to remove tag',
        'all notifs read': 'All notifications marked as read',
        'notification deleted': 'Notification deleted',
        'Unknown author': 'Unknown',
        # attack_detail scan label
        'Scan:': 'Scan:',
        # Activity log action labels
        'act scan_complete': 'Scan Complete', 'act scan_start': 'Scan Start',
        'act login': 'Login', 'act logout': 'Logout',
        'act triage': 'Triage', 'act triage_bulk': 'Bulk Triage',
        'act case_create': 'Case Created', 'act case_close': 'Case Closed', 'act case_assign': 'Case Assigned',
        'act case_analyst_close': 'Analyst Submitted', 'act case_cc_close': 'CC Admin Reviewed', 'act case_attach': 'Attachment Added',
        'act case_return_analyst': 'Returned to Analyst', 'act case_return_cc': 'Returned to CC Admin',
        'act case_comment_delete': 'Comment Deleted', 'act case_archived': 'Case Archived',
        'act settings_save': 'Settings Saved',
        'act user_add': 'User Added', 'act user_remove': 'User Removed',
        'act user_enable': 'User Enabled', 'act user_disable': 'User Disabled',
        'act user_role_change': 'Role Changed', 'act user_promote': 'User Promoted',
        'act analyst_move': 'Analyst Moved',
        'act watchlist_add': 'Watchlist Add', 'act watchlist_remove': 'Watchlist Remove',
        'act watchlist_edit': 'Watchlist Edit', 'act watchlist_import': 'Watchlist Import',
        'act password_change': 'Password Changed',
        'act 2fa_enabled': '2FA Enabled', 'act 2fa_disabled': '2FA Disabled',
        'act auto_triage': 'Auto Triage',
        'act whitelist_add': 'Whitelist Add', 'act whitelist_remove': 'Whitelist Remove',
        'act cc_admin_user_add': 'User Added (CC)',
        # Threat Intelligence Feed
        'Threat Intel': 'Threat Intel',
        'Threat Intelligence Feed': 'Threat Intelligence Feed',
        'threat_intel subtitle': 'Aggregated IOC data from your scan history, enriched with AbuseIPDB, VirusTotal & Shodan',
        'Top Malicious IPs': 'Top Malicious IPs',
        'top_ips subtitle': 'Most frequently detected threat sources across all scans',
        'Attack Breakdown': 'Attack Breakdown',
        'attack_breakdown subtitle': 'Distribution of attack types from recent scans',
        'IP Lookup': 'IP Lookup',
        'ip_lookup subtitle': 'Enrich any IP with live threat intelligence',
        'Cached Intelligence': 'Cached Intelligence',
        'cached_intel subtitle': 'Previously enriched IPs (refreshed every 24 h)',
        'Lookup IP': 'Lookup IP',
        'Enter IP address': 'Enter IP address…',
        'Abuse Score': 'Abuse Score',
        'ISP': 'ISP',
        'Last Reported': 'Last Reported',
        'Times Seen': 'Times Seen',
        'Attack Types': 'Attack Types',
        'Scans': 'Scans',
        'No malicious IPs found': 'No malicious IPs detected across your scan history yet.',
        'No cached intel': 'No IP lookups cached yet. Use the lookup form above.',
        'No attack data': 'No attack data available from recent scans.',
        'Private IP': 'Private IP',
        'Querying…': 'Querying…',
        'Add to Watchlist': 'Add to Watchlist',
        'View Details': 'View Details',
        'intel_private_ip': 'Private/reserved IP — not queryable via threat intel services.',
        'intel_no_key': 'AbuseIPDB API key not configured. Go to Settings to add it.',
        'ip lookup hint': 'Enter a public IP address to check its reputation across AbuseIPDB, VirusTotal, and Shodan.',
        'scans label': 'scans',
        'Reports': 'Reports', 'Total Reports': 'Total Reports',
        'intel_high_risk': 'HIGH RISK', 'intel_risk': 'RISK', 'intel_suspicious': 'SUSPICIOUS', 'intel_clean': 'CLEAN',
        'Scans Analyzed': 'Scans Analyzed',
        'Country': 'Country',
        'VT Score': 'VT Score', 'VT Malicious': 'Malicious Engines',
        'Shodan Intel': 'Shodan Intel', 'Open Ports': 'Open Ports',
        'CVEs': 'Known CVEs', 'Hostnames': 'Hostnames',
        'shodan_no_key': 'Shodan API key not configured. Go to Settings to add it.',
        'shodan_no_data': 'No Shodan data available for this IP.',
        'Last Seen': 'Last Seen', 'Organization': 'Organization',
        # API JSON error messages displayed to users
        'user word': ' user ',
        'csrf failed': 'CSRF validation failed',
        'api not found': 'Not found',
        'api access denied': 'Access denied',
        'api model not loaded': 'Model not loaded — check server logs',
        'api shap not installed': 'SHAP library not installed on server.',
        'api internal error': 'An internal error occurred',
        'api rate limited': 'API rate limit exceeded — please try again later',
        'api abuseipdb invalid key': 'Invalid AbuseIPDB API key — check Settings',
        'api invalid ip': 'Invalid IP address',
        'api no ip': 'No IP address',
        'engines': 'engines',
        'api abuseipdb key not set': 'AbuseIPDB API key not configured',
        'api vt key not set': 'VirusTotal API key not configured',
        'api shodan key not set': 'Shodan API key not configured',
        'api vt ip not found': 'IP not found in VirusTotal',
        'api shodan ip not found': 'No Shodan data for this IP',
        'api invalid status': 'Invalid status',
        'api no flow ids': 'No flow IDs provided',
        'api too many flow ids': 'Too many flow IDs (max 5000)',
        'api flow ids integers': 'Flow IDs must be integers',
        'request failed prefix': 'Request failed: ',
        'shodan plan required': '⚠ Shodan host lookup requires a paid plan.',
        'api shodan timed out': 'Request timed out',
        'api shodan conn failed': 'Connection failed',
        'api shodan invalid key': 'Invalid API key',
    },
    'ar': {
        # Navigation
        'Dashboard': 'لوحة التحكم', 'New Scan': 'فحص جديد',
        'Scan History': 'سجل الفحص', 'Watchlist': 'قائمة المراقبة', 'Compare Scans': 'مقارنة الفحوصات',
        'Model': 'النموذج', 'Admin': 'المشرف', 'Settings': 'الإعدادات', 'Logout': 'تسجيل الخروج',
        'API Status': 'حالة API', 'Analysis': 'التحليل', 'System': 'النظام', 'Main': 'الرئيسية',
        'Model Online': 'النموذج متصل', 'Model Offline': 'النموذج غير متصل',
        # Dashboard
        'Security Operations Center': 'مركز عمليات الأمن',
        'Real-time threat intelligence': 'استخبارات التهديدات الآنية وتحليل تدفقات الشبكة',
        'IP Map': 'خريطة IP', 'Activity': 'النشاط', 'PDF': 'PDF',
        'Total Scans': 'إجمالي الفحوصات', 'Flows Analyzed': 'التدفقات المحللة',
        'Threats Detected': 'التهديدات المكتشفة', 'Detection Rate': 'معدل الكشف',
        'Threat Level': 'مستوى التهديد', 'Overall posture': 'الوضع الأمني العام',
        'No active threats detected': 'لا توجد تهديدات نشطة',
        'Recurring Attackers': 'المهاجمون المتكررون', 'IPs seen in 2+ scans': 'عناوين IP في أكثر من فحصين',
        'IP Address': 'عنوان IP', 'Scan Count': 'عدد الفحوصات', 'Total Hits': 'إجمالي الضربات',
        'Watch': 'مراقبة', 'No recurring attackers': 'لم يُكتشف مهاجمون متكررون بعد',
        'Severity Distribution': 'توزيع درجة الخطورة', 'Attack Type Breakdown': 'تصنيف أنواع الهجمات',
        'No scan data yet': 'لا توجد بيانات فحص بعد', 'Run First Scan': 'تشغيل أول فحص',
        'No threat data yet': 'لا توجد بيانات تهديد بعد',
        'Scan Activity Timeline': 'الجدول الزمني لنشاط الفحص', 'Last 20 scans': 'آخر 20 فحص',
        'Run scans to see activity': 'شغّل فحوصات لرؤية النشاط عبر الزمن',
        'Attack Origin Map': 'خريطة مصدر الهجمات', 'Country distribution': 'توزيع الدول',
        'Loading map': 'جارٍ تحميل الخريطة...', 'Threat Trend': 'اتجاه التهديدات',
        'Recent Scans': 'الفحوصات الأخيرة', 'No scans yet': 'لا توجد فحوصات بعد',
        # Scan page
        'Network Flow Analysis': 'تحليل تدفقات الشبكة',
        'Upload subtitle': 'ارفع ملف CSV أو PCAP من CIC-IDS2017 لتصنيف حركة الشبكة',
        'Upload Traffic Capture': 'رفع ملف التقاط الحركة',
        'Model Ready': 'النموذج جاهز', 'Single File': 'ملف واحد', 'Multiple Files': 'ملفات متعددة',
        'Drop your file here': 'اسحب ملفك هنا', 'or click to browse': 'أو انقر للتصفح',
        'Expected Format': 'التنسيق المتوقع', 'Attack Classes': 'فئات الهجمات',
        'How Scan Works': 'كيف يعمل الفحص',
        'scan step 1': '1. ارفع ملف CSV أو PCAP يحتوي على تدفقات حركة الشبكة.',
        'scan step 2': '2. يقوم النظام باستخراج الميزات المطلوبة وتطبيعها.',
        'scan step 3': '3. يصنّف نموذج التعلم الآلي كل تدفق كحركة طبيعية أو نوع هجوم.',
        'scan step 4': '4. تُعرض النتائج مع تسميات التهديدات ودرجات الثقة وعناوين IP المصدر.',
        'Model Performance': 'أداء النموذج', 'Analyze Flows': 'تحليل التدفقات',
        'Clear': 'مسح', 'Analyze All Files': 'تحليل جميع الملفات',
        'Select multiple files': 'اختر ملفات متعددة',
        'INITIALIZING SCAN': 'جارٍ تهيئة الفحص...', 'LOADING MODELS': 'جارٍ تحميل النماذج...', 'ANALYZING FLOWS': 'جارٍ تحليل التدفقات...', 'CLASSIFYING THREATS': 'جارٍ تصنيف التهديدات...',
        'only CSV accepted': 'لا تُقبل إلا ملفات CSV أو PCAP أو PCAPNG.', 'select CSV first': 'يرجى اختيار ملف CSV أولاً.',
        'Processing flows': 'معالجة تدفقات الشبكة — يرجى الانتظار',
        # History
        'scans recorded': 'فحص مسجّل', 'Search scans': 'ابحث عن فحوصات...',
        'Flows': 'تدفقات', 'Threats': 'تهديدات', 'Confidence': 'الثقة',
        'No scans on record': 'لا توجد فحوصات مسجلة بعد.',
        # Result page
        'Total Flows': 'إجمالي التدفقات', 'Malicious': 'ضار', 'Benign': 'حميد',
        'Avg Confidence': 'متوسط الثقة', 'View Map': 'عرض الخريطة', 'Explain': 'شرح',
        'PDF Report': 'تقرير PDF', 'Export CEF': 'تصدير CEF',
        'Correlation': 'الارتباط', 'Export CSV': 'تصدير CSV',
        'PDF + CSV Report': 'تقرير PDF + CSV', 'Raw Flows CSV': 'تصدير CSV الخام',
        'PDF + CSV': 'PDF + CSV',
        # Settings
        'Settings subtitle': 'إعدادات تنبيهات SMTP وخطافات الويب و AbuseIPDB و VirusTotal و Shodan',
        'Email Alerts (SMTP)': 'تنبيهات البريد (SMTP)', 'Test Email': 'اختبار البريد',
        'SMTP Host': 'خادم SMTP', 'SMTP Port': 'منفذ SMTP',
        'SMTP User / From': 'مستخدم SMTP / المُرسِل', 'SMTP Password': 'كلمة مرور SMTP',
        'Alert Recipient': 'مستلم التنبيه (إلى)',
        'Webhook Alerts': 'تنبيهات Webhook', 'Test Webhook': 'اختبار Webhook', 'Webhook URL': 'رابط Webhook',
        'IP Reputation': 'سمعة IP (AbuseIPDB)', 'AbuseIPDB API Key': 'مفتاح AbuseIPDB API',
        'VirusTotal Lookup': 'فحص IP عبر VirusTotal', 'VirusTotal API Key': 'مفتاح VirusTotal API',
        'Shodan Host Intel': 'استخبارات المضيف (Shodan)', 'Shodan API Key': 'مفتاح Shodan API',
        'Key configured': 'المفتاح مُهيَّأ', 'Alert Triggers': 'مشغّلات التنبيه',
        'Alert on CRITICAL': 'تنبيه عند تهديدات حرجة',
        'CRITICAL alert desc': 'إرسال بريد/خطاف عند اكتشاف تدفقات بخطورة حرجة',
        'Alert on HIGH': 'تنبيه عند تهديدات عالية',
        'HIGH alert desc': 'إرسال بريد/خطاف عند اكتشاف تدفقات بخطورة عالية',
        'Save Settings': 'حفظ الإعدادات', 'Leave blank': 'اتركه فارغاً للإبقاء على القيمة الحالية',
        'Sending': 'جارٍ الإرسال...',
        # Admin
        'Admin subtitle': 'إدارة المستخدمين ونظرة عامة على النظام',
        'Model Status': 'حالة النموذج', 'Config': 'الإعداد', 'Watchlist IPs': 'عناوين IP المراقبة',
        'Users': 'المستخدمون', 'Username': 'اسم المستخدم', 'Role': 'الدور', 'Status': 'الحالة',
        'Last Login': 'آخر دخول', 'Actions': 'الإجراءات',
        'Set': 'تعيين', 'Enable': 'تفعيل', 'Disable': 'تعطيل', 'Remove': 'حذف',
        'Add New User': 'إضافة مستخدم جديد', 'Password': 'كلمة المرور',
        'Assign to CC Admin': 'تعيين لمشرف CC', 'Add User': 'إضافة مستخدم',
        'CC Admin Overview': 'نظرة عامة على مشرفي CC',
        'CC Admin Overview subtitle': 'المحللون المُدارون من كل مشرف CC',
        'analyst(s)': 'محلل/محللون', 'Analyst': 'المحلل', 'Promote': 'ترقية', 'Move': 'نقل',
        'No analysts assigned': 'لم يُعيَّن أي محلل بعد.',
        'View analyst activity': 'عرض نشاط المحلل',
        'events': 'أحداث', 'LOGIN': 'دخول', 'LOGOUT': 'خروج',
        'Never': 'لم يدخل', 'you': 'أنت',
        # Table columns / common labels
        'Filename': 'اسم الملف', 'Timestamp': 'الوقت', 'Time': 'الوقت', 'Top Severity': 'أعلى خطورة',
        'View': 'عرض', 'View All': 'عرض الكل', 'Week': 'أسبوع', 'Month': 'شهر',
        'Attack Frequency Heatmap': 'خريطة حرارة تكرار الهجمات', 'Day x Hour': 'اليوم × الساعة',
        'Less': 'أقل', 'More': 'أكثر',
        'No scans yet start': 'لا توجد فحوصات بعد. ارفع ملف CSV للبدء.',
        'Start First Scan': 'ابدأ أول فحص',
        'Model not loaded': 'النموذج غير محمّل',
        # Nav items (base.html)
        'Correlation nav': 'الارتباط', 'IP Map nav': 'خريطة IP', 'Threat Hunt': 'صيد التهديدات',
        'Timeline': 'الجدول الزمني', 'Cases': 'القضايا', 'Alert Rules': 'قواعد التنبيه',
        'Schedules': 'الجداول الزمنية', 'Audit Log': 'سجل المراجعة', 'Activity Log': 'سجل النشاط',
        'Export Dashboard PDF': 'تصدير لوحة التحكم PDF', 'FP Feedback': 'تغذية راجعة FP',
        'IP Whitelist': 'القائمة البيضاء للـ IP', 'Change Password': 'كلمة المرور', 'CC Admin': 'مشرف CC',
        '2FA Setup': 'إعداد 2FA', 'Back': 'رجوع', 'Scan Detail': 'تفاصيل الفحص',
        # Result page
        'THREAT LEVEL': 'مستوى التهديد', 'No Threats Detected': 'لم يُكتشف أي تهديد',
        'Low-Level Threats': 'تهديدات منخفضة المستوى',
        'Significant Threats': 'تهديدات بالغة مكتشفة',
        'Critical Threats': 'تهديدات حرجة — إجراء فوري مطلوب',
        'Scan ID': 'معرّف الفحص', 'Alert sent': 'تم إرسال تنبيه عبر البريد/الخطاف للتهديدات المكتشفة.',
        'Traffic Split': 'توزيع حركة المرور', 'Severity Breakdown': 'توزيع درجة الخطورة',
        'Threat Timeline': 'الجدول الزمني للتهديدات', 'No threat data': 'لا توجد بيانات تهديد',
        'Threat Distribution Chart': 'مخطط توزيع التهديدات',
        'Attack Types': 'أنواع الهجمات', 'Click to inspect flows': 'انقر للتفتيش',
        'No malicious flows': 'لم يُكتشف أي تدفق ضار',
        'Flow-Level Results': 'نتائج على مستوى التدفق', 'Search flows': 'ابحث في التدفقات...',
        'Columns': 'الأعمدة', 'FILTER': 'تصفية',
        'All': 'الكل', 'Critical': 'حرجة', 'High': 'عالية', 'Medium': 'متوسطة', 'Safe': 'آمنة',
        'Classification': 'التصنيف', 'Src IP': 'IP المصدر', 'Src Port': 'منفذ المصدر',
        'Dst IP': 'IP الوجهة', 'Dst Port': 'منفذ الوجهة', 'Proto': 'البروتوكول',
        'Severity': 'الخطورة', 'Triage': 'الفرز',
        'THREAT': 'تهديد', 'SAFE status': 'آمن',
        'Investigated': 'تم التحقيق', 'FP': 'إيجابية كاذبة', 'Confirmed': 'مؤكد',
        'Flow ID': 'معرّف التدفق', 'Anomaly Score': 'نسبة الشذوذ', 'Protocol': 'البروتوكول',
        'Watchlist Hit': 'في قائمة المراقبة', 'Yes': 'نعم', 'No': 'لا',
        'Lookup WHOIS': 'بحث WHOIS',
        'Showing first 2000': 'عرض أول 2,000 تدفق. نزّل CSV للنتائج الكاملة.',
        'selected': 'محدد', 'Mark Investigated': 'وضع علامة: تم التحقيق',
        'Mark False Positive': 'وضع علامة: إيجابية كاذبة', 'Mark Confirmed': 'وضع علامة: مؤكد',
        'Add to Case': 'إضافة إلى قضية', 'Cancel': 'إلغاء',
        'Add Selected Flows to Case': 'إضافة التدفقات المحددة إلى قضية',
        'Case ID': 'معرّف القضية', 'Re-scan': 'إعادة الفحص', 'Network Graph': 'مخطط الشبكة',
        'threats in': 'تهديد في', 'analyzed flows': 'تدفق محلّل',
        'View Full Result': 'عرض النتيجة الكاملة', 'HIGH SEVERITY': 'خطورة عالية',
        # Common
        'Online': 'متصل', 'Offline': 'غير متصل', 'ACTIVE': 'نشط', 'DISABLED': 'معطّل',
        # Compare select
        'Compare subtitle': 'اختر من 2 إلى 5 فحوصات للمقارنة جنباً إلى جنب',
        'Select Scans': 'اختر الفحوصات', 'Add Scan': 'إضافة فحص', 'Remove Last': 'حذف الأخير',
        'Compare btn': 'مقارنة', 'Need 2 scans': 'تحتاج إلى فحصين على الأقل في السجل للمقارنة.',
        'Run a scan': 'شغّل فحصاً', 'scans selected': 'فحص محدد',
        # Compare results
        'Scan Comparison': 'مقارنة الفحوصات', 'scans compared': 'فحوصات مقارنة',
        'New Comparison': 'مقارنة جديدة', 'Metric Comparison': 'مقارنة المقاييس',
        'Best': 'الأفضل', 'Worst': 'الأسوأ', 'Metric': 'المقياس',
        'Malicious Flows': 'تدفقات ضارة', 'Benign Flows': 'تدفقات حميدة',
        'Avg Confidence %': 'متوسط الثقة %', 'No threats': 'لا تهديدات',
        # CC Admin page
        'CC Admin Panel title': 'لوحة مشرف CC',
        'CC Admin page subtitle': 'إدارة حسابات المحللين ومراقبة النشاط',
        'Analysts': 'المحللون', 'Add New Analyst': 'إضافة محلل جديد',
        'Add Analyst': 'إضافة محلل', 'Analyst Activity Log': 'سجل نشاط المحلل',
        'Login Logout events': 'أحداث الدخول/الخروج — آخر 200',
        'Detail': 'التفاصيل', 'No analysts yet': 'لا يوجد محللون بعد.',
        'No login events': 'لم يتم تسجيل أي أحداث دخول/خروج لمحلليك بعد.',
        'analyst only note': 'يمكنك فقط إنشاء حسابات محلل.',
        # Audit log
        'Analyst Audit Log': 'سجل مراجعة المحللين', 'Search log': 'ابحث في السجل...',
        'User': 'المستخدم', 'Action': 'الإجراء', 'No audit entries': 'لا توجد إدخالات مراجعة بعد',
        # Model page
        'Model subtitle': 'نموذج IDS المبني على XGBoost — تقرير التدريب وعناصر التحكم',
        'Reload Models': 'إعادة تحميل النماذج', 'Start Retrain': 'بدء إعادة التدريب',
        'Retraining': 'جارٍ إعادة التدريب…', 'Best Model': 'أفضل نموذج', 'Test Accuracy': 'دقة الاختبار',
        'Training Report': 'تقرير التدريب', 'training report source': 'من outputs/training_report.txt',
        'Live Retrain Log': 'سجل إعادة التدريب المباشر',
        'Running': 'جارٍ التشغيل…', 'Completed': 'اكتمل',
        'Retrain confirm': 'سيبدأ هذا إعادة تدريب جميع النماذج من الصفر. قد يستغرق هذا وقتاً طويلاً. هل تريد المتابعة؟',
        'retrain already running': 'إعادة التدريب قيد التشغيل بالفعل',
        # Watchlist
        'Watchlist subtitle': 'مراقبة عناوين IP والشبكات الفرعية المحددة عبر جميع الفحوصات',
        'Import CSV': 'استيراد CSV', 'Sample CSV': 'نموذج CSV', 'Add IP': 'إضافة IP',
        'Monitored IPs': 'عناوين IP / الشبكات المراقبة', 'IP / CIDR': 'IP / CIDR',
        'Note': 'ملاحظة', 'Added': 'تمت الإضافة', 'Expires': 'ينتهي',
        'Last Seen': 'آخر ظهور', 'Hits': 'الضربات', 'Rep': 'السمعة', 'Alert': 'تنبيه',
        'Scans btn': 'الفحوصات', 'Edit': 'تعديل', 'No IPs in watchlist': 'لا يوجد عناوين IP في قائمة المراقبة بعد.',
        'Add First IP': 'إضافة أول IP', 'Add IP to Watchlist': 'إضافة IP إلى قائمة المراقبة',
        'IP Address or CIDR': 'عنوان IP أو CIDR *', 'Note optional': 'ملاحظة (اختياري)',
        'Expires At': 'ينتهي في (اختياري)', 'Send alert when detected': 'إرسال تنبيه عند الكشف',
        'Send alert when this IP': 'إرسال تنبيه عند اكتشاف هذا العنوان',
        'Add to Watchlist btn': 'إضافة إلى قائمة المراقبة', 'Edit Watchlist Entry': 'تعديل إدخال قائمة المراقبة',
        'Save Changes': 'حفظ التغييرات', 'Import IPs from CSV': 'استيراد IPs من CSV',
        'CSV File': 'ملف CSV *', 'Import': 'استيراد', 'Search IP or note': 'ابحث بـ IP أو ملاحظة…',
        # Attack detail
        'Attack Detail title': 'تفاصيل الهجوم', 'Back to Scan': '← رجوع إلى الفحص',
        'Add to Watchlist': 'إضافة إلى قائمة المراقبة', 'Threat Intelligence': 'استخبارات التهديدات',
        'Detected Flows': 'التدفقات المكتشفة', 'Of Total Traffic': 'من إجمالي الحركة',
        'Total Flows in Scan': 'إجمالي التدفقات في الفحص', 'Protocol Breakdown': 'توزيع البروتوكولات',
        'About This Attack': 'حول هذا الهجوم', 'Why model flagged': 'لماذا وضع النموذج علامة على هذا؟',
        'Technique ID': 'معرّف التقنية', 'Technique Name': 'اسم التقنية', 'Tactic': 'التكتيك',
        'Response Playbook': 'دليل الاستجابة',
        'playbook hint': '— انقر لعرض خطوات الاستجابة للحوادث',
        'Network Flows table': 'تدفقات الشبكة', 'Filter flows': 'تصفية التدفقات…',
        'Source IP': 'IP المصدر', 'Destination IP': 'IP الوجهة',
        'Inv': 'تحقيق', 'Conf': 'تأكيد', 'No flows found': 'لم يتم العثور على تدفقات لهذا النوع من الهجمات.',
        'Select IPs to add': 'حدد عناوين IP للإضافة من هذا الهجوم:', 'Add Selected': 'إضافة المحدد',
        'WHOIS btn': 'WHOIS',
        # Threat Hunt
        'Threat Hunting': 'صيد التهديدات', 'Hunt subtitle': 'البحث في جميع بيانات الفحص التاريخية',
        'Hunt Query': 'استعلام الصيد', 'Attack Type': 'نوع الهجوم',
        'Date From': 'من تاريخ', 'Date To': 'إلى تاريخ',
        'Min Confidence (%)': 'أدنى ثقة (%)', 'Hunt btn': 'صيد',
        'Results': 'النتائج', 'No results': 'لا توجد نتائج',
        'matches': 'تطابق', 'page': 'صفحة', 'File col': 'الملف',
        'Prev': '‹ السابق', 'Next': 'التالي ›', 'No flows matched': 'لم تتطابق أي تدفقات مع استعلامك.',
        # Notifications
        'Alert Notifications': 'إشعارات التنبيه', 'unread': 'غير مقروء',
        'Mark All Read': 'وضع علامة مقروء للكل', 'Mark Read': 'وضع علامة مقروء', 'Delete': 'حذف',
        'View Scan': 'عرض الفحص', 'View Case': 'عرض القضية', 'No notifications': 'لا توجد إشعارات بعد',
        'Notifs appear when': 'تظهر الإشعارات عندما تكتشف الفحوصات تهديدات',
        # Cases
        'Case Management': 'إدارة القضايا', 'cases': 'قضية', 'open': 'مفتوحة',
        'New Case': 'قضية جديدة', 'No cases yet': 'لا توجد قضايا بعد',
        'Create First Case': 'إنشاء أول قضية', 'New Investigation Case': 'قضية تحقيق جديدة',
        'Case Title': 'عنوان القضية *', 'Description': 'الوصف',
        'Priority': 'الأولوية', 'Assign To': 'تعيين إلى',
        'Link Scan ID': 'ربط معرّف الفحص (اختياري)', 'SLA Hours': 'ساعات SLA (افتراضي: 24)',
        'Create Case': 'إنشاء القضية', 'Assigned': 'مُعيَّن:', 'Created at': 'تاريخ الإنشاء:',
        'comments': 'تعليقات', 'Open time': 'مفتوحة:', 'SLA label': 'SLA',
        'OVERDUE': 'متأخرة', 'SLA WARNING': 'تحذير SLA', 'ON TRACK': 'في المسار',
        'Overdue Cases': 'القضايا المتأخرة', 'overdue cases': 'قضية متأخرة', 'All Cases': 'جميع القضايا',
        'Assignees': 'المُكلَّفون', 'Assign To (multiple)': 'تعيين إلى', 'Assigned to': 'مُسنَد إلى',
        'Open Cases': 'القضايا المفتوحة', 'Closed Cases': 'القضايا المغلقة',
        'closed': 'مغلقة', 'No closed cases': 'لا توجد قضايا مغلقة بعد.',
        'No open cases': 'لا توجد قضايا مفتوحة.', 'No results match': 'لا توجد قضايا تطابق بحثك.',
        'Search cases label': 'ابحث في القضايا…',
        # History detail
        'Detected Attack Types': 'أنواع الهجمات المكتشفة', 'Flow Details': 'تفاصيل التدفقات',
        'Filter flows td': 'تصفية التدفقات...',
        # Change password
        'Change Password title': 'تغيير كلمة المرور', 'Update password subtitle': 'تحديث كلمة مرور حسابك',
        'Password Update': 'تحديث كلمة المرور', 'Current Password': 'كلمة المرور الحالية',
        'New Password label': 'كلمة مرور جديدة', 'Confirm New Password': 'تأكيد كلمة المرور الجديدة',
        'Update Password': 'تحديث كلمة المرور',
        'pw match': 'كلمتا المرور متطابقتان', 'pw no match': 'كلمتا المرور غير متطابقتين',
        'pw weak': 'ضعيفة', 'pw fair': 'مقبولة', 'pw good': 'جيدة', 'pw strong': 'قوية', 'pw very strong': 'قوية جداً',
        # FP Feedback
        'False Positive Feedback': 'تغذية راجعة للإيجابيات الكاذبة',
        'FP subtitle': 'الإيجابيات الكاذبة التي أبلغ عنها المحللون مجمّعة حسب التصنيف',
        'No FP records': 'لا توجد سجلات إيجابيات كاذبة بعد.',
        'FP records note': 'يتم إنشاء سجلات FP عندما يضع المحللون علامة "إيجابية كاذبة" أثناء الفرز.',
        # IP Whitelist
        'IP Whitelist title': 'القائمة البيضاء للـ IP',
        'Whitelist subtitle': 'عناوين IP والنطاقات المُدرجة في القائمة البيضاء تُستثنى من التنبيهات',
        'Whitelist Entries': 'إدخالات القائمة البيضاء', 'Added By': 'أضافه', 'Added At': 'وقت الإضافة',
        'No whitelisted IPs': 'لا توجد عناوين IP في القائمة البيضاء بعد.',
        'Add Whitelist Entry': 'إضافة إدخال إلى القائمة البيضاء',
        'IP Address or CIDR add': 'عنوان IP أو CIDR *', 'Add btn': 'إضافة',
        # Login
        'Username label': 'اسم المستخدم', 'Password label': 'كلمة المرور',
        'AUTHENTICATE': 'تسجيل الدخول', 'System Operational': 'النظام يعمل',
        # Activity Log
        'Activity Log title': 'سجل النشاط',
        'All system events': 'جميع أحداث النظام', 'entries': 'إدخال',
        'Back to Dashboard': '← العودة إلى لوحة التحكم',
        'Scans Completed': 'الفحوصات المكتملة', 'Login Events': 'أحداث تسجيل الدخول',
        'Triage Actions': 'إجراءات الفرز', 'Total Events': 'إجمالي الأحداث',
        'All Events': 'جميع الأحداث',
        'All Actions': 'جميع الإجراءات', 'Logins filter': 'تسجيلات الدخول',
        'Triage filter': 'الفرز', 'Alerts filter': 'التنبيهات', 'Settings filter': 'الإعدادات',
        'No activity recorded': 'لم يُسجَّل أي نشاط بعد.',
        'Activity empty note': 'يتم تسجيل النشاط عند تشغيل الفحوصات أو تسجيل الدخول أو تنفيذ إجراءات الفرز.',
        'Run First Scan': 'تشغيل أول فحص',
        # API Status
        'API Status title': 'حالة واجهة برمجة التطبيقات والخدمات', 'Last checked:': 'آخر فحص:',
        'Refresh': 'تحديث', 'Reset': 'إعادة ضبط', 'Online stat': 'متصل', 'services healthy': 'خدمات تعمل بشكل جيد',
        'Warnings stat': 'تحذيرات', 'not configured': 'غير مُهيَّأ',
        'Errors stat': 'أخطاء', 'connection failed': 'فشل الاتصال',
        'Total stat': 'الإجمالي', 'services checked': 'خدمة مفحوصة',
        'Configure': 'ضبط',
        # Case Detail
        'Cases breadcrumb': 'القضايا', 'Analyst:': 'المحلل:', 'Assigned:': 'مُسنَد إلى:',
        'by': 'بواسطة',
        'Appointed by': 'عُيِّن بواسطة',
        'Case ID:': 'معرّف القضية:', 'Created:': 'أُنشئت:', 'comments suffix': 'تعليق',
        'Back to Cases': '← العودة إلى القضايا', 'Export PDF': 'تصدير PDF', 'Close Case': 'إغلاق القضية',
        'Attachments': 'المرفقات', 'Any file type allowed': 'أي نوع ملف — يمكن رفع ملفات متعددة',
        'Attachment types hint': 'PDF, TXT, LOG, CSV, JSON، الصور، مستندات Office، ZIP، PCAP — يمكن رفع ملفات متعددة',
        'No attachments yet': 'لا توجد مرفقات بعد.',
        'Add Attachments label': 'إضافة مرفقات', 'Upload btn': 'رفع', 'Download btn': 'تنزيل',
        'Attach File label': 'إرفاق ملف', 'optional any type': '(اختياري، أي نوع)',
        'files suffix': 'ملف(ات)',
        'analyst close btn': 'إنهاء وتقديم للمراجعة',
        'analyst close confirm': 'هل تريد تقديم هذه القضية لمراجعة مسؤول CC؟',
        'cc close btn': 'إغلاق بعد المراجعة',
        'cc close confirm': 'هل تريد إغلاق هذه القضية وإخطار المسؤول؟',
        'permanently close btn': 'إغلاق نهائي',
        'Assignment Priority': 'التعيين والأولوية', 'Update btn': 'تحديث',
        'Priority:': 'الأولوية:', 'Assigned inline': 'مُسنَد:',
        'Linked Scans': 'الفحوصات المرتبطة', 'scans suffix': 'فحص',
        'File th': 'الملف', 'Threats th': 'التهديدات', 'View btn': 'عرض',
        'Investigation Comments': 'تعليقات التحقيق',
        'No comments yet': 'لا توجد تعليقات بعد. أضف أول تعليق أدناه.',
        'Add Comment label': 'إضافة تعليق', 'Add Comment btn': 'إضافة تعليق',
        'Add Comment placeholder': 'نتائج التحقيق، الإجراءات المتخذة…',
        'Case closed note': 'هذه القضية مغلقة. لا يمكن إضافة تعليقات جديدة.',
        # Case Archive & Return flow
        'Case Archive': 'أرشيف القضايا', 'Archive': 'الأرشيف', 'View Archive': 'عرض الأرشيف',
        'Yearly Cases': 'القضايا السنوية', 'Monthly Cases': 'القضايا الشهرية',
        'No archived cases': 'لا توجد قضايا مؤرشفة بعد.', 'archived cases': 'قضية مؤرشفة',
        'years': 'سنة', 'month': 'شهر', 'months': 'أشهر',
        'Closed cases from previous months are automatically archived here.': 'يتم أرشفة القضايا المغلقة من الأشهر السابقة تلقائياً هنا.',
        'Closed:': 'أُغلق:', 'CLOSED': 'مغلق',
        'Return to Analyst': 'إرجاع للمحلل',
        'return analyst confirm': 'هل تريد إرجاع هذه القضية إلى المحلل لمزيد من العمل؟',
        'Return to CC Admin': 'إرجاع لمسؤول CC',
        'return cc confirm': 'هل تريد إرجاع هذه القضية إلى مسؤول CC لإعادة المراجعة؟',
        'flash case returned analyst': 'تم إرجاع القضية إلى المحلل لمزيد من العمل.',
        'flash case returned cc': 'تم إرجاع القضية إلى مسؤول CC لإعادة المراجعة.',
        'delete comment confirm': 'هل تريد حذف هذا التعليق نهائياً؟',
        'flash comment deleted': 'تم حذف التعليق.',
        'RETURNED badge': 'مُرجَع',
        'Returned by notice': 'أُرجع بواسطة',
        'for further work notice': 'لمزيد من العمل',
        'for re-review notice': 'لإعادة المراجعة',
        # Alert Rules
        'Alert Rules title': 'قواعد التنبيه',
        'Alert Rules subtitle': 'تشغيل تنبيهات البريد الإلكتروني أو webhook بناءً على شروط الفحص',
        'New Rule': 'قاعدة جديدة',
        'Rules card': 'القواعد', 'Condition th': 'الشرط',
        'Name th': 'الاسم', 'Created': 'تاريخ الإنشاء', 'Enabled': 'مُفعَّل', 'Disabled': 'معطَّل',
        'No alert rules': 'لا توجد قواعد تنبيه محددة.', 'Create First Rule': 'إنشاء أول قاعدة',
        'Condition Syntax': 'بناء جملة الشرط', 'New Alert Rule': 'قاعدة تنبيه جديدة',
        'Rule Name label': 'اسم القاعدة *', 'Condition label': 'الشرط *',
        'Action select': 'الإجراء', 'Email option': 'بريد إلكتروني', 'Webhook option': 'Webhook',
        'Both option': 'كلاهما', 'Enable immediately': 'تفعيل فوراً',
        'Create Rule btn': 'إنشاء القاعدة',
        # Scheduled Scans
        'Scheduled Scans title': 'الفحوصات المجدولة',
        'Schedules subtitle': 'تشغيل الفحوصات تلقائياً في الأوقات المحددة',
        'New Schedule': 'جدول جديد', 'Schedules card': 'الجداول',
        'Time HH MM': 'الوقت (HH:MM)', 'File Path th': 'مسار الملف',
        'Last Run': 'آخر تشغيل',
        'No schedules': 'لا توجد جداول مُهيَّأة.', 'Create First Schedule': 'إنشاء أول جدول',
        'Schedule Name label': 'اسم الجدول *', 'Time HH MM label': 'الوقت (HH:MM، 24 ساعة) *',
        'File Path label': 'مسار الملف (مسار مطلق لملف CSV)',
        'Create Schedule btn': 'إنشاء الجدول',
        # Scan Queue
        'Scan Queue title': 'طابور الفحص', 'files processing': 'ملف — تتم معالجتها واحداً تلو الآخر',
        # Attack Timeline
        'Attack Timeline title': 'الجدول الزمني للهجمات',
        'Timeline subtitle': 'عرض زمني لجميع التهديدات المكتشفة عبر الفحوصات',
        'Threat Event Scatter': 'مخطط انتشار أحداث التهديد',
        'All Events tl': 'جميع الأحداث', 'Count th': 'العدد', 'Scan th': 'الفحص',
        'No attack events': 'لم يتم العثور على أحداث هجوم. قم بإجراء بعض الفحوصات أولاً.',
        # SHAP
        'SHAP title': 'شرح النموذج (SHAP)',
        'Top 10 Features': 'أهم 10 مميزات',
        'Computing SHAP': 'جارٍ احتساب قيم SHAP…',
        'Feature Importance Table': 'جدول أهمية المميزات',
        'Feature th': 'الميزة', 'Mean SHAP Value': 'متوسط |SHAP|',
        'Relative Importance': 'الأهمية النسبية',
        # Correlation
        'Correlation title': 'ترابط الهجمات حسب عنوان IP المصدر',
        'Correlation note prefix': 'الارتباط — فحص',
        'Correlated attacker prefix': 'مهاجم مترابط —',
        'Threat Actors': 'الجهات المهددة',
        'Threat Score formula': 'نقاط التهديد = عدد التدفقات × ترتيب الخطورة',
        'Attack Types th': 'أنواع الهجمات', 'Flow Count th': 'عدد التدفقات',
        'Max Severity': 'أقصى خطورة', 'Threat Score': 'نقاط التهديد',
        'Watch btn': '🎯 مراقبة', 'No malicious correlation': 'لم يتم العثور على تدفقات خبيثة في هذا الفحص.',
        # Playbooks
        'Playbooks title': 'كتيبات الاستجابة للحوادث',
        'Playbooks subtitle': 'إجراءات استجابة خطوة بخطوة لكل نوع هجوم',
        # Scan Live
        'Live Classification title': 'تصنيف التدفق المباشر',
        'Processed stat': 'تمت معالجته', 'Total live stat': 'الإجمالي',
        'Threats live stat': 'التهديدات', 'Benign live stat': 'حميد', 'Phase stat': 'المرحلة',
        'Pause btn': 'إيقاف مؤقت', 'Resume btn': 'استئناف', 'Restart btn': 'إعادة تشغيل',
        'Load step': 'تحميل', 'Features step': 'المميزات', 'Classify step': 'تصنيف',
        'Save step': 'حفظ', 'Speed label': 'السرعة',
        'Live Flow Feed': 'تغذية التدفق المباشر', 'rows suffix': 'صف',
        'Threats only': 'التهديدات فقط', 'Clear btn': 'مسح',
        'Status th': 'الحالة', 'Waiting classification': 'في انتظار نتائج التصنيف…',
        'Streaming': 'جارٍ البث…', 'Showing last flows': 'عرض آخر',
        # 2FA Setup
        '2FA title': 'المصادقة الثنائية',
        '2FA subtitle': 'أضف طبقة حماية إضافية لحسابك',
        '2FA Enabled card': 'المصادقة الثنائية مُفعَّلة',
        '2FA enabled msg': 'المصادقة الثنائية مُفعَّلة حالياً على حسابك.',
        '2FA disable hint': 'يمكنك تعطيل المصادقة الثنائية أدناه. ستحتاج إلى إعادة تفعيلها لتأمين حسابك مجدداً.',
        '2FA disable code hint': 'أدخل الرمز من تطبيق المصادقة للتأكيد',
        'Disable 2FA': 'تعطيل المصادقة الثنائية',
        'Scan QR Code': 'مسح رمز QR',
        'TOTP scan hint': 'امسح باستخدام Google Authenticator أو Authy أو أي تطبيق TOTP',
        'Manual secret key': 'المفتاح السري اليدوي:',
        'Verify Enable': 'تحقق وتفعيل',
        '2FA verify hint': 'بعد مسح رمز QR، أدخل الرمز المكوّن من 6 أرقام من تطبيق المصادقة لتفعيل المصادقة الثنائية.',
        '6-Digit Code label': 'رمز مكوّن من 6 أرقام *', 'Enable 2FA': 'تفعيل المصادقة الثنائية',
        # 2FA Verify
        '2FA Verification': 'التحقق بالمصادقة الثنائية',
        '2FA verify code hint': 'أدخل الرمز المكوّن من 6 أرقام من تطبيق المصادقة للمتابعة.',
        'Verification Code': 'رمز التحقق', 'Verify btn': 'تحقق',
        'Cancel Logout': 'إلغاء / تسجيل خروج',
        # Global Correlation page
        'Global Attack Correlation': 'الارتباط العالمي للهجمات',
        'unique sources': 'مصدر فريد',
        'Search IP corr': 'ابحث بـ IP…',
        'Scans Seen': 'الفحوصات التي شوهد فيها',
        'more': 'المزيد',
        'No cross-scan correlations': 'لم يتم العثور على ارتباطات عبر الفحوصات بعد.',
        'Run Scans': 'تشغيل الفحوصات',
        # Network Graph page
        'Unique IPs': 'عناوين IP فريدة', 'Connections': 'الاتصالات',
        'Attackers': 'المهاجمون', 'Victims': 'الضحايا',
        'NODE:': 'العقدة:', 'Attacker src': 'مهاجم (مصدر)',
        'Victim dst': 'ضحية (وجهة)', 'Both node': 'كلاهما', 'EDGE:': 'الحافة:',
        'Force-Directed IP Topology': 'طوبولوجيا IP',
        'Building graph': 'جارٍ بناء الرسم البياني…',
        'No IP connections': 'لا توجد اتصالات IP',
        'No IP connections hint': 'الفحص لا يحتوي على أعمدة IP أو جميع العناوين خاصة',
        'Role:': 'الدور:', 'Attacks:': 'الهجمات:',
        # Geo / Dashboard Map pages
        'IP Geolocation Map': 'خريطة تحديد موقع IP',
        'Global Threat Distribution': 'التوزيع العالمي للتهديدات',
        'IP List': 'قائمة IP', 'Loading geo data': 'جارٍ تحميل بيانات الموقع…',
        'Lat / Lon': 'خط العرض / الطول', 'Country': 'الدولة',
        'Country:': 'الدولة:', 'Flows:': 'التدفقات:', 'Status:': 'الحالة:',
        'MALICIOUS': 'ضار', 'BENIGN badge': 'حميد',
        'auto rotate btn': 'تدوير تلقائي',
        'globe load failed': '⚠ فشل تحميل الخريطة — تحقق من اتصال الإنترنت.',
        'NEW badge': 'جديد',
        'Global IP Geolocation Map': 'خريطة تحديد موقع IP العالمية',
        'dashboard map subtitle': 'عناوين IP المجمّعة من جميع الفحوصات — العناوين العامة معروضة',
        'Public IP Map': 'خريطة IP العامة', 'Loading': 'جارٍ التحميل…',
        'All Attack IPs': 'جميع عناوين IP الهجومية', 'Filter IPs': 'تصفية عناوين IP…',
        'Malicious only': 'الضارة فقط', 'Type': 'النوع', 'Attack Labels': 'تصنيفات الهجوم',
        'Malicious IPs': 'عناوين IP الضارة', 'Private IPs': 'عناوين IP الخاصة',
        'No public IPs msg': 'لا توجد عناوين IP عامة — البيانات تستخدم عناوين خاصة',
        'public IPs plotted': 'عنوان IP عام معروض',
        'No IP data found': 'لا توجد بيانات IP. شغّل فحصاً أولاً.',
        'Failed to load': 'فشل التحميل',
        # Scan Live page
        'RUNNING badge': 'جارٍ', 'PAUSED badge': 'متوقف مؤقتاً',
        'COMPLETE badge': 'اكتمل', 'ERROR badge': 'خطأ',
        'INITIALIZING': 'جارٍ التهيئة…', 'Streaming': 'جارٍ البث…', 'Paused': 'متوقف مؤقتاً',
        'rows': 'صف', 'Showing last 500': 'عرض آخر 500 تدفق',
        'THREAT badge': '⚠ تهديد', 'SAFE badge': '✓ آمن',
        'Complete finished in': 'اكتمل — انتهى في', 'redirecting': 'جارٍ إعادة التوجيه…',
        # Scan Queue page
        'Queued badge': 'في الانتظار', 'Waiting': 'انتظار…', 'Scanning': 'جارٍ الفحص…',
        'Done': 'اكتمل', 'View Results': 'عرض النتائج ←',
        # History Detail / Attack Detail / SHAP
        'SEVERITY': 'خطورة', 'SEVERITY ATTACK': 'هجوم — خطورة',
        'What is': 'ما هو',
        'Enter IP to query': 'أدخل عنوان IP واضغط على مزود للاستعلام.',
        'SHAP subtitle': 'أهم المميزات للتدفقات الضارة (XGBoost)',
        'SHAP how to read': 'كيفية القراءة:',
        'SHAP explanation': 'تقيس قيم SHAP مساهمة كل ميزة في تنبؤات النموذج. القيم الأعلى تشير إلى ميزات ذات تأثير أكبر على تصنيف التدفقات. يُحسب هذا على أول 50 تدفقاً ضاراً باستخدام XGBoost TreeExplainer.',
        'No mal flows scan': 'لا توجد تدفقات ضارة في هذا الفحص.',
        'features shown': 'ميزة معروضة',
        # Capture
        'Capturing': 'جارٍ الالتقاط…', 'Stopped': 'توقف',
        'Low': 'منخفضة', 'Scan label': 'فحص', 'Select scan': '— اختر فحصاً —', 'threats count': 'تهديد',
        # Topbar titles
        'Case Detail title': 'تفاصيل القضية', 'Scan Result': 'نتيجة الفحص',
        'Live Analysis title': 'التحليل المباشر', 'Bucket': 'حاوية',
        # Help texts
        'whitelist IP hint': 'يدعم عناوين IP الدقيقة (192.168.1.1) وترميز CIDR (10.0.0.0/8). سيتم تصنيف عناوين IP المدرجة في القائمة البيضاء على أنها حميدة أثناء الفحص.',
        'schedule how it works': 'كيف يعمل: يتحقق الجدول الزمني كل دقيقة. عيّن الوقت بتنسيق HH:MM (24 ساعة). يجب أن يكون مسار الملف مساراً مطلقاً لملف CSV على الخادم. تعمل الفحوصات تلقائياً في الخلفية وتظهر النتائج في سجل الفحص.',
        'password help text': 'بعد تغيير كلمة مرورك، ستبقى مسجلاً الدخول. اختر كلمة مرور قوية من 8 أحرف على الأقل تحتوي على أحرف وأرقام ورموز.',
        'scan column help': 'يتم مطابقة أسماء الأعمدة تلقائياً — الأعمدة الإضافية يتم تجاهلها، والميزات المفقودة تأخذ قيمة 0.',
        'condition syntax help': 'الشروط المدعومة: attack_count > N من نفس IP في 5 دقائق — يُطلق التنبيه عندما يرسل IP أكثر من N تدفق ضار في نافذة 5 دقائق. اضبط رقم الحد حسب الحاجة.',
        'How it works': 'كيف يعمل',
        'Supported conditions': 'الشروط المدعومة:',
        'rule fire desc': '— يُطلق التنبيه عندما يرسل IP أكثر من 100 تدفق ضار في نافذة 5 دقائق',
        'Adjust threshold': 'اضبط رقم الحد حسب الحاجة',
        'alert settings note': 'يتم ضبط إعدادات البريد الإلكتروني والخطاف في',
        # JS confirm / alert messages
        'Alert enabled': 'تم تفعيل التنبيه', 'Alert disabled': 'تم تعطيل التنبيه',
        'Re-run confirm': 'هل تريد إعادة تشغيل هذا الفحص بالملف الأصلي؟',
        'Remove from watchlist confirm': 'إزالة {ip} من قائمة المراقبة؟',
        'Permanently remove user': 'حذف {user} نهائياً؟',
        'Promote to CC Admin': 'ترقية {user} إلى مشرف CC؟',
        'Remove analyst confirm': 'إزالة المحلل {user}؟',
        'Bulk triage error': 'خطأ في الفرز الجماعي: ',
        'Please enter Case ID': 'الرجاء إدخال معرّف القضية.',
        'Added to case msg': 'تمت الإضافة إلى القضية وتم تمييزه على أنه قيد التحقيق.',
        'ERROR prefix': 'خطأ: ',
        'Delete rule confirm': 'حذف القاعدة؟',
        'Delete schedule confirm': 'حذف الجدول الزمني؟',
        # Login page
        'Intrusion Detection System': 'نظام كشف التسلل',
        'system footer': 'مجموعة بيانات CIC-IDS2017 · نموذج ThresholdClassifier',
        'terminal line 1': '> جارٍ تهيئة BASTION...',
        'terminal line 2': '> جارٍ تحميل نماذج التهديد... [موافق]',
        'terminal line 3': '> النظام جاهز. في انتظار المصادقة.',
        # Settings JS
        'Network error': 'خطأ في الشبكة',
        'Get API key at': 'احصل على مفتاح API من',
        'Get free API key at': 'احصل على مفتاح API المجاني من',
        'free tier checks': '(مجاني: 1000 فحص/يوم)',
        'lookups free': '(500 بحث/يوم مجاناً)',
        'free tier available': '(الطبقة المجانية متاحة)',
        # Scan formats
        'Hold Ctrl select': 'اضغط Ctrl لتحديد ملفات متعددة',
        'file formats supported': 'يدعم .CSV / .PCAP / .PCAPNG',
        'file formats max': '.CSV / .PCAP / .PCAPNG — حد أقصى 2 غيغابايت',
        'MB selected': 'ميغابايت محدد',
        # Admin
        'Min 8 characters': 'حد أدنى 8 أحرف',
        'None Unassigned': '— لا شيء / غير مُسنَد —',
        # 2FA
        'Disable 2FA confirm': 'هل تريد تعطيل المصادقة الثنائية؟ سيكون حسابك أقل أماناً.',
        # Timeline
        'flows label': 'تدفقات',
        # Toast titles
        'toast SUCCESS': 'نجاح', 'toast ERROR': 'خطأ', 'toast WARNING': 'تحذير', 'toast INFO': 'معلومة',
        # API Status page detail/note strings
        'svc not loaded': 'غير محمَّل', 'svc not configured': 'غير مُعدَّ',
        'svc configure settings': 'يمكن الإعداد في الإعدادات',
        'svc connected ip': 'متصل · فحص سمعة IP نشط',
        'svc invalid key': 'مفتاح API غير صالح (401)',
        'svc connection failed': 'فشل الاتصال',
        'svc unreachable': 'غير قابل للوصول',
        'svc model note': 'محمَّل من models/best_model.pkl',
        'svc api key not configured': 'مفتاح API غير مُعدَّ',
        'svc smtp connected': 'متصل بـ {host}:{port}',
        'svc smtp alert to': 'التنبيهات → {email}',
        'svc smtp host': 'المضيف',
        'svc webhook reachable': 'قابل للوصول',
        'svc storage used': 'مستخدم',
        'svc storage free': 'حر',
        'svc storage scan files': 'ملف فحص في outputs/flows/',
        'svc could not read': 'تعذّر القراءة',
        'test email ok': 'تم إرسال البريد الإلكتروني بنجاح',
        'smtp not configured': 'بروتوكول SMTP غير مُعدَّ',
        'webhook responded': 'استجاب Webhook: {code}',
        'webhook url not configured': 'رابط Webhook غير مُعدَّ',
        # Compare
        'SCAN label': 'فحص',
        # Cases
        'e.g. DDoS Campaign': 'مثال: تحقيق هجوم DDoS',
        'Brief description': 'وصف مختصر للقضية…',
        'e.g. scan id': 'مثال: 20241201_143022',
        'recurring attacker note': 'مهاجم متكرر — أضيف من لوحة التحكم',
        # JS inline labels — attack_detail / watchlist / capture / shap / case
        'Close case confirm': 'إغلاق هذه القضية؟',
        'Enter an IP address': 'أدخل عنوان IP',
        'Checking': 'جارٍ الفحص…',
        'Country:': 'الدولة:',
        'Reports:': 'التقارير:',
        'Last reported:': 'آخر إبلاغ:',
        'Reputation:': 'السمعة:',
        'City:': 'المدينة:',
        'ISP:': 'مزود الإنترنت:',
        'Malicious:': 'ضار:',
        'Suspicious:': 'مشبوه:',
        'Harmless:': 'غير ضار:',
        'AS Owner:': 'مالك AS:',
        'Org:': 'المنظمة:',
        'Open Ports:': 'المنافذ المفتوحة:',
        'Hostnames:': 'أسماء المضيف:',
        'CVEs:': 'الثغرات الأمنية:',
        'Private IP badge': 'IP خاص',
        'N/A rep': 'غير متاح', 'UTC label': 'UTC',
        'Error: prefix': 'خطأ: ',
        'Network error prefix': 'خطأ في الشبكة: ',
        # API provider messages
        'AbuseIPDB not configured': '⚠ مفتاح AbuseIPDB API غير مضبوط — اذهب إلى <a href="/settings" style="color:var(--cyan)">الإعدادات</a> لتهيئته.',
        'VT not configured': '⚠ مفتاح VirusTotal API غير مضبوط — اذهب إلى <a href="/settings" style="color:var(--cyan)">الإعدادات</a> لتهيئته.',
        'Shodan not configured': '⚠ مفتاح Shodan API غير مضبوط — اذهب إلى <a href="/settings" style="color:var(--cyan)">الإعدادات</a> لتهيئته.',
        'private IP query note': 'عنوان IP خاص/محجوز — غير قابل للاستعلام عبر هذه الخدمة.',
        'Request failed': 'فشل الطلب',
        'VT error prefix': 'خطأ VT: ',
        'Shodan error prefix': 'Shodan: ',
        'Querying VirusTotal': 'جارٍ الاستعلام من VirusTotal…',
        'Querying Shodan': 'جارٍ الاستعلام من Shodan…',
        'No playbook': 'لا يوجد دليل إجراءات لهذا النوع من الهجمات.',
        'Failed to load playbook': 'فشل تحميل دليل الإجراءات.',
        # Dashboard map
        'No geo data yet': 'لا توجد بيانات جغرافية بعد',
        'Map unavailable': 'الخريطة غير متاحة',
        'Heatmap data unavailable': 'بيانات خريطة الحرارة غير متاحة',
        'attacks label': 'هجمات',
        'No recent threats': 'لا تهديدات حديثة — النظام يعمل بشكل طبيعي',
        # Remaining UI labels
        'LOADING': 'جارٍ التحميل',
        'Private badge': 'خاص',
        'Public badge': 'عام',
        'Enter IP placeholder': 'أدخل IP…',
        'Username placeholder': 'اسم المستخدم',
        'Min 6 characters': 'الحد الأدنى 6 أحرف',
        'Enter case ID placeholder': 'أدخل معرف القضية مثال: a1b2c3d4',
        'Select all malicious title': 'تحديد كل التدفقات الضارة',
        'Watchlist hit title': 'موجود في قائمة المراقبة',
        'Add tag placeholder': 'إضافة وسم…',
        'triage confirmed': 'مؤكد',
        'triage false positive': 'إيجابية كاذبة',
        'triage investigated': 'قيد التحقيق',
        # base.html UI
        'Toggle sidebar': 'تبديل الشريط الجانبي',
        'Toggle theme': 'تبديل السمة',
        'Active threats': 'التهديدات النشطة',
        'THREATS label': 'تهديدات',
        'LIVE FEED': 'بث مباشر',
        'Loading threat feed': 'جارٍ تحميل بيانات التهديدات…',
        'Toggle alert title': 'تبديل تنبيه البريد الإلكتروني عند الرصد',
        'HIGH RISK label': 'خطر مرتفع',
        'abuse score label': '% درجة الإساءة',
        'None label': 'لا شيء',
        'None found label': 'لا شيء موجود',
        'Unknown label': 'غير معروف',
        'Threats chart': 'التهديدات',
        'Scans chart': 'الفحوصات',
        # Threat gauge level labels
        'gauge MINIMAL': 'ضئيل', 'gauge LOW': 'منخفض', 'gauge MEDIUM': 'متوسط', 'gauge HIGH': 'عالٍ', 'gauge CRITICAL': 'حرج',
        'CSV import note': 'يجب أن يحتوي ملف CSV على عمود <code>ip</code>. العمودان <code>note</code> و<code>threat_level</code> اختياريان.',
        'Sample CSV download': 'قم بتنزيل <a href="{url}" style="color:var(--cyan)">نموذج CSV</a> لرؤية التنسيق المطلوب.',
        'Login title': 'تسجيل الدخول',
        'MALICIOUS badge': 'ضار',
        'SUSPICIOUS badge': 'مشبوه',
        'CLEAN badge': 'نظيف',
        'UNKNOWN badge': 'غير معروف',
        # ── Flash messages ─────────────────────────────────────────────────────
        'flash session expired': 'انتهت الجلسة. يرجى تسجيل الدخول مجدداً.',
        'flash admin required': 'مطلوب صلاحيات المسؤول.',
        'flash cc admin required': 'مطلوب صلاحيات مسؤول مركز التحكم.',
        'flash account disabled': 'تم تعطيل هذا الحساب. يرجى التواصل مع المسؤول.',
        'flash invalid credentials': 'بيانات اعتماد غير صحيحة',
        'flash captcha required': 'يرجى إتمام التحقق من CAPTCHA.',
        'flash captcha failed': 'فشل التحقق من CAPTCHA. يرجى المحاولة مرة أخرى.',
        'flash captcha error': 'خدمة CAPTCHA غير متاحة. يرجى المحاولة مرة أخرى.',
        'Security Check': 'التحقق الأمني',
        'captcha human verify': 'التحقق من هوية المستخدم مطلوب',
        'captcha footer': 'محمي بواسطة hCaptcha',
        'flash invalid file type': 'يرجى رفع ملف .csv أو .pcap أو .pcapng صحيح.',
        'flash model not loaded': 'لم يتم تحميل النموذج — راجع سجلات الخادم.',
        'flash pcap failed': 'فشل تحويل PCAP — راجع سجلات الخادم.',
        'flash scan not found': 'الفحص غير موجود.',
        'flash access denied scan': 'الوصول مرفوض — هذا الفحص يخص محللاً آخر.',
        'flash ip added watchlist': 'تمت إضافة {ip} إلى قائمة المراقبة.',
        'flash ip removed watchlist': 'تمت إزالة {ip} من قائمة المراقبة.',
        'flash watchlist updated': 'تم تحديث إدخال قائمة المراقبة لـ {ip}.',
        'flash ip required': 'عنوان IP مطلوب.',
        'flash invalid ip': 'عنوان IP غير صحيح.',
        'flash ip already watchlist': '{ip} موجود بالفعل في قائمة المراقبة.',
        'flash no file': 'لم يتم رفع أي ملف.',
        'flash file empty': 'الملف فارغ.',
        'flash import error': 'فشل الاستيراد — راجع سجلات الخادم.',
        'flash imported ips': 'تم استيراد {n} عناوين IP جديدة.',
        'flash alert rule added': 'تمت إضافة قاعدة التنبيه.',
        'flash rule deleted': 'تم حذف القاعدة.',
        'flash schedule added': 'تمت إضافة الجدولة.',
        'flash schedule deleted': 'تم حذف الجدولة.',
        'flash compare min 2': 'اختر على الأقل فحصين للمقارنة.',
        'flash scan id not found': 'الفحص {sid} غير موجود.',
        'flash models reloaded': 'تم إعادة تحميل النماذج.',
        'flash settings saved': 'تم حفظ الإعدادات.',
        'flash user pass required': 'اسم المستخدم وكلمة المرور مطلوبان.',
        'flash invalid username': 'يجب أن يكون اسم المستخدم 1-32 حرفاً (أحرف وأرقام وشرطة سفلية فقط).',
        'flash password too short': 'يجب أن تكون كلمة المرور 8 أحرف على الأقل.',
        'flash invalid file path': 'يجب أن يكون مسار الملف داخل مجلد الرفع.',
        'flash user exists': 'المستخدم {u} موجود بالفعل.',
        'flash user added': 'تمت إضافة المستخدم {u}.',
        'flash cannot remove self': 'لا يمكنك إزالة نفسك.',
        'flash cannot remove last admin': 'لا يمكن حذف المشرف الأخير.',
        'flash invalid recipient email': 'عنوان البريد الإلكتروني للمستلم غير صحيح.',
        'flash webhook must use https': 'يجب أن يستخدم رابط Webhook بروتوكول http أو https.',
        'flash webhook no localhost': 'يجب ألا يشير رابط Webhook إلى localhost.',
        'flash webhook no private ip': 'يجب ألا يشير رابط Webhook إلى عنوان خاص/داخلي.',
        'flash user removed': 'تم حذف المستخدم {u}.',
        'flash cannot disable self': 'لا يمكنك تعطيل نفسك.',
        'flash user enabled': 'تم تفعيل المستخدم {u}.',
        'flash user disabled': 'تم تعطيل المستخدم {u}.',
        'flash cannot change own role': 'لا يمكنك تغيير دورك الخاص.',
        'flash invalid role': 'دور غير صحيح.',
        'flash user not found': 'المستخدم {u} غير موجود.',
        'flash role set': 'تم تعيين دور {u} إلى {role}.',
        'flash promoted cc admin': 'تمت ترقية {u} إلى مسؤول مركز التحكم.',
        'flash analyst moved': 'تم نقل {u} إلى {dest}.',
        'flash title required': 'العنوان مطلوب.',
        'flash case created': 'تم إنشاء القضية "{title}".',
        'flash case not found': 'القضية غير موجودة.',
        'flash access denied': 'الوصول مرفوض.',
        'flash case closed': 'تم إغلاق القضية.',
        'flash case analyst close': 'تم تقديم القضية لمراجعة مسؤول CC.',
        'flash case cc close': 'تمت مراجعة القضية وإغلاقها. تم إخطار المسؤول للإغلاق النهائي.',
        'flash case updated': 'تم تحديث القضية.',
        'flash fpdf2 missing': 'fpdf2 غير مثبت. قم بتشغيل: pip install fpdf2',
        'flash no valid files': 'لم يتم العثور على ملفات CSV أو PCAP صحيحة.',
        'flash file unavailable': 'الملف الأصلي لم يعد متاحاً.',
        'flash wrong password': 'كلمة المرور الحالية غير صحيحة.',
        'flash passwords mismatch': 'كلمتا المرور الجديدتان غير متطابقتين.',
        'flash password changed': 'تم تغيير كلمة المرور بنجاح.',
        'flash 2fa missing': 'التحقق الثنائي يتطلب: pip install pyotp qrcode[pil]',
        'flash 2fa disabled': 'تم تعطيل التحقق الثنائي.',
        'flash 2fa enabled': 'تم تفعيل التحقق الثنائي. يرجى تسجيل الدخول مجدداً للتحقق.',
        'flash invalid code': 'رمز التحقق غير صحيح.',
        'flash invalid 2fa code': 'رمز التحقق الثنائي غير صحيح.',
        'flash file too large': 'الملف كبير جداً — الحد الأقصى للرفع هو 2 جيجابايت.',
        'flash analyst added': 'تمت إضافة المحلل {u}.',
        'flash ip whitelist added': 'تمت إضافة {ip} إلى القائمة البيضاء.',
        'flash entry removed': 'تم حذف الإدخال.',
        'flash file save error': 'تعذّر حفظ الملف — تحقق من مساحة القرص والصلاحيات.',
        'flash file type not allowed': 'نوع الملف .{ext} غير مسموح به.',
        'flash notes limit reached': 'تم الوصول إلى الحد الأقصى البالغ 500 ملاحظة لكل قضية.',
        'unassigned': 'غير مُعيَّن',
        'IDS Platform': 'منصة كشف التسلل',
        'English': 'الإنجليزية',
        'Arabic': 'العربية',
        'Notifications': 'الإشعارات',
        'ETA': 'الوقت المتبقي',
        'Event': 'الحدث',
        'role analyst': 'محلل',
        'role cc_admin': 'مسؤول مركز التحكم',
        'role admin': 'مسؤول',
        'ph ip simple': 'مثال: 192.168.1.1',
        'ph ip dest': 'مثال: 10.0.0.1',
        'ph ip range': 'مثال: 192.168.1.100 أو 10.0.0.0/8',
        'ph note watchlist': 'مثال: مهاجم معروف، خادم C2...',
        'ph whitelist note': 'مثال: ماسح داخلي، خادم مراقبة',
        'ph rule name': 'مثال: مهاجم عالي الحجم',
        'ph rule condition': 'attack_count > 100 من نفس الـ IP في 5 دقائق',
        'ph schedule name': 'مثال: فحص يومي للحركة',
        'ph username example': 'محلل01',
        'View scans for this IP': 'عرض الفحوصات لهذا العنوان',
        'Session Expiring': 'انتهاء الجلسة قريباً',
        'Session warning message': 'ستنتهي جلستك خلال',
        'Stay Logged In': 'البقاء متصلاً',
        # Remaining untranslated strings
        'XGBoost acc label': 'ThresholdClassifier · دقة 99.9%',
        'CSV format before': 'ملفات CSV مُصدَّرة من ',
        'CSV format after': ' أو أدوات تدفق الشبكة المتوافقة.',
        'Accuracy': 'الدقة',
        'Macro F1': 'ماكرو F1',
        'ROC-AUC': 'ROC-AUC',
        'files selected:': 'ملف(ات) محددة:',
        'day Mon': 'الإثنين', 'day Tue': 'الثلاثاء', 'day Wed': 'الأربعاء', 'day Thu': 'الخميس',
        'day Fri': 'الجمعة', 'day Sat': 'السبت', 'day Sun': 'الأحد',
        'month Jan': 'يناير', 'month Feb': 'فبراير', 'month Mar': 'مارس', 'month Apr': 'أبريل',
        'month May': 'مايو', 'month Jun': 'يونيو', 'month Jul': 'يوليو', 'month Aug': 'أغسطس',
        'month Sep': 'سبتمبر', 'month Oct': 'أكتوبر', 'month Nov': 'نوفمبر', 'month Dec': 'ديسمبر',
        'run scan first suffix': ' أولاً.',
        'threat singular': 'تهديد', 'threats plural': 'تهديدات',
        'total label': 'إجمالي',
        'entries admin only': 'إدخالات (للمشرف فقط)',
        'ID th': 'المعرف',
        'select scan alert': 'يرجى اختيار فحص لكل حقل.',
        'different scan alert': 'يجب أن يكون كل حقل فحصاً مختلفاً.',
        # sentinel.js / WHOIS / watchlist strings
        'whois private IP': 'عنوان IP خاص/داخلي — لا توجد بيانات WHOIS عامة',
        'whois no data': 'لا توجد بيانات',
        'whois lookup failed': 'فشل البحث',
        'no IP address': 'لا يوجد عنوان IP',
        'IP added watchlist toast': 'أضيف إلى قائمة المراقبة',
        'watching label': '✓ قيد المراقبة',
        'failed to add': 'فشل الإضافة',
        'watch label': '🎯 مراقبة',
        'marked as read': 'تم التعليم كمقروء',
        'select at least one IP': 'حدد عنوان IP واحداً على الأقل',
        'IPs added watchlist': 'عنوان(عناوين) IP أضيف إلى قائمة المراقبة',
        'IPs already watchlist': 'عنوان(عناوين) IP موجود بالفعل في قائمة المراقبة',
        # sentinel.js triage/tag/notification toasts
        'flow marked as': 'وُضِعت علامة على التدفق:',
        'triage failed': 'فشل الفرز',
        'tag added': 'تمت إضافة الوسم',
        'failed to add tag': 'فشل إضافة الوسم',
        'tag removed': 'تمت إزالة الوسم',
        'failed to remove tag': 'فشل إزالة الوسم',
        'all notifs read': 'تم تعليم جميع الإشعارات كمقروءة',
        'notification deleted': 'تم حذف الإشعار',
        'Unknown author': 'غير معروف',
        # attack_detail scan label
        'Scan:': 'الفحص:',
        # Activity log action labels
        'act scan_complete': 'فحص مكتمل', 'act scan_start': 'بدء الفحص',
        'act login': 'تسجيل دخول', 'act logout': 'تسجيل خروج',
        'act triage': 'فرز', 'act triage_bulk': 'فرز مجمّع',
        'act case_create': 'قضية مُنشأة', 'act case_close': 'قضية مغلقة', 'act case_assign': 'قضية مُسندة',
        'act case_analyst_close': 'محلل أنهى القضية', 'act case_cc_close': 'مراجعة CC مكتملة', 'act case_attach': 'مرفق مُضاف',
        'act case_return_analyst': 'أُرجع للمحلل', 'act case_return_cc': 'أُرجع لمسؤول CC',
        'act case_comment_delete': 'تعليق محذوف', 'act case_archived': 'قضية مؤرشفة',
        'act settings_save': 'حفظ الإعدادات',
        'act user_add': 'مستخدم مُضاف', 'act user_remove': 'مستخدم محذوف',
        'act user_enable': 'مستخدم مُفعَّل', 'act user_disable': 'مستخدم معطَّل',
        'act user_role_change': 'تغيير الدور', 'act user_promote': 'ترقية مستخدم',
        'act analyst_move': 'نقل المحلل',
        'act watchlist_add': 'إضافة للمراقبة', 'act watchlist_remove': 'إزالة من المراقبة',
        'act watchlist_edit': 'تعديل المراقبة', 'act watchlist_import': 'استيراد قائمة المراقبة',
        'act password_change': 'تغيير كلمة المرور',
        'act 2fa_enabled': 'تفعيل 2FA', 'act 2fa_disabled': 'تعطيل 2FA',
        'act auto_triage': 'فرز تلقائي',
        'act whitelist_add': 'إضافة للقائمة البيضاء', 'act whitelist_remove': 'إزالة من القائمة البيضاء',
        'act cc_admin_user_add': 'مستخدم مُضاف (CC)',
        # Threat Intelligence Feed
        'Threat Intel': 'استخبارات التهديدات',
        'Threat Intelligence Feed': 'موجز استخبارات التهديدات',
        'threat_intel subtitle': 'بيانات IOC مجمّعة من سجل الفحوصات، مُعززة بـ AbuseIPDB وVirusTotal وShodan',
        'Top Malicious IPs': 'أبرز عناوين IP الضارة',
        'top_ips subtitle': 'مصادر التهديد الأكثر رصداً عبر جميع الفحوصات',
        'Attack Breakdown': 'توزيع أنواع الهجمات',
        'attack_breakdown subtitle': 'توزيع أنواع الهجمات من الفحوصات الأخيرة',
        'IP Lookup': 'البحث عن IP',
        'ip_lookup subtitle': 'إثراء أي عنوان IP ببيانات استخباراتية آنية',
        'Cached Intelligence': 'الاستخبارات المخزّنة',
        'cached_intel subtitle': 'عناوين IP التي جرى إثراؤها مسبقاً (يُحدَّث كل 24 س)',
        'Lookup IP': 'ابحث عن IP',
        'Enter IP address': 'أدخل عنوان IP…',
        'Abuse Score': 'نسبة الإساءة',
        'ISP': 'مزوّد الخدمة',
        'Last Reported': 'آخر إبلاغ',
        'Times Seen': 'عدد مرات الرصد',
        'Attack Types': 'أنواع الهجمات',
        'Scans': 'الفحوصات',
        'No malicious IPs found': 'لم يُرصد أي عنوان IP ضار في سجل الفحوصات بعد.',
        'No cached intel': 'لا توجد بيانات IP مخزّنة بعد. استخدم نموذج البحث أعلاه.',
        'No attack data': 'لا تتوفر بيانات هجمات من الفحوصات الأخيرة.',
        'Private IP': 'IP خاص',
        'Querying…': 'جارٍ الاستعلام…',
        'Add to Watchlist': 'إضافة إلى قائمة المراقبة',
        'View Details': 'عرض التفاصيل',
        'intel_private_ip': 'عنوان IP خاص/محجوز — لا يمكن الاستعلام عنه عبر خدمات الاستخبارات.',
        'intel_no_key': 'مفتاح AbuseIPDB غير مهيّأ. اذهب إلى الإعدادات لإضافته.',
        'ip lookup hint': 'أدخل عنوان IP عاماً للتحقق من سمعته عبر AbuseIPDB وVirusTotal وShodan.',
        'scans label': 'فحوصات',
        'Reports': 'تقارير', 'Total Reports': 'إجمالي التقارير',
        'intel_high_risk': 'خطر عالٍ', 'intel_risk': 'خطر', 'intel_suspicious': 'مشبوه', 'intel_clean': 'نظيف',
        'Scans Analyzed': 'فحوصات محللة',
        'Country': 'الدولة',
        'VT Score': 'نتيجة VT', 'VT Malicious': 'محركات خبيثة',
        'Shodan Intel': 'استخبارات Shodan', 'Open Ports': 'المنافذ المفتوحة',
        'CVEs': 'ثغرات CVE المعروفة', 'Hostnames': 'أسماء المضيف',
        'shodan_no_key': 'مفتاح Shodan غير مهيّأ. اذهب إلى الإعدادات لإضافته.',
        'shodan_no_data': 'لا توجد بيانات Shodan لهذا العنوان.',
        'Last Seen': 'آخر رصد', 'Organization': 'المؤسسة',
        # API JSON error messages displayed to users
        'user word': ' المستخدم ',
        'csrf failed': 'فشل التحقق من CSRF',
        'api not found': 'غير موجود',
        'api access denied': 'الوصول مرفوض',
        'api model not loaded': 'النموذج غير محمّل — راجع سجلات الخادم',
        'api shap not installed': 'مكتبة SHAP غير مثبتة على الخادم.',
        'api internal error': 'حدث خطأ داخلي',
        'api rate limited': 'تم تجاوز حد الطلبات — يرجى المحاولة لاحقاً',
        'api abuseipdb invalid key': 'مفتاح AbuseIPDB غير صالح — تحقق من الإعدادات',
        'api invalid ip': 'عنوان IP غير صالح',
        'api no ip': 'لا يوجد عنوان IP',
        'engines': 'محركات',
        'api abuseipdb key not set': 'مفتاح AbuseIPDB API غير مُعدَّ',
        'api vt key not set': 'مفتاح VirusTotal API غير مُعدَّ',
        'api shodan key not set': 'مفتاح Shodan API غير مُعدَّ',
        'api vt ip not found': 'عنوان IP غير موجود في VirusTotal',
        'api shodan ip not found': 'لا توجد بيانات Shodan لهذا العنوان',
        'api invalid status': 'حالة غير صالحة',
        'api no flow ids': 'لم يتم تحديد معرّفات التدفقات',
        'api too many flow ids': 'عدد معرّفات التدفقات كبير جداً (الحد الأقصى 5000)',
        'api flow ids integers': 'يجب أن تكون معرّفات التدفقات أرقاماً صحيحة',
        'request failed prefix': 'فشل الطلب: ',
        'shodan plan required': '⚠ البحث في Shodan يتطلب خطة مدفوعة.',
        'api shodan timed out': 'انتهت مهلة الطلب',
        'api shodan conn failed': 'فشل الاتصال',
        'api shodan invalid key': 'مفتاح API غير صالح',
    }
}

def t(key):
    lang = session.get('lang', cfg('language', 'en'))
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, key)

# ── Severity map ──────────────────────────────────────────────────────────────
SEVERITY = {
    'BENIGN':                   ('SAFE',     '#00ff94', 0),
    'PortScan':                 ('HIGH',     '#ff6b35', 3),
    'DoS Slowhttptest':         ('MEDIUM',   '#ffb800', 2),
    'DoS slowloris':            ('MEDIUM',   '#ffb800', 2),
    'DoS GoldenEye':            ('HIGH',     '#ff6b35', 3),
    'DoS Hulk':                 ('HIGH',     '#ff6b35', 3),
    'FTP-Patator':              ('HIGH',     '#ff6b35', 3),
    'SSH-Patator':              ('HIGH',     '#ff6b35', 3),
    'Web Attack Brute Force':   ('HIGH',     '#ff6b35', 3),
    'Web Attack XSS':           ('HIGH',     '#ff6b35', 3),
    'Web Attack Sql Injection': ('CRITICAL', '#ff3e5f', 4),
    'Bot':                      ('CRITICAL', '#ff3e5f', 4),
    'DDoS':                     ('CRITICAL', '#ff3e5f', 4),
    'Heartbleed':               ('CRITICAL', '#ff3e5f', 4),
    'Infiltration':             ('CRITICAL', '#ff3e5f', 4),
    'Suspicious C2':            ('MEDIUM',   '#ffb800', 2),
    'Malicious C2':             ('CRITICAL', '#ff3e5f', 4),
}

SEVERITY_NUM = {'SAFE': 1, 'MEDIUM': 5, 'HIGH': 7, 'CRITICAL': 10, 'UNKNOWN': 3}
SEVERITY_RANK = {'SAFE': 0, 'UNKNOWN': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

MITRE_MAPPING = {
    'PortScan':                 {'id':'T1046','name':'Network Service Discovery','tactic':'Discovery'},
    'DoS Slowhttptest':         {'id':'T1499','name':'Endpoint Denial of Service','tactic':'Impact'},
    'DoS slowloris':            {'id':'T1499','name':'Endpoint Denial of Service','tactic':'Impact'},
    'DoS GoldenEye':            {'id':'T1499','name':'Endpoint Denial of Service','tactic':'Impact'},
    'DoS Hulk':                 {'id':'T1499','name':'Endpoint Denial of Service','tactic':'Impact'},
    'DDoS':                     {'id':'T1498','name':'Network Denial of Service','tactic':'Impact'},
    'FTP-Patator':              {'id':'T1110','name':'Brute Force','tactic':'Credential Access'},
    'SSH-Patator':              {'id':'T1110','name':'Brute Force','tactic':'Credential Access'},
    'Web Attack Brute Force':   {'id':'T1110','name':'Brute Force','tactic':'Credential Access'},
    'Web Attack XSS':           {'id':'T1059','name':'Command and Scripting Interpreter','tactic':'Execution'},
    'Web Attack Sql Injection': {'id':'T1190','name':'Exploit Public-Facing Application','tactic':'Initial Access'},
    'Bot':                      {'id':'T1071','name':'Application Layer Protocol','tactic':'Command and Control'},
    'Heartbleed':               {'id':'T1190','name':'Exploit Public-Facing Application','tactic':'Initial Access'},
    'Infiltration':             {'id':'T1078','name':'Valid Accounts','tactic':'Defense Evasion'},
}

ATTACK_DEFINITIONS = {
    'PortScan':                 'A port scan is when an attacker sends packets to many different ports on a target to discover which services are listening and potentially vulnerable.',
    'DDoS':                     'A Distributed Denial of Service attack floods a target with traffic from many different machines simultaneously, making the service unavailable to legitimate users.',
    'DoS Hulk':                 'DoS Hulk is a script-based HTTP flood that generates a large volume of unique HTTP GET requests to exhaust web server resources and bypass caching.',
    'DoS GoldenEye':            'DoS GoldenEye targets HTTP keep-alive connections, keeping many connections open to exhaust the server\'s connection pool.',
    'DoS slowloris':            'Slowloris sends partial HTTP requests slowly, keeping many connections open without completing them, exhausting the server\'s connection limit.',
    'DoS Slowhttptest':         'A slow HTTP attack that tests server limits by sending data at a very slow rate, tying up server threads waiting for the request to complete.',
    'FTP-Patator':              'FTP-Patator is a brute-force tool that systematically tries many username and password combinations to gain unauthorized access to an FTP server.',
    'SSH-Patator':              'SSH-Patator is a brute-force tool that repeatedly attempts to log into an SSH server using many different credential combinations.',
    'Web Attack Brute Force':   'A brute-force attack against a web application login page, automatically trying many password combinations until access is gained.',
    'Web Attack XSS':           'Cross-Site Scripting (XSS) injects malicious scripts into a web page, which then execute in the victim\'s browser to steal data or hijack sessions.',
    'Web Attack Sql Injection': 'SQL Injection inserts malicious SQL code into input fields to manipulate the database, potentially extracting, modifying, or deleting sensitive data.',
    'Bot':                      'Botnet traffic indicates a compromised host is communicating with a command-and-control server and is being used for malicious activity such as spam or further attacks.',
    'Heartbleed':               'Heartbleed (CVE-2014-0160) exploits a bug in the OpenSSL library that allows an attacker to read memory from the server, potentially exposing passwords and private keys.',
    'Infiltration':             'An infiltration event means an attacker has bypassed the network perimeter and is now operating inside the network, posing a high risk of data exfiltration.',
}

ATTACK_WHY_FLAGGED = {
    'PortScan':                 'The model detected a high number of unique destination ports with very short flow durations and minimal data transfer — a pattern consistent with automated port scanning.',
    'DDoS':                     'The model found an extremely high packet rate, many source IPs converging on a single destination, and abnormally large total flow volume — classic DDoS characteristics.',
    'DoS Hulk':                 'The model detected a large volume of HTTP flows with high packet counts, rapidly varying request patterns, and no normal server response timing — matching the Hulk flood signature.',
    'DoS GoldenEye':            'The model identified long-lived HTTP connections with low data rate and keep-alive headers, consistent with the GoldenEye connection-exhaustion technique.',
    'DoS slowloris':            'The model detected many slow, incomplete connections with abnormally low bytes-per-second — a strong indicator of the Slowloris partial-request attack.',
    'DoS Slowhttptest':         'The model found flows with unusually slow data transfer rates and long connection durations consistent with a slow HTTP attack probing server timeout limits.',
    'FTP-Patator':              'The model detected repeated short-lived FTP connections from the same source IP with rapid retries and varying credentials — a clear brute-force pattern.',
    'SSH-Patator':              'The model identified a high rate of SSH connection attempts from one IP, each failing quickly, which is characteristic of automated SSH credential brute-forcing.',
    'Web Attack Brute Force':   'The model detected repetitive web requests with varying payloads, consistent response failure codes, and high request frequency — all signs of an automated login attack.',
    'Web Attack XSS':           'The model flagged flows with abnormal HTTP payload lengths and unusual character patterns in request fields commonly targeted by script injection.',
    'Web Attack Sql Injection': 'The model detected flows with abnormal query string patterns and response sizes that match known SQL injection traffic signatures.',
    'Bot':                      'The model identified periodic, regular communication flows to external IPs with consistent timing intervals — a hallmark of botnet command-and-control heartbeat traffic.',
    'Heartbleed':               'The model detected malformed TLS heartbeat requests with response sizes far exceeding the request — the exact pattern of the Heartbleed memory-leak exploit.',
    'Infiltration':             'The model flagged unusual internal-to-external communication patterns and lateral movement indicators consistent with an attacker already operating inside the network.',
}

ATTACK_DEFINITIONS_AR = {
    'PortScan':                 'الفحص الشبكي هو عندما يرسل المهاجم حزمًا إلى منافذ مختلفة على هدف معين لاكتشاف الخدمات المفتوحة والثغرات المحتملة.',
    'DDoS':                     'هجوم الحرمان الموزع من الخدمة يُغرق الهدف بحركة مرور من أجهزة متعددة في آنٍ واحد، مما يجعل الخدمة غير متاحة للمستخدمين الشرعيين.',
    'DoS Hulk':                 'DoS Hulk هجوم فيضان HTTP يُولّد حجمًا كبيرًا من طلبات GET الفريدة لاستنزاف موارد خادم الويب وتجاوز التخزين المؤقت.',
    'DoS GoldenEye':            'DoS GoldenEye يستهدف اتصالات HTTP المستمرة (keep-alive)، إذ يبقي عددًا كبيرًا من الاتصالات مفتوحة لاستنزاف مجموعة اتصالات الخادم.',
    'DoS slowloris':            'Slowloris يرسل طلبات HTTP جزئية ببطء، مبقيًا اتصالات عديدة مفتوحة دون إكمالها، مما يستنزف حد اتصالات الخادم.',
    'DoS Slowhttptest':         'هجوم HTTP بطيء يختبر حدود الخادم بإرسال البيانات بمعدل بطيء جدًا، مما يشغل خيوط الخادم في انتظار اكتمال الطلب.',
    'FTP-Patator':              'FTP-Patator أداة قوة غاشمة تُجرّب مجموعات عديدة من أسماء المستخدمين وكلمات المرور للوصول غير المصرح به إلى خادم FTP.',
    'SSH-Patator':              'SSH-Patator أداة قوة غاشمة تُكرر محاولات تسجيل الدخول إلى خادم SSH باستخدام مجموعات بيانات اعتماد متعددة.',
    'Web Attack Brute Force':   'هجوم قوة غاشمة على صفحة تسجيل الدخول في تطبيق ويب، يُجرّب تلقائيًا مجموعات كثيرة من كلمات المرور حتى يتحقق الوصول.',
    'Web Attack XSS':           'البرمجة النصية عبر المواقع (XSS) تُدرج سكريبتات خبيثة في صفحة ويب تُنفَّذ في متصفح الضحية لسرقة البيانات أو اختطاف الجلسات.',
    'Web Attack Sql Injection': 'حقن SQL يُدرج كودًا SQL خبيثًا في حقول الإدخال للتلاعب بقاعدة البيانات، مما قد يؤدي إلى استخراج أو تعديل أو حذف البيانات الحساسة.',
    'Bot':                      'حركة مرور الشبكة الروبوتية تُشير إلى أن جهازًا مخترقًا يتواصل مع خادم القيادة والتحكم ويُستخدم في نشاط خبيث كإرسال الرسائل المزعجة أو شنّ هجمات أخرى.',
    'Heartbleed':               'Heartbleed (CVE-2014-0160) يستغل ثغرة في مكتبة OpenSSL تتيح للمهاجم قراءة الذاكرة من الخادم، مما قد يكشف كلمات المرور والمفاتيح الخاصة.',
    'Infiltration':             'حدث التسلل يعني أن المهاجم اخترق المحيط الأمني للشبكة وبات يعمل داخلها، مما يُشكّل خطرًا عاليًا لتسريب البيانات.',
}

ATTACK_WHY_FLAGGED_AR = {
    'PortScan':                 'اكتشف النموذج عددًا كبيرًا من منافذ الوجهة الفريدة مع مدد تدفق قصيرة جدًا ونقل بيانات ضئيل — نمط يتوافق مع الفحص الشبكي الآلي.',
    'DDoS':                     'رصد النموذج معدل حزم مرتفعًا للغاية وعناوين IP مصدر متعددة تتقارب نحو وجهة واحدة وحجم تدفق إجمالي شاذ — خصائص كلاسيكية لهجوم DDoS.',
    'DoS Hulk':                 'اكتشف النموذج حجمًا كبيرًا من تدفقات HTTP ذات أعداد حزم عالية وأنماط طلبات متغيرة بسرعة وغياب توقيت استجابة طبيعي من الخادم — يطابق بصمة فيضان Hulk.',
    'DoS GoldenEye':            'حدّد النموذج اتصالات HTTP طويلة الأمد ذات معدل بيانات منخفض ورؤوس keep-alive، يتوافق مع تقنية استنزاف الاتصالات لـ GoldenEye.',
    'DoS slowloris':            'رصد النموذج اتصالات كثيرة بطيئة وغير مكتملة مع معدل بايت/ثانية منخفض بشكل شاذ — مؤشر قوي لهجوم الطلبات الجزئية Slowloris.',
    'DoS Slowhttptest':         'عثر النموذج على تدفقات ذات معدلات نقل بيانات بطيئة غير عادية ومدد اتصال طويلة، يتوافق مع هجوم HTTP بطيء يختبر حدود مهلة الخادم.',
    'FTP-Patator':              'اكتشف النموذج اتصالات FTP قصيرة متكررة من نفس IP المصدر مع محاولات إعادة سريعة وبيانات اعتماد متغيرة — نمط قوة غاشمة واضح.',
    'SSH-Patator':              'حدّد النموذج معدلًا عاليًا من محاولات الاتصال بـ SSH من عنوان IP واحد تفشل كل منها بسرعة — سمة مميزة لاختراق بيانات اعتماد SSH الآلي.',
    'Web Attack Brute Force':   'رصد النموذج طلبات ويب متكررة بحمولات متغيرة ورموز فشل استجابة متسقة وتردد عالٍ للطلبات — كلها علامات هجوم تسجيل دخول آلي.',
    'Web Attack XSS':           'صنّف النموذج تدفقات ذات أطوال حمولة HTTP شاذة وأنماط أحرف غير معتادة في حقول الطلب المستهدفة بحقن السكريبت.',
    'Web Attack Sql Injection': 'اكتشف النموذج تدفقات ذات أنماط سلاسل استعلام شاذة وأحجام استجابة تطابق بصمات حركة مرور حقن SQL المعروفة.',
    'Bot':                      'حدّد النموذج تدفقات اتصال دورية منتظمة إلى عناوين IP خارجية بفواصل زمنية متسقة — سمة مميزة لحركة النبضات بين الروبوت وخادم القيادة والتحكم.',
    'Heartbleed':               'رصد النموذج طلبات TLS heartbeat مشوّهة بأحجام استجابة تتجاوز بكثير حجم الطلب — النمط الدقيق لاستغلال تسريب الذاكرة Heartbleed.',
    'Infiltration':             'صنّف النموذج أنماط اتصال داخلية-خارجية غير معتادة ومؤشرات حركة جانبية تتوافق مع مهاجم يعمل داخل الشبكة بالفعل.',
}

def get_attack_info(label):
    """Return (definition, why_flagged) for a given attack label, with fuzzy matching."""
    lang = session.get('lang', 'en')
    defs = ATTACK_DEFINITIONS_AR if lang == 'ar' else ATTACK_DEFINITIONS
    why  = ATTACK_WHY_FLAGGED_AR  if lang == 'ar' else ATTACK_WHY_FLAGGED
    for k in defs:
        if k.lower() in label.lower() or label.lower() in k.lower():
            return defs[k], why.get(k, '')
    return None, None

def get_mitre(label):
    for k, v in MITRE_MAPPING.items():
        if k.lower() in label.lower() or label.lower() in k.lower():
            return v
    return None

def clean_label(s):
    """Normalize raw label strings from the model/encoder for display."""
    s = str(s).replace('\ufffd','').replace('\x96','').replace('—','').replace('–','')
    return ' '.join(s.split())

def get_severity(label):
    def _norm(s):
        return s.replace('\x96','').replace('—','').replace('–','').replace('-',' ').replace('  ',' ').strip().lower()
    norm_label = _norm(label)
    for key, val in SEVERITY.items():
        if _norm(key) in norm_label or norm_label in _norm(key):
            return val
    return ('UNKNOWN', '#8899bb', 1)

# ── IP/Port column detection ──────────────────────────────────────────────────
_META_VARIANTS = {
    'src_ip':   [' Source IP','Source IP','Src IP','src_ip','SrcIP'],
    'dst_ip':   [' Destination IP','Destination IP','Dst IP','dst_ip','DstIP'],
    'src_port': [' Source Port','Source Port','Src Port','src_port','SrcPort'],
    'dst_port': [' Destination Port','Destination Port','Dst Port','dst_port','DstPort'],
    'protocol': [' Protocol','Protocol','protocol'],
}

def find_meta_cols(df):
    cols = set(df.columns)
    return {k: next((v for v in variants if v in cols), None)
            for k, variants in _META_VARIANTS.items()}

# ── PCAP → Flow feature extractor ─────────────────────────────────────────────
def pcap_to_flows_df(pcap_path):
    """Convert a PCAP/PCAPNG file to a DataFrame matching all CIC-IDS2017 features."""
    from scapy.all import PcapReader
    from scapy.layers.inet import IP, TCP, UDP
    from collections import defaultdict

    def _new_flow():
        return {
            'fwd_lens': [], 'bwd_lens': [],
            'fwd_times': [], 'bwd_times': [],
            'fwd_hdr': 0, 'bwd_hdr': 0,
            'fwd_payload': [], 'bwd_payload': [],
            'all_times': [],
            'init_fwd_win': 0, 'init_bwd_win': 0,
            'src_ip': '', 'dst_ip': '',
            'src_port': 0, 'dst_port': 0, 'protocol': 0,
            # TCP flag counters
            'fin_fwd': 0, 'fin_bwd': 0,
            'syn_fwd': 0, 'syn_bwd': 0,
            'rst_fwd': 0, 'rst_bwd': 0,
            'psh_fwd': 0, 'psh_bwd': 0,
            'ack_fwd': 0, 'ack_bwd': 0,
            'urg_fwd': 0, 'urg_bwd': 0,
            'cwe_fwd': 0, 'cwe_bwd': 0,
            'ece_fwd': 0, 'ece_bwd': 0,
            'min_seg_fwd': 999999,
        }

    flows = defaultdict(_new_flow)
    established = set()

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            proto = ip.proto
            pkt_len = ip.len

            flags = 0
            win = 0
            if pkt.haslayer(TCP):
                l4 = pkt[TCP]
                sport, dport = l4.sport, l4.dport
                ip_hdr  = ip.ihl * 4
                tcp_hdr = l4.dataofs * 4
                hdr_len = ip_hdr + tcp_hdr
                payload = max(0, pkt_len - hdr_len)
                win = l4.window
                flags = int(l4.flags)
            elif pkt.haslayer(UDP):
                l4 = pkt[UDP]
                sport, dport = l4.sport, l4.dport
                hdr_len = ip.ihl * 4 + 8
                payload = max(0, pkt_len - hdr_len)
            else:
                continue

            ts = float(pkt.time)
            fwd_key = (ip.src, ip.dst, sport, dport, proto)
            bwd_key = (ip.dst, ip.src, dport, sport, proto)

            if fwd_key in flows or fwd_key in established:
                key, direction = fwd_key, 'fwd'
            elif bwd_key in flows or bwd_key in established:
                key, direction = bwd_key, 'bwd'
            else:
                key, direction = fwd_key, 'fwd'
                flows[key]['src_ip']   = ip.src
                flows[key]['dst_ip']   = ip.dst
                flows[key]['src_port'] = sport
                flows[key]['dst_port'] = dport
                flows[key]['protocol'] = proto
                established.add(fwd_key)

            f = flows[key]
            f['all_times'].append(ts)

            # Flag accounting
            fin = 1 if flags & 0x01 else 0
            syn = 1 if flags & 0x02 else 0
            rst = 1 if flags & 0x04 else 0
            psh = 1 if flags & 0x08 else 0
            ack = 1 if flags & 0x10 else 0
            urg = 1 if flags & 0x20 else 0
            ece = 1 if flags & 0x40 else 0
            cwe = 1 if flags & 0x80 else 0

            if direction == 'fwd':
                f['fwd_lens'].append(payload)
                f['fwd_times'].append(ts)
                f['fwd_hdr'] += hdr_len
                f['fwd_payload'].append(payload)
                f['fin_fwd'] += fin; f['syn_fwd'] += syn; f['rst_fwd'] += rst
                f['psh_fwd'] += psh; f['ack_fwd'] += ack; f['urg_fwd'] += urg
                f['ece_fwd'] += ece; f['cwe_fwd'] += cwe
                if f['init_fwd_win'] == 0 and win > 0:
                    f['init_fwd_win'] = win
                if payload > 0:
                    f['min_seg_fwd'] = min(f['min_seg_fwd'], payload)
            else:
                f['bwd_lens'].append(payload)
                f['bwd_times'].append(ts)
                f['bwd_hdr'] += hdr_len
                f['bwd_payload'].append(payload)
                f['fin_bwd'] += fin; f['syn_bwd'] += syn; f['rst_bwd'] += rst
                f['psh_bwd'] += psh; f['ack_bwd'] += ack; f['urg_bwd'] += urg
                f['ece_bwd'] += ece; f['cwe_bwd'] += cwe
                if f['init_bwd_win'] == 0 and win > 0:
                    f['init_bwd_win'] = win

    records = []
    for key, f in flows.items():
        fwd = np.array(f['fwd_lens'], dtype=float) if f['fwd_lens'] else np.array([0.0])
        bwd = np.array(f['bwd_lens'], dtype=float) if f['bwd_lens'] else np.array([0.0])
        all_pkts = np.concatenate([fwd, bwd])

        fwd_times = sorted(f['fwd_times'])
        bwd_times = sorted(f['bwd_times'])
        all_times = sorted(f['all_times'])

        fwd_iat  = np.diff(fwd_times) * 1_000_000 if len(fwd_times) > 1 else np.array([0.0])
        bwd_iat  = np.diff(bwd_times) * 1_000_000 if len(bwd_times) > 1 else np.array([0.0])
        flow_iat = np.diff(all_times) * 1_000_000 if len(all_times) > 1 else np.array([0.0])

        duration = (all_times[-1] - all_times[0]) if len(all_times) > 1 else 1e-9
        if duration <= 0:
            duration = 1e-9

        total_fwd  = len(f['fwd_lens'])
        total_bwd  = len(f['bwd_lens'])
        total_pkts = total_fwd + total_bwd
        fwd_bytes  = int(fwd.sum())
        bwd_bytes  = int(bwd.sum())
        total_bytes = fwd_bytes + bwd_bytes
        fwd_act    = sum(1 for p in f['fwd_payload'] if p > 0)
        min_seg    = f['min_seg_fwd'] if f['min_seg_fwd'] < 999999 else 0

        down_up = (total_bwd / total_fwd) if total_fwd > 0 else 0.0

        # Active/Idle periods (CIC-IDS2017 uses 5-second idle threshold)
        active_periods = []
        idle_periods = []
        if len(flow_iat) > 0:
            idle_threshold = 5_000_000  # 5 seconds in microseconds
            active_start = 0.0
            for iat_val in flow_iat:
                if iat_val > idle_threshold:
                    if active_start > 0:
                        active_periods.append(active_start)
                    idle_periods.append(float(iat_val))
                    active_start = 0.0
                else:
                    active_start += float(iat_val)
            if active_start > 0:
                active_periods.append(active_start)
        if not active_periods:
            active_periods = [duration * 1_000_000]

        records.append({
            'src_ip':   f['src_ip'],   'dst_ip':   f['dst_ip'],
            'src_port': f['src_port'], 'dst_port': f['dst_port'],
            # ── exact CIC-IDS2017 column names ──────────────────
            'Protocol':                 f['protocol'],
            'Destination Port':         f['dst_port'],
            # Duration & rates
            'Flow Duration':            duration * 1_000_000,
            'Flow Bytes/s':             total_bytes / duration,
            'Flow Packets/s':           total_pkts / duration,
            'Fwd Packets/s':            total_fwd / duration,
            'Bwd Packets/s':            total_bwd / duration,
            # Packet counts
            'Total Fwd Packets':        total_fwd,
            'Total Backward Packets':   total_bwd,
            'Subflow Fwd Packets':      total_fwd,
            'Subflow Bwd Packets':      total_bwd,
            # Fwd length stats
            'Total Length of Fwd Packets': fwd_bytes,
            'Subflow Fwd Bytes':        fwd_bytes,
            'Fwd Packet Length Max':    float(fwd.max()),
            'Fwd Packet Length Min':    float(fwd.min()),
            'Fwd Packet Length Mean':   float(fwd.mean()),
            'Fwd Packet Length Std':    float(fwd.std()),
            'Avg Fwd Segment Size':     float(fwd.mean()),
            # Bwd length stats
            'Total Length of Bwd Packets': bwd_bytes,
            'Subflow Bwd Bytes':        bwd_bytes,
            'Bwd Packet Length Max':    float(bwd.max()),
            'Bwd Packet Length Min':    float(bwd.min()),
            'Bwd Packet Length Mean':   float(bwd.mean()),
            'Bwd Packet Length Std':    float(bwd.std()),
            'Avg Bwd Segment Size':     float(bwd.mean()),
            # All-packet stats
            'Min Packet Length':        float(all_pkts.min()),
            'Max Packet Length':        float(all_pkts.max()),
            'Packet Length Mean':       float(all_pkts.mean()),
            'Packet Length Std':        float(all_pkts.std()),
            'Packet Length Variance':   float(all_pkts.var()),
            'Average Packet Size':      float(all_pkts.mean()),
            # Flow IAT
            'Flow IAT Mean':            float(flow_iat.mean()),
            'Flow IAT Std':             float(flow_iat.std()),
            'Flow IAT Max':             float(flow_iat.max()),
            'Flow IAT Min':             float(flow_iat.min()),
            # Fwd IAT
            'Fwd IAT Total':            float(fwd_iat.sum()),
            'Fwd IAT Mean':             float(fwd_iat.mean()),
            'Fwd IAT Std':              float(fwd_iat.std()),
            'Fwd IAT Max':              float(fwd_iat.max()),
            'Fwd IAT Min':              float(fwd_iat.min()),
            # Bwd IAT
            'Bwd IAT Total':            float(bwd_iat.sum()),
            'Bwd IAT Mean':             float(bwd_iat.mean()),
            'Bwd IAT Std':              float(bwd_iat.std()),
            'Bwd IAT Max':              float(bwd_iat.max()),
            'Bwd IAT Min':              float(bwd_iat.min()),
            # Header lengths
            'Fwd Header Length':        f['fwd_hdr'],
            'Fwd Header Length.1':      f['fwd_hdr'],
            'Bwd Header Length':        f['bwd_hdr'],
            # TCP flags
            'FIN Flag Count':           f['fin_fwd'] + f['fin_bwd'],
            'SYN Flag Count':           f['syn_fwd'] + f['syn_bwd'],
            'RST Flag Count':           f['rst_fwd'] + f['rst_bwd'],
            'PSH Flag Count':           f['psh_fwd'] + f['psh_bwd'],
            'ACK Flag Count':           f['ack_fwd'] + f['ack_bwd'],
            'URG Flag Count':           f['urg_fwd'] + f['urg_bwd'],
            'CWE Flag Count':           f['cwe_fwd'] + f['cwe_bwd'],
            'ECE Flag Count':           f['ece_fwd'] + f['ece_bwd'],
            'Fwd PSH Flags':            f['psh_fwd'],
            'Bwd PSH Flags':            f['psh_bwd'],
            'Fwd URG Flags':            f['urg_fwd'],
            'Bwd URG Flags':            f['urg_bwd'],
            # Window & segment
            'Init_Win_bytes_forward':   f['init_fwd_win'],
            'Init_Win_bytes_backward':  f['init_bwd_win'],
            'min_seg_size_forward':     min_seg,
            # Other
            'Down/Up Ratio':            down_up,
            'act_data_pkt_fwd':         fwd_act,
            # Active/Idle (threshold = 5 seconds = 5_000_000 µs)
            'Active Mean':              float(np.mean(active_periods)) if active_periods else 0.0,
            'Active Std':               float(np.std(active_periods)) if len(active_periods) > 1 else 0.0,
            'Active Max':               float(np.max(active_periods)) if active_periods else 0.0,
            'Active Min':               float(np.min(active_periods)) if active_periods else 0.0,
            'Idle Mean':                float(np.mean(idle_periods)) if idle_periods else 0.0,
            'Idle Std':                 float(np.std(idle_periods)) if len(idle_periods) > 1 else 0.0,
            'Idle Max':                 float(np.max(idle_periods)) if idle_periods else 0.0,
            'Idle Min':                 float(np.min(idle_periods)) if idle_periods else 0.0,
        })

    if not records:
        raise ValueError('No IP/TCP/UDP flows found in PCAP file.')
    return pd.DataFrame(records)

# ── Model loading ─────────────────────────────────────────────────────────────
model = preprocessor = label_encoder = feature_names = None
model_error = None
_MODEL_LOCK = threading.Lock()

class ThresholdClassifier:
    """
    Wraps a predict_proba model with per-class probability scale factors.
    Defined here so joblib can unpickle best_model.pkl when it is a
    ThresholdClassifier produced by the training pipeline.
    """
    def __init__(self, base_model, scales, int_classes):
        self.base_model = base_model
        self.scales     = np.asarray(scales, dtype=float)
        self.classes_   = int_classes

    def predict(self, X):
        proba  = self.base_model.predict_proba(X)
        scaled = proba / self.scales
        return self.classes_[np.argmax(scaled, axis=1)]

    def predict_proba(self, X):
        return self.base_model.predict_proba(X)


import sys as _sys
# Register ThresholdClassifier in __main__ so joblib can unpickle models
# that were originally saved from main.py (where the class was in __main__)
if not hasattr(_sys.modules.get('__main__', None), 'ThresholdClassifier'):
    _sys.modules['__main__'].ThresholdClassifier = ThresholdClassifier

def load_models():
    global model, preprocessor, label_encoder, feature_names, model_error
    with _MODEL_LOCK:
        try:
            model         = joblib.load(MODELS_DIR / 'best_model.pkl')
            preprocessor  = joblib.load(MODELS_DIR / 'preprocessor.pkl')
            label_encoder = joblib.load(MODELS_DIR / 'label_encoder.pkl')
            feature_names = joblib.load(MODELS_DIR / 'feature_names.pkl')
            model_error   = None
            print('[BASTION] Models loaded OK')
        except Exception as e:
            model = preprocessor = label_encoder = feature_names = None
            model_error = str(e)
            print(f'[BASTION] Model error: {e}')

load_models()

# ── CICFlowMeter integration (Python package) ─────────────────────────────────
def cicflowmeter_available():
    """Return True if the cicflowmeter Python package is installed."""
    try:
        import cicflowmeter  # noqa
        return True
    except ImportError:
        return False

def pcap_to_flows_cicflowmeter(pcap_path: Path) -> pd.DataFrame:
    """
    Use the cicflowmeter Python API to convert a PCAP to a flow DataFrame.
    Bypasses the buggy CLI and calls the sniffer directly.
    """
    import tempfile
    from cicflowmeter.sniffer import create_sniffer
    fd, _out_csv_str = tempfile.mkstemp(suffix='.csv')
    os.close(fd)
    out_csv = Path(_out_csv_str)
    try:
        sniffer, _flow_session = create_sniffer(
            input_file=str(pcap_path),
            input_interface=None,
            input_directory=None,
            output_mode='csv',
            output=str(out_csv),
            fields=None,
            verbose=False,
        )
        sniffer.start()
        sniffer.join(timeout=300)
        if not out_csv.exists():
            raise ValueError('cicflowmeter produced no output file')
        df = pd.read_csv(out_csv)
        df.columns = df.columns.str.strip()
        return df
    finally:
        out_csv.unlink(missing_ok=True)

# ── Rule-based detection engine (fallback for PCAP flows) ────────────────────
# Thresholds calibrated against CIC-IDS2017 feature distributions.
# These rules fire when the ML model says BENIGN but flow patterns match
# known attack signatures.  Ordered by specificity (most specific first).
# IMPORTANT: order matters — first match wins.  Port-specific rules MUST
#            come before generic rules like portscan.
_RULE_THRESHOLDS_LIST = [
    # 1. FTP-Patator: port 21 brute force — needs actual FTP command exchange.
    ('ftp_patator',  [('Destination Port', '==', 21), ('Protocol', '==', 6),
                      ('Total Fwd Packets', '>=', 3),
                      ('PSH Flag Count', '>=', 2),
                      ('Fwd Packet Length Max', '>=', 5)]),
    # 2. SSH-Patator: port 22 with meaningful payload exchange.
    ('ssh_patator',  [('Destination Port', '==', 22), ('Protocol', '==', 6),
                      ('Total Fwd Packets', '>=', 5),
                      ('Total Backward Packets', '>=', 3),
                      ('Fwd Packet Length Max', '>=', 80)]),
    # 3. Bot: C2 beacon on port 8000-9000, tiny beacon payload, minimum duration.
    ('bot',          [('Destination Port', '>=', 8000), ('Destination Port', '<=', 9000),
                      ('Protocol', '==', 6),
                      ('Total Fwd Packets', '>=', 2), ('Total Fwd Packets', '<=', 6),
                      ('Total Backward Packets', '>=', 1), ('Total Backward Packets', '<=', 5),
                      ('Fwd Packet Length Max', '>=', 3),
                      ('Fwd Packet Length Max', '<=', 20),
                      ('Flow Duration', '>=', 10_000)]),
    # 4. DDoS (SYN flood): many SYN flags, sustained packet rate, no bwd.
    ('ddos',         [('SYN Flag Count', '>=', 5),
                      ('Total Backward Packets', '<=', 2),
                      ('Total Fwd Packets', '>=', 5),
                      ('Flow Packets/s', '>=', 20)]),
    # 5. DDoS (distributed HTTP): port 80 with low Init_Win (attack-tool
    #    signature) but FEW packets per flow — characteristic of a distributed
    #    flood where each source contributes a handful of requests. Must come
    #    before dos_hulk so dos_hulk only catches single-source floods.
    ('ddos_http',    [('Destination Port', '==', 80), ('Protocol', '==', 6),
                      ('Init_Win_bytes_forward', '>=', 100),
                      ('Init_Win_bytes_forward', '<=', 1000),
                      ('Total Fwd Packets', '>=', 3),
                      ('Total Fwd Packets', '<=', 30)]),
    # 6. DoS Hulk (single-source HTTP flood): Init_Win ~256 + HIGH packet count
    #    (>=30 fwd) + sustained rate. MUST come before web_brute so the
    #    attack-tool window signature wins over generic PSH-heavy HTTP.
    ('dos_hulk',     [('Destination Port', '==', 80), ('Protocol', '==', 6),
                      ('Init_Win_bytes_forward', '>=', 200),
                      ('Init_Win_bytes_forward', '<=', 300),
                      ('Total Fwd Packets', '>=', 30),
                      ('Flow Packets/s', '>=', 20)]),
    # 7. Web brute force: port 80, many repeated HTTP requests, from a *normal*
    #    client (Init_Win > 1000 excludes attack-tool signatures).
    ('web_brute',    [('Destination Port', '==', 80), ('Protocol', '==', 6),
                      ('Init_Win_bytes_forward', '>=', 1000),
                      ('PSH Flag Count', '>=', 8),
                      ('Total Fwd Packets', '>=', 8),
                      ('Total Backward Packets', '<=', 3)]),
    # 7. DoS slowloris: port 80, tiny fwd payloads, *long* duration (>=10s).
    ('dos_slowloris',[('Destination Port', '==', 80), ('Protocol', '==', 6),
                      ('Fwd Packet Length Max', '>=', 1),
                      ('Fwd Packet Length Max', '<=', 50),
                      ('Total Fwd Packets', '>=', 4),
                      ('Total Backward Packets', '<=', 2),
                      ('Bwd Packet Length Max', '<=', 0),
                      ('Flow Duration', '>=', 10_000_000)]),
    # 8. DoS GoldenEye: Init_Win ~29200 + large fwd payload + min duration.
    ('dos_goldeneye',[('Destination Port', '==', 80), ('Protocol', '==', 6),
                      ('Init_Win_bytes_forward', '>=', 29000),
                      ('Init_Win_bytes_forward', '<=', 30000),
                      ('Total Fwd Packets', '>=', 5),
                      ('Fwd Packet Length Max', '>=', 300),
                      ('Flow Duration', '>=', 1_000_000)]),
    # 9. DoS Slowhttptest: port 80, long duration, fwd-only.
    ('dos_slowhttp', [('Destination Port', '==', 80), ('Protocol', '==', 6),
                      ('Flow Duration',    '>',  10_000_000),
                      ('Total Backward Packets', '==', 0),
                      ('Total Fwd Packets', '>=', 3)]),
    # 10. PortScan: SYN probe — 1-2 packets, zero payload on fwd.
    ('portscan',     [('Total Fwd Packets','<=', 2),
                      ('SYN Flag Count', '>=', 1),
                      ('Total Backward Packets', '<=', 2),
                      ('Fwd Packet Length Max', '<=', 0),
                      ('Total Length of Fwd Packets', '<=', 0)]),
]

_RULE_LABELS = {
    'ddos':          ('DDoS',                          90.0, 'CRITICAL'),
    'ddos_http':     ('DDoS',                          88.0, 'CRITICAL'),
    'dos_hulk':      ('DoS Hulk',                      85.0, 'HIGH'),
    'dos_goldeneye': ('DoS GoldenEye',                 85.0, 'HIGH'),
    'dos_slowloris': ('DoS slowloris',                 82.0, 'MEDIUM'),
    'dos_slowhttp':  ('DoS Slowhttptest',               82.0, 'MEDIUM'),
    'portscan':      ('PortScan',                       88.0, 'HIGH'),
    'ssh_patator':   ('SSH-Patator',                    85.0, 'HIGH'),
    'ftp_patator':   ('FTP-Patator',                    85.0, 'HIGH'),
    'web_brute':     ('Web Attack Brute Force',         80.0, 'HIGH'),
    'bot':           ('Bot',                            82.0, 'HIGH'),
}

def _rule_check(row: dict, conditions: list) -> bool:
    """Return True if all rule conditions match."""
    ops = {'>': float.__gt__, '<': float.__lt__,
           '>=': float.__ge__, '<=': float.__le__, '==': float.__eq__}
    for feat, op, thresh in conditions:
        val = row.get(feat, 0)
        try:
            if not ops[op](float(val), float(thresh)):
                return False
        except (TypeError, ValueError):
            return False
    return True

def rule_based_label(row: dict):
    """
    Apply rule engine to a flow dict (using raw feature values, not scaled).
    Returns (label, confidence, severity) or None if no rule fires.
    Uses ordered list so port-specific rules fire before generic ones.
    """
    for rule_name, conditions in _RULE_THRESHOLDS_LIST:
        if _rule_check(row, conditions):
            label, conf, sev = _RULE_LABELS[rule_name]
            return label, conf, sev
    return None

# Well-known benign service ports. A Bot classification on these is almost
# always a false positive; the ML was trained on CIC-IDS2017 where a few
# attacks rode these ports, so it over-associates them.
_BENIGN_SERVICE_PORTS = frozenset({
    21, 22, 25, 53, 80, 88, 123, 135, 137, 138, 139, 143, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 3268, 3389, 5353,
})

def ml_sanity_check(label: str, conf: float, row: dict):
    """
    Suppress obvious ML false positives. Demotes a flow to BENIGN when its
    shape contradicts the claimed attack pattern. Returns (label, conf, demoted).

    Runs AFTER the ML prediction and BEFORE the rule engine, so a wrongly
    demoted genuine attack can still be recovered by a rule match.
    """
    label_upper = label.upper().replace('-', ' ').strip()
    total_fwd = row.get('Total Fwd Packets', 0)
    total_bwd = row.get('Total Backward Packets', 0)
    fwd_bytes = row.get('Total Length of Fwd Packets', 0)
    bwd_bytes = row.get('Total Length of Bwd Packets', 0)
    fwd_max   = row.get('Fwd Packet Length Max', 0)
    dst_port  = int(row.get('Destination Port', 0) or 0)

    # DDoS: only demote when the flow has zero attack indicators AND looks
    # like a normal conversation. DDoS-characteristic signals (anomalously
    # low Init_Win, SYN flood, high packet rate, lopsided many-packet flow)
    # keep the ML label.
    if label_upper == 'DDOS':
        init_win = row.get('Init_Win_bytes_forward', 0)
        syn_count = row.get('SYN Flag Count', 0)
        flow_pps = row.get('Flow Packets/s', 0)
        has_attack_signal = (
            (0 < init_win <= 1000) or            # anomalously low rcv window
            syn_count >= 5 or                    # SYN flood
            flow_pps >= 50 or                    # flood rate
            (total_bwd <= 2 and total_fwd >= 10) # lopsided many-packet flow
        )
        if has_attack_signal:
            return label, conf, False
        if total_fwd < 3:
            return 'BENIGN', conf, True
        if bwd_bytes >= 500 and total_bwd >= 3:
            return 'BENIGN', conf, True

    # PortScan: real scans have no payload and minimal exchange.
    if label_upper == 'PORTSCAN':
        if fwd_max > 0 and total_bwd >= 2:
            return 'BENIGN', conf, True
        if fwd_bytes >= 100 or bwd_bytes >= 100:
            return 'BENIGN', conf, True
        if total_fwd >= 4 and total_bwd >= 3:
            return 'BENIGN', conf, True

    # DoS family: normal short/balanced sessions aren't DoS.
    if label_upper in ('DOS HULK', 'DOS GOLDENEYE', 'DOS SLOWLORIS',
                       'DOS SLOWHTTPTEST'):
        if total_bwd >= total_fwd and total_fwd <= 8:
            return 'BENIGN', conf, True
        if bwd_bytes >= 1000 and total_bwd >= 3:
            return 'BENIGN', conf, True

    # Bot on well-known service ports is almost certainly a false positive.
    if label_upper == 'BOT' and dst_port in _BENIGN_SERVICE_PORTS:
        return 'BENIGN', conf, True

    return label, conf, False

# Ports commonly used for legitimate services — traffic to these is not
# automatically suspicious, even to a public IP.
_C2_BENIGN_PORTS = frozenset({
    21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139, 143,
    161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1521,
    1723, 3268, 3306, 3389, 5060, 5061, 5222, 5353, 5900, 5984, 6379,
    8080, 8443, 8883, 9090, 11211, 27017,
})

def suspicious_c2_check(row, src_ip, dst_ip):
    """
    Flag malware-C2-like flows: public destination on a non-standard port
    with substantial, sustained data exchange. Only runs when the ML model
    and the rule engine both failed to label a flow as malicious.
    Returns ('Suspicious C2', confidence) or (None, None).
    """
    if not dst_ip or dst_ip in ('N/A', 'nan') or is_private_ip(dst_ip):
        return None, None
    dst_port = int(row.get('Destination Port', 0) or 0)
    if dst_port == 0 or dst_port in _C2_BENIGN_PORTS:
        return None, None
    total_bytes = (row.get('Total Length of Fwd Packets', 0) +
                   row.get('Total Length of Bwd Packets', 0))
    duration = row.get('Flow Duration', 0)
    if total_bytes >= 50_000 and duration >= 5_000_000:
        return 'Suspicious C2', 75.0
    return None, None

def enrich_results_with_ip_reputation(results, api_key, cache_path):
    """
    Post-scan: for every BENIGN flow with a public external IP, look up the
    IP against AbuseIPDB. If abuseConfidenceScore >= 50, re-label the flow
    as 'Malicious C2' (CRITICAL). Uses the 24h on-disk cache to avoid
    burning the free-tier quota. Caps at MAX_LOOKUPS fresh API calls per
    scan to stay under the daily limit.
    """
    if not api_key:
        return 0
    MAX_LOOKUPS = 25
    now = datetime.now()

    # Load cache
    try:
        with open(cache_path) as f:
            cache = json.load(f)
    except (OSError, ValueError):
        cache = {}

    # Collect public IPs appearing in BENIGN flows
    benign_public = set()
    for r in results:
        if r.get('label', '').upper() != 'BENIGN':
            continue
        for k in ('src_ip', 'dst_ip'):
            ip = r.get(k, '')
            if ip and ip != 'N/A' and not is_private_ip(ip):
                benign_public.add(ip)

    # Work out which IPs need a fresh lookup
    to_lookup = []
    for ip in benign_public:
        entry = cache.get(ip, {})
        try:
            cached_at = datetime.fromisoformat(entry.get('cached_at', '2000-01-01'))
        except (ValueError, TypeError):
            cached_at = datetime(2000, 1, 1)
        if 'abuseScore' not in entry or (now - cached_at) >= timedelta(hours=24):
            to_lookup.append(ip)

    # Hit AbuseIPDB for the stale/missing ones (capped)
    for ip in to_lookup[:MAX_LOOKUPS]:
        try:
            resp = req_lib.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': api_key, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=5,
            )
            if resp.status_code != 200:
                continue
            d = resp.json().get('data', {})
            cache[ip] = {
                'ip':           ip,
                'abuseScore':   d.get('abuseConfidenceScore', 0),
                'country':      d.get('countryCode', 'N/A'),
                'isp':          d.get('isp', 'N/A'),
                'domain':       d.get('domain', 'N/A'),
                'totalReports': d.get('totalReports', 0),
                'cached_at':    now.isoformat(),
            }
        except Exception:
            continue

    # Persist cache updates
    try:
        with open(cache_path, 'w') as f:
            json.dump(cache, f)
    except OSError:
        pass

    # Re-label BENIGN flows whose external IP has a bad reputation
    relabelled = 0
    for r in results:
        if r.get('label', '').upper() != 'BENIGN':
            continue
        worst_score = 0
        for k in ('src_ip', 'dst_ip'):
            ip = r.get(k, '')
            if ip and ip != 'N/A' and not is_private_ip(ip):
                worst_score = max(worst_score, cache.get(ip, {}).get('abuseScore', 0))
        if worst_score >= 50:
            r['label']        = 'Malicious C2'
            r['confidence']   = float(worst_score)
            r['anomaly_score'] = round(100.0 - worst_score, 2)
            r['severity']     = 'CRITICAL'
            r['color']        = '#ff3e5f'
            r['rank']         = 4
            r['is_malicious'] = True
            r['rule_triggered'] = True
            relabelled += 1
    return relabelled

_SEV_AR = {'SAFE': 'آمن', 'MEDIUM': 'متوسط', 'HIGH': 'عالٍ', 'CRITICAL': 'حرج', 'UNKNOWN': 'غير معروف'}

def _tsev(s):
    """Translate a severity string (SAFE/MEDIUM/HIGH/CRITICAL/UNKNOWN) for display."""
    lang = session.get('lang', cfg('language', 'en'))
    if lang == 'ar':
        return _SEV_AR.get(str(s).upper(), s)
    return s

_STAT_AR = {
    'open': 'مفتوح', 'closed': 'مغلق',
    'online': 'متصل', 'warning': 'تحذير', 'offline': 'غير متصل', 'error': 'خطأ',
    'pending_cc_review': 'بانتظار مراجعة CC', 'pending_admin_close': 'بانتظار الإغلاق النهائي',
}

_STAT_EN = {
    'pending_cc_review': 'PENDING CC REVIEW',
    'pending_admin_close': 'PENDING FINAL CLOSE',
}

def _tstat(s):
    """Translate a status string (open/closed/online/offline/warning) for display."""
    lang = session.get('lang', cfg('language', 'en'))
    if lang == 'ar':
        return _STAT_AR.get(str(s).lower(), str(s).upper())
    return _STAT_EN.get(str(s).lower(), str(s).upper())

@app.template_filter('in_set')
def filter_in_set(lst, s):
    return [x for x in lst if x in s]

@app.context_processor
def inject_globals():
    lang = session.get('lang', cfg('language', 'en'))
    roles = get_roles()
    user_role = roles.get(session.get('user', ''), 'analyst')
    return dict(
        model_loaded=model is not None,
        model_error=model_error,
        get_severity=get_severity,
        t=t,
        current_lang=lang,
        user_role=user_role,
        is_admin=(user_role == 'admin'),
        is_cc_admin=(user_role == 'cc_admin'),
        unread_count=get_unread_count(user_role),
        HAS_2FA=HAS_2FA,
        tsev=_tsev,
        tstat=_tstat,
    )

# ── Background scan state ─────────────────────────────────────────────────────
SCANS: dict = {}
SCANS_LOCK = threading.Lock()

def make_state(scan_id, filename):
    return {
        'scan_id':     scan_id,
        'filename':    filename,
        'status':      'running',
        'progress':    0,
        'processed':   0,
        'total':       0,
        'phase':       'Starting…',
        'results':     [],
        'entry':       {},
        'error':       None,
        'alert_sent':  False,
        'user':        '',           # set by caller to enforce ownership
        '_pause':      threading.Event(),
        '_abort':      threading.Event(),
        '_live_buf':   [],           # new rows since last SSE drain
        '_live_lock':  threading.Lock(),
        '_speed':      1.0,          # scan speed multiplier
        'start_time':  None,         # set when classification begins
        'eta':         None,         # seconds remaining
        'elapsed':     0,            # seconds elapsed
    }

def _scan_owned_by(state):
    """Return True if the current session user owns this scan or is admin/cc_admin."""
    owner = state.get('user', '')
    if not owner:
        return True
    current_user = session.get('user', '')
    role = session.get('role', 'analyst')
    return owner == current_user or role in ('admin', 'cc_admin')

def is_private_ip(ip):
    if not ip or ip in ('N/A', 'nan', ''): return True
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_unspecified or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return True

_SCAN_PHASES = {
    'en': {
        'loading_csv':        'Loading CSV…',
        'validating':         'Validating {n:,} flows…',
        'extracting':         'Extracting features…',
        'scaling':            'Scaling features…',
        'classifying':        'Classifying flows… {done:,} / {total:,}',
        'aggregating':        'Aggregating results…',
        'saving':             'Saving results…',
        'complete':           'Analysis complete',
        'error':              'Error: Scan failed — see server logs for details',
        'queued':             'Queued — waiting for previous scan to finish',
    },
    'ar': {
        'loading_csv':        'جارٍ تحميل الملف…',
        'validating':         'جارٍ التحقق من {n:,} تدفق…',
        'extracting':         'جارٍ استخراج الميزات…',
        'scaling':            'جارٍ تحجيم الميزات…',
        'classifying':        'جارٍ التصنيف… {done:,} / {total:,}',
        'aggregating':        'جارٍ تجميع النتائج…',
        'saving':             'جارٍ حفظ النتائج…',
        'complete':           'اكتمل التحليل',
        'error':              'خطأ: فشل الفحص — راجع سجلات الخادم',
        'queued':             'في الانتظار — ينتظر انتهاء الفحص السابق',
    },
}

def _ph(state, key, **kwargs):
    """Return a translated scan phase string using the language stored in state."""
    lang = state.get('lang', 'en')
    d = _SCAN_PHASES.get(lang, _SCAN_PHASES['en'])
    s = d.get(key, _SCAN_PHASES['en'].get(key, key))
    return s.format(**kwargs) if kwargs else s

def _run_scan(scan_id: str, filepath: Path, scan_user: str = 'system'):
    with SCANS_LOCK:
        state = SCANS.get(scan_id)
    if not state:
        return
    state['status'] = 'running'
    state['_pause'].set()
    state['_abort'].clear()
    CHUNK = 500

    # Snapshot model globals under lock so a concurrent load_models() / model_reload()
    # cannot replace them mid-scan, causing a None-reference crash.
    with _MODEL_LOCK:
        _feature_names  = feature_names
        _preprocessor   = preprocessor
        _model          = model
        _label_encoder  = label_encoder

    if _model is None or _preprocessor is None or _feature_names is None or _label_encoder is None:
        state['status'] = 'error'
        state['error']  = 'Model not loaded'
        return

    def upd(pct, phase):
        state['progress'] = pct
        state['phase']    = phase

    # Hard cap: 2M rows per scan to prevent OOM from crafted oversized CSV files.
    _SCAN_ROW_CAP = 2_000_000

    # Outer loop: restarts re-enter here iteratively instead of recursing
    # (prevents stack overflow when the user clicks restart many times).
    _MAX_RESTARTS = 50
    for _restart_attempt in range(_MAX_RESTARTS + 1):
      _restarted = False
      try:
        upd(3,  _ph(state, 'loading_csv'))
        # Try UTF-8 first, fall back to latin-1 for CSVs from Windows tools
        try:
            df = pd.read_csv(filepath, nrows=_SCAN_ROW_CAP, encoding='utf-8')
        except UnicodeDecodeError:
            df = pd.read_csv(filepath, nrows=_SCAN_ROW_CAP, encoding='latin-1')
        total = len(df)
        state['total'] = total

        # Guard against empty CSV (headers only or truly empty file)
        if total == 0:
            state['error']  = 'CSV file contains no data rows'
            state['status'] = 'error'
            state['phase']  = _ph(state, 'error')
            return

        upd(8, _ph(state, 'validating', n=total))
        state['_pause'].wait()
        if state['_abort'].is_set():
            _restart(scan_id, filepath, scan_user); continue

        df.columns = df.columns.str.strip()
        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        upd(15, _ph(state, 'extracting'))
        state['_pause'].wait()
        if state['_abort'].is_set():
            _restart(scan_id, filepath, scan_user); continue

        X = pd.DataFrame(0.0, index=df.index, columns=_feature_names)
        for col in _feature_names:
            if col in df.columns:
                X[col] = df[col]
        X = X.fillna(X.median(numeric_only=True)).fillna(0.0)

        upd(25, _ph(state, 'scaling'))
        state['_pause'].wait()
        if state['_abort'].is_set():
            _restart(scan_id, filepath, scan_user); continue

        X_scaled = _preprocessor.transform(X)
        meta     = find_meta_cols(df)
        results  = []

        # Pre-build raw feature rows for rule engine + ML sanity filter.
        # NOTE: every feature any rule or sanity check reads MUST be in this list —
        # missing columns silently default to 0.0, which makes size/window checks
        # ("<= 10", ">= 29000") evaluate against zero and misfire.
        rule_feature_cols = [
            'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count', 'FIN Flag Count',
            'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Bwd Packet Length Max',
            'Init_Win_bytes_forward',
            'Flow Packets/s', 'Fwd Packets/s', 'Flow Duration',
            'Destination Port', 'Protocol',
        ]
        raw_rows = []
        for idx in range(total):
            row = {}
            for col in rule_feature_cols:
                if col in df.columns:
                    try: row[col] = float(df[col].iloc[idx])
                    except (ValueError, TypeError): row[col] = 0.0
                else:
                    row[col] = 0.0
            raw_rows.append(row)

        # Check if this scan came from a PCAP (rule engine active for PCAP sources)
        is_pcap_scan = state.get('is_pcap', False)

        # Load watchlist under lock to avoid torn reads
        with _WATCHLIST_LOCK:
            watchlist_entries = load_watchlist()
        watchlist_ips = set()
        watchlist_cidrs = []
        for w in watchlist_entries:
            wip = w.get('ip', '')
            if not wip:
                continue
            if '/' in wip:
                try:
                    watchlist_cidrs.append(ipaddress.ip_network(wip, strict=False))
                except ValueError:
                    pass
            else:
                watchlist_ips.add(wip)

        # Pre-load whitelist once (same pattern as watchlist above) to avoid
        # reading the JSON file from disk on every single flow iteration.
        with _WHITELIST_LOCK:
            _wl_entries = load_whitelist()
        _wl_exact = set()
        _wl_cidrs = []
        for _we in _wl_entries:
            _wcidr = _we.get('cidr') or _we.get('ip', '')
            if '/' in _wcidr:
                try:
                    _wl_cidrs.append(ipaddress.ip_network(_wcidr, strict=False))
                except ValueError:
                    pass
            elif _wcidr:
                _wl_exact.add(_wcidr)

        def _is_whitelisted_fast(ip_str):
            """Check whitelist using pre-loaded data (no disk I/O)."""
            if not ip_str or ip_str == 'N/A':
                return False
            if ip_str in _wl_exact:
                return True
            if _wl_cidrs:
                try:
                    addr = ipaddress.ip_address(ip_str)
                    for net in _wl_cidrs:
                        if addr in net:
                            return True
                except ValueError:
                    pass
            return False

        def _in_watchlist(ip_str):
            """Check if an IP matches any watchlist entry (exact or CIDR)."""
            if not ip_str or ip_str == 'N/A':
                return False
            if ip_str in watchlist_ips:
                return True
            if watchlist_cidrs:
                try:
                    addr = ipaddress.ip_address(ip_str)
                    for net in watchlist_cidrs:
                        if addr in net:
                            return True
                except ValueError:
                    pass
            return False

        state['start_time'] = time.time()

        for i in range(0, total, CHUNK):
            state['_pause'].wait()
            if state['_abort'].is_set():
                _restarted = True; break

            end   = min(i + CHUNK, total)
            preds = _model.predict(X_scaled[i:end])
            probs = _model.predict_proba(X_scaled[i:end])
            lbls  = [clean_label(l) for l in _label_encoder[preds]]
            # Use the probability of the actual predicted class, not the max
            # probability across all classes. For ThresholdClassifier these
            # can differ because predict() applies scaled thresholds before
            # argmax while predict_proba() returns raw probabilities.
            confs = probs[np.arange(len(preds)), preds] * 100

            for j, (label, conf) in enumerate(zip(lbls, confs)):
                idx = i + j

                # ML sanity filter: demote obvious false positives (e.g. port-80
                # flows labeled DDoS with real bidirectional data) to BENIGN
                # before the rule engine gets a chance to re-label.
                sanity_demoted = False
                label, conf, sanity_demoted = ml_sanity_check(label, conf, raw_rows[idx])

                # Rule engine: for CSV scans, only run on low-confidence results.
                # For PCAP scans, always run because PCAP feature extraction
                # differs from CIC-IDS2017 and ML may miss attacks.
                rule_triggered = False
                run_rules = False
                if is_pcap_scan and label.upper() == 'BENIGN':
                    run_rules = True
                elif label.upper() == 'BENIGN' and conf < 70:
                    run_rules = True
                elif label.upper() == 'DDOS' and conf < 70:
                    run_rules = True
                if run_rules:
                    rule_result = rule_based_label(raw_rows[idx])
                    if rule_result:
                        label, conf, _ = rule_result
                        rule_triggered = True

                sev, color, rank = get_severity(label)
                r = {
                    'flow_id':       idx + 1,
                    'label':         label,
                    'confidence':    round(float(conf), 2),
                    'anomaly_score': round(float(100 - conf), 2),
                    'severity':      sev,
                    'color':         color,
                    'rank':          rank,
                    'is_malicious':  label.upper() != 'BENIGN',
                    'watchlist_hit': False,
                    'rule_triggered': rule_triggered,
                }
                for key, col in meta.items():
                    if col:
                        try:    r[key] = str(df[col].iloc[idx]).strip()
                        except (IndexError, KeyError, ValueError, TypeError): r[key] = 'N/A'
                    else:
                        r[key] = 'N/A'
                # Suspicious-C2 heuristic: if ML + rules both said BENIGN but the
                # flow goes to a public IP on a non-standard port with notable
                # volume/duration, flag it MEDIUM.
                if r['label'].upper() == 'BENIGN' and not rule_triggered:
                    c2_label, c2_conf = suspicious_c2_check(
                        raw_rows[idx], r.get('src_ip'), r.get('dst_ip')
                    )
                    if c2_label:
                        r['label'] = c2_label
                        r['confidence'] = c2_conf
                        r['anomaly_score'] = round(100.0 - c2_conf, 2)
                        r['severity'], r['color'], r['rank'] = get_severity(c2_label)
                        r['is_malicious'] = True
                        r['rule_triggered'] = True
                # Check whitelist — suppress malicious flag if whitelisted
                if r['is_malicious'] and (_is_whitelisted_fast(r.get('src_ip','')) or _is_whitelisted_fast(r.get('dst_ip',''))):
                    r['is_malicious'] = False
                    r['severity'] = 'SAFE'
                    r['label'] = 'BENIGN'
                    r['whitelisted'] = True
                # Check watchlist (supports both exact IPs and CIDR ranges)
                _src_wl = _in_watchlist(r.get('src_ip'))
                _dst_wl = _in_watchlist(r.get('dst_ip'))
                if _src_wl or _dst_wl:
                    r['watchlist_hit'] = True
                    bump_watchlist_hit(r.get('src_ip') if _src_wl else r.get('dst_ip'))
                results.append(r)
                # Feed live row buffer (compact — only what the UI needs)
                with state['_live_lock']:
                    state['_live_buf'].append({
                        'flow_id':    r['flow_id'],
                        'label':      r['label'],
                        'severity':   r['severity'],
                        'confidence': r['confidence'],
                        'is_malicious': r['is_malicious'],
                        'src_ip':     r.get('src_ip', 'N/A'),
                        'src_port':   r.get('src_port', 'N/A'),
                        'dst_ip':     r.get('dst_ip', 'N/A'),
                        'dst_port':   r.get('dst_port', 'N/A'),
                        'protocol':   r.get('protocol', 'N/A'),
                    })

            state['processed'] = end
            state['progress']  = 25 + int((end / total) * 65)
            state['phase']     = _ph(state, 'classifying', done=end, total=total)

            # ETA calculation
            now = time.time()
            elapsed_sec = now - state['start_time']
            state['elapsed'] = int(elapsed_sec)
            if end > 0 and elapsed_sec > 0:
                rate = end / elapsed_sec  # flows/sec
                remaining = total - end
                state['eta'] = int(remaining / rate) if rate > 0 else None

            # Speed throttle (0.0 = max, 0.5 = slow, 1.0 = normal, 2.0 = fast)
            spd = state.get('_speed', 1.0)
            if spd == 0.5:
                time.sleep(0.08)
            elif spd == 1.0:
                time.sleep(0.02)

        # If abort was triggered inside the chunk loop, restart from the top
        if _restarted:
            _restart(scan_id, filepath, scan_user)
            continue

        upd(92, _ph(state, 'aggregating'))

        # AbuseIPDB post-enrichment: re-label BENIGN flows whose external IP
        # has a bad reputation (abuseScore >= 50) as Malicious C2.
        # Silent no-op when the AbuseIPDB key isn't configured.
        try:
            _abuse_key = get_config().get('abuseipdb_key', '') or ''
            if _abuse_key:
                enrich_results_with_ip_reputation(results, _abuse_key, IP_CACHE_PATH)
        except Exception:
            app.logger.exception('AbuseIPDB enrichment failed for scan %s', scan_id)

        malicious = sum(1 for r in results if r['is_malicious'])
        threat_bd, sev_bd = {}, {}
        for r in results:
            if r['is_malicious']:
                threat_bd[r['label']] = threat_bd.get(r['label'], 0) + 1
            sev_bd[r['severity']] = sev_bd.get(r['severity'], 0) + 1

        avg_conf  = round(float(np.mean([r.get('confidence', 0) for r in results])), 2) if results else 0.0
        timestamp = datetime.now().isoformat()

        upd(96, _ph(state, 'saving'))
        flows_path = FLOWS_DIR / f'scan_{scan_id}.csv'
        pd.DataFrame(results).to_csv(flows_path, index=False)

        entry = dict(scan_id=scan_id, timestamp=timestamp,
                     filename=state['filename'],
                     total_flows=total, malicious_flows=malicious,
                     benign_flows=total - malicious, avg_confidence=avg_conf,
                     threat_breakdown=threat_bd, severity_breakdown=sev_bd,
                     flows_file=str(flows_path), tags=[], user=scan_user)
        save_scan(entry)

        # ── Auto-triage by confidence ──────────────────────────
        with _TRIAGE_LOCK:
            triage = load_triage()
            if scan_id not in triage:
                triage[scan_id] = {}
            for r in results:
                if not r.get('is_malicious'):
                    continue
                fid  = str(r['flow_id'])
                conf = r.get('confidence', 0)
                if conf > 75:
                    triage[scan_id][fid] = 'confirmed'
                elif conf >= 50:
                    triage[scan_id][fid] = 'investigated'
                else:
                    triage[scan_id][fid] = 'false_positive'
            save_triage(triage)
        audit_system('auto_triage', user=scan_user, detail=f'Scan {scan_id}: auto-triage applied to {malicious} malicious flows')

        state['results']  = results
        state['entry']    = entry
        state['progress'] = 100
        state['phase']    = _ph(state, 'complete')
        state['status']   = 'done'

        # Audit scan complete
        audit_system('scan_complete', user=scan_user,
                     detail=f'Scan {scan_id}: {total} flows, {malicious} threats')

        # Auto notification
        if malicious > 0:
            top_sev = max(sev_bd, key=lambda s: {'SAFE':0,'UNKNOWN':1,'MEDIUM':2,'HIGH':3,'CRITICAL':4}.get(s,0), default='UNKNOWN')
            save_notification({
                'id':        f'notif_{scan_id}',
                'timestamp': timestamp,
                'type':      top_sev.lower(),
                'title':     f'{top_sev}: {malicious} threats detected',
                'message':   f'Scan {scan_id} ({state["filename"]}) found {malicious} malicious flows out of {total}.',
                'read':      False,
                'scan_id':   scan_id,
            })

        # Fire alerts
        if malicious > 0:
            threading.Thread(target=_send_alerts, args=(entry,), daemon=True).start()

        return  # Scan completed successfully -- exit the restart loop

      except Exception as e:
        app.logger.error(f'Scan {state.get("scan_id","?")} failed: {e}', exc_info=True)
        state['error']  = _ph(state, 'error')
        state['status'] = 'error'
        state['phase']  = _ph(state, 'error')
        return  # Don't retry on exceptions -- exit the restart loop
    else:
        # Exhausted all restart attempts
        app.logger.error(f'Scan {scan_id} exceeded {_MAX_RESTARTS} restart attempts')
        state['error']  = 'Too many restarts'
        state['status'] = 'error'
        state['phase']  = _ph(state, 'error')

def _restart(scan_id, filepath, scan_user='system'):
    """Reset scan state for a restart iteration. Does NOT call _run_scan (caller loops)."""
    state = SCANS[scan_id]
    state['results']   = []
    state['processed'] = 0
    state['progress']  = 0
    state['error']     = None
    state['status']    = 'running'
    state['_abort'].clear()
    with state['_live_lock']:
        state['_live_buf'] = []

# ── Alerts ────────────────────────────────────────────────────────────────────
def _send_alerts(entry):
    c = get_config()
    sev_bd = entry.get('severity_breakdown', {})
    has_critical = sev_bd.get('CRITICAL', 0) > 0
    has_high     = sev_bd.get('HIGH', 0) > 0

    should_alert = (c.get('alert_on_critical', True) and has_critical) or \
                   (c.get('alert_on_high', True) and has_high)
    if not should_alert:
        return

    subject = f"[BASTION IDS] Threats Detected — Scan {entry['scan_id']}"
    html_body = f"""
    <html><body style="font-family:sans-serif;background:#050a14;color:#e8f0ff;padding:24px">
    <h2 style="color:#00d4ff">BASTION IDS Alert</h2>
    <p>Threats detected in scan <strong>{entry['scan_id']}</strong></p>
    <table border="1" cellpadding="8" style="border-collapse:collapse;color:#e8f0ff">
      <tr><td>File</td><td>{_html.escape(str(entry['filename']))}</td></tr>
      <tr><td>Total Flows</td><td>{entry['total_flows']}</td></tr>
      <tr><td>Malicious</td><td style="color:#ff3e5f">{entry['malicious_flows']}</td></tr>
      <tr><td>Benign</td><td style="color:#00ff94">{entry['benign_flows']}</td></tr>
      <tr><td>Timestamp</td><td>{_html.escape(str(entry['timestamp'][:16]))}</td></tr>
    </table>
    <h3 style="color:#ffb800">Threat Breakdown</h3>
    <ul>
    {''.join(f"<li>{_html.escape(str(k))}: {_html.escape(str(v))}</li>" for k,v in entry.get('threat_breakdown',{}).items())}
    </ul>
    </body></html>
    """

    # Email
    smtp_host = c.get('smtp_host','')
    if smtp_host and c.get('smtp_user') and c.get('smtp_to'):
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From']    = c.get('smtp_user')
            msg['To']      = c.get('smtp_to')
            msg.attach(MIMEText(html_body, 'html'))
            with smtplib.SMTP(smtp_host, int(c.get('smtp_port', 587))) as srv:
                srv.ehlo()
                srv.starttls()
                srv.login(c.get('smtp_user'), c.get('smtp_pass',''))
                srv.sendmail(c.get('smtp_user'), c.get('smtp_to'), msg.as_string())
            print('[BASTION] Alert email sent')
        except Exception as e:
            print(f'[BASTION] Email error: {e}')

    # Webhook
    webhook_url = c.get('webhook_url','')
    if webhook_url:
        try:
            req_lib.post(webhook_url, json={
                'scan_id':   entry['scan_id'],
                'filename':  entry['filename'],
                'malicious': entry['malicious_flows'],
                'total':     entry['total_flows'],
                'threats':   entry.get('threat_breakdown', {}),
                'timestamp': entry['timestamp'],
            }, timeout=10)
            print('[BASTION] Webhook sent')
        except Exception as e:
            print(f'[BASTION] Webhook error: {e}')

# ── History ───────────────────────────────────────────────────────────────────
_HISTORY_LOCK      = threading.Lock()
_WATCHLIST_LOCK    = threading.Lock()
_CASES_LOCK        = threading.RLock()   # RLock: callers hold it for load+save, save_cases re-acquires safely
_TRIAGE_LOCK       = threading.Lock()
_NOTIF_LOCK        = threading.Lock()
_FP_LOCK           = threading.Lock()
_ALERT_RULES_LOCK  = threading.Lock()
_SCHEDULE_LOCK     = threading.Lock()
_WHITELIST_LOCK    = threading.Lock()
_CONFIG_LOCK       = threading.Lock()
_RETRAIN_LOCK      = threading.Lock()
_IP_CACHE_LOCK     = threading.Lock()

def load_history():
    if HISTORY.exists():
        try:
            with open(HISTORY) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def load_user_history():
    u = session.get('user', '')
    return [h for h in load_history() if h.get('user') == u]

def save_scan(entry):
    with _HISTORY_LOCK:
        h = load_history()
        # Remove old entry with same scan_id if exists
        h = [x for x in h if x.get('scan_id') != entry.get('scan_id')]
        h.insert(0, entry)
        _safe_write(HISTORY, h[:500])

def normalise_results(rows):
    SEV_COLOR = {'SAFE':'#00ff94','MEDIUM':'#ffb800','HIGH':'#ff6b35',
                 'CRITICAL':'#ff3e5f','UNKNOWN':'#8899bb'}
    for r in rows:
        # Always re-derive from label so historical CSV bugs are corrected
        label = clean_label(r.get('label', ''))
        r['label'] = label
        r['is_malicious'] = label.upper() != 'BENIGN'
        sev, color, rank  = get_severity(label)
        r['severity'] = sev
        r['color']    = color
        r['rank']     = rank
        if isinstance(r.get('watchlist_hit'), str):
            r['watchlist_hit'] = r['watchlist_hit'].strip().lower() == 'true'
        r.setdefault('watchlist_hit', False)
        # Sanitize confidence: CSV reload can produce float NaN which poisons
        # downstream np.mean calculations and renders as "nan" in templates.
        try:
            _conf = float(r.get('confidence', 0))
            if _conf != _conf:  # NaN check (NaN != NaN)
                _conf = 0.0
            r['confidence'] = round(_conf, 2)
        except (ValueError, TypeError):
            r['confidence'] = 0.0
        # Derive anomaly_score so historical scans always have it.
        # Check for None AND NaN (CSV reload can produce float NaN).
        _as = r.get('anomaly_score')
        _as_missing = _as is None or (isinstance(_as, float) and _as != _as)
        if 'anomaly_score' not in r or _as_missing:
            try:
                r['anomaly_score'] = round(float(100 - float(r.get('confidence', 0))), 2)
            except (ValueError, TypeError):
                r['anomaly_score'] = 0.0
        # Ensure flow_id is always int so triage key lookup matches
        try:
            r['flow_id'] = int(float(r.get('flow_id', 0) or 0))
        except (ValueError, TypeError):
            pass
    return rows

def load_results(scan_id):
    h   = load_history()
    e   = next((x for x in h if x.get('scan_id') == scan_id), None)
    if not e:
        return None, []
    fp  = Path(e.get('flows_file') or '')
    rows = []
    if fp.exists():
        try:
            rows = normalise_results(pd.read_csv(fp).to_dict('records'))
        except Exception:
            rows = []
    return e, rows

# ── Watchlist ─────────────────────────────────────────────────────────────────
def load_watchlist():
    if WATCHLIST_PATH.exists():
        try:
            with open(WATCHLIST_PATH) as f:
                wl = json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
        now = datetime.now()
        def _not_expired(w):
            ea = w.get('expires_at')
            if not ea:
                return True
            try:
                return datetime.fromisoformat(ea) > now
            except (ValueError, TypeError):
                return True
        return [w for w in wl if _not_expired(w)]
    return []

def save_watchlist(wl):
    _safe_write(WATCHLIST_PATH, wl)

def bump_watchlist_hit(ip):
    if not ip or ip == 'N/A':
        return
    with _WATCHLIST_LOCK:
        wl = load_watchlist()
        for w in wl:
            wip = w.get('ip', '')
            matched = False
            if '/' in wip:
                # CIDR entry — check if the detected IP falls within the range
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(wip, strict=False):
                        matched = True
                except (ValueError, TypeError):
                    pass
            else:
                matched = (wip == ip)
            if matched:
                w['hit_count'] = w.get('hit_count', 0) + 1
                w['last_seen'] = datetime.now().isoformat()
                if w.get('alert_on_hit'):
                    threading.Thread(target=_send_watchlist_alert, args=(ip, w), daemon=True).start()
                break
        save_watchlist(wl)

def _send_watchlist_alert(ip, w):
    c = get_config()
    subject = f"[BASTION IDS] Watchlist Hit: {ip}"
    body = f"<html><body style='font-family:sans-serif;background:#050a14;color:#e8f0ff;padding:24px'><h2 style='color:#00d4ff'>BASTION IDS Watchlist Alert</h2><p>IP <strong>{_html.escape(ip)}</strong> was detected in a scan.</p><p>Note: {_html.escape(w.get('note',''))}</p><p>Threat Level: {_html.escape(str(w.get('threat_level','')))}</p><p>Hit Count: {w.get('hit_count',0)}</p></body></html>"
    smtp_host = c.get('smtp_host','')
    if smtp_host and c.get('smtp_user') and c.get('smtp_to'):
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject; msg['From'] = c.get('smtp_user'); msg['To'] = c.get('smtp_to')
            msg.attach(MIMEText(body, 'html'))
            with smtplib.SMTP(smtp_host, int(c.get('smtp_port',587))) as srv:
                srv.ehlo(); srv.starttls(); srv.login(c.get('smtp_user'), c.get('smtp_pass',''))
                srv.sendmail(c.get('smtp_user'), c.get('smtp_to'), msg.as_string())
        except Exception as e:
            print(f'[BASTION] Watchlist alert email error: {e}')
    webhook = c.get('webhook_url','')
    if webhook:
        try:
            req_lib.post(webhook, json={'event':'watchlist_hit','ip':ip,'note':w.get('note',''),'hit_count':w.get('hit_count',0)}, timeout=10)
        except Exception as e:
            print(f'[BASTION] Watchlist webhook error: {e}')

# ── IP Reputation Cache ───────────────────────────────────────────────────────
def load_ip_cache():
    if IP_CACHE_PATH.exists():
        try:
            with open(IP_CACHE_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}

def save_ip_cache(cache):
    _safe_write(IP_CACHE_PATH, cache)

# ── Notifications ─────────────────────────────────────────────────────────────
def load_notifications():
    if NOTIFICATIONS_PATH.exists():
        try:
            with open(NOTIFICATIONS_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def save_notification(n):
    with _NOTIF_LOCK:
        notifs = load_notifications()
        notifs.insert(0, n)
        _safe_write(NOTIFICATIONS_PATH, notifs[:200])

def get_unread_count(role=None):
    try:
        with _NOTIF_LOCK:
            notifs = load_notifications()
        if role:
            notifs = [n for n in notifs if not n.get('target_roles') or role in n['target_roles']]
        return sum(1 for n in notifs if not n.get('read', False))
    except Exception:
        return 0

# ── Triage ─────────────────────────────────────────────────────────────────────
def load_triage():
    if TRIAGE_PATH.exists():
        try:
            with open(TRIAGE_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}

def save_triage(data):
    _safe_write(TRIAGE_PATH, data)

# ── Audit Log ──────────────────────────────────────────────────────────────────
_AUDIT_LOCK = threading.Lock()

def audit(action, detail=''):
    try:
        with _AUDIT_LOCK:
            log = []
            if AUDIT_PATH.exists():
                try:
                    with open(AUDIT_PATH) as f:
                        log = json.load(f)
                except (json.JSONDecodeError, OSError):
                    log = []
            log.append({
                'timestamp': datetime.now().isoformat(),
                'user':      session.get('user', 'system'),
                'action':    action,
                'detail':    detail,
            })
            _safe_write(AUDIT_PATH, log[-500:])
    except Exception:
        pass

def audit_system(action, user='system', detail=''):
    """Thread-safe audit call without Flask session context."""
    try:
        with _AUDIT_LOCK:
            log = []
            if AUDIT_PATH.exists():
                try:
                    with open(AUDIT_PATH) as f:
                        log = json.load(f)
                except (json.JSONDecodeError, OSError):
                    log = []
            log.append({
                'timestamp': datetime.now().isoformat(),
                'user':      user,
                'action':    action,
                'detail':    detail,
            })
            _safe_write(AUDIT_PATH, log[-500:])
    except Exception:
        pass

# ── Cases ──────────────────────────────────────────────────────────────────────
def load_cases():
    if CASES_PATH.exists():
        try:
            with open(CASES_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def get_assignees(case):
    """Return assigned_to as a list, handling legacy string values."""
    val = case.get('assigned_to', [])
    if isinstance(val, str):
        return [val] if val else []
    return val or []

def _available_assignees_for(me, roles, config):
    """Return list of usernames the current user may assign cases to."""
    role = roles.get(me, 'analyst')
    disabled = set(config.get('disabled_users', []))
    if role == 'admin':
        # Admin can assign to active analysts and cc_admins
        return sorted(u for u in get_users()
                      if roles.get(u, 'analyst') in ('analyst', 'cc_admin') and u not in disabled)
    elif role == 'cc_admin':
        # CC Admin can only assign to their own active managed analysts
        managed_by = config.get('managed_by', {})
        return sorted(u for u, mgr in managed_by.items()
                      if mgr == me and u not in disabled)
    return []

def save_cases(cases):
    with _CASES_LOCK:
        _safe_write(CASES_PATH, cases)

def auto_archive_closed_cases():
    """Mark closed cases from previous months as archived (runs lazily on page load)."""
    with _CASES_LOCK:
        all_cases = load_cases()
        now = datetime.now()
        current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        changed = False
        for c in all_cases:
            if c.get('status') == 'closed' and not c.get('archived'):
                close_str = c.get('closed_at') or c.get('cc_closed_at') or c.get('analyst_closed_at') or c.get('created', '')
                try:
                    close_dt = datetime.fromisoformat(close_str)
                except Exception:
                    continue
                if close_dt < current_month_start:
                    c['archived'] = True
                    changed = True
        if changed:
            save_cases(all_cases)

# ── FP Feedback ───────────────────────────────────────────────────────────────
def load_fp_feedback():
    if FP_FEEDBACK_PATH.exists():
        try:
            with open(FP_FEEDBACK_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def save_fp_feedback(records):
    _safe_write(FP_FEEDBACK_PATH, records)

def append_fp_feedback(scan_id, flow_id, src_ip, label, analyst):
    with _FP_LOCK:
        records = load_fp_feedback()
        records.insert(0, {
            'id':        str(uuid.uuid4())[:8],
            'scan_id':   scan_id,
            'flow_id':   str(flow_id),
            'src_ip':    src_ip,
            'label':     label,
            'analyst':   analyst,
            'timestamp': datetime.now().isoformat(),
        })
        save_fp_feedback(records[:1000])

# ── IP Whitelist ──────────────────────────────────────────────────────────────
def load_whitelist():
    if WHITELIST_PATH.exists():
        try:
            with open(WHITELIST_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def save_whitelist(wl):
    _safe_write(WHITELIST_PATH, wl)

def is_whitelisted(ip):
    """Return True if ip matches any whitelist entry (exact or CIDR)."""
    if not ip or ip == 'N/A':
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    with _WHITELIST_LOCK:
        entries = load_whitelist()
    for entry in entries:
        cidr = entry.get('cidr') or entry.get('ip', '')
        try:
            if '/' in cidr:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            else:
                if str(addr) == cidr:
                    return True
        except ValueError:
            continue
    return False

# ── Retrain state ─────────────────────────────────────────────────────────────
RETRAIN_STATE = {'running': False, 'log': [], 'proc': None}

# ── Login rate limiting ────────────────────────────────────────────────────────
# {ip: {'count': int, 'locked_until': datetime or None}}
_LOGIN_ATTEMPTS: dict = {}
_LOGIN_ATTEMPTS_LOCK = threading.Lock()
_LOGIN_MAX_ATTEMPTS  = 5      # failures before lockout
_LOGIN_LOCKOUT_MIN   = 5      # lockout duration in minutes

# ── 2FA rate limiting ─────────────────────────────────────────────────────────
# {username: {'count': int, 'locked_until': datetime or None}}
_2FA_ATTEMPTS: dict = {}
_2FA_ATTEMPTS_LOCK = threading.Lock()
_2FA_MAX_ATTEMPTS  = 5
_2FA_LOCKOUT_MIN   = 5

def _check_2fa_rate(username: str) -> bool:
    """Return True if user is allowed to attempt 2FA, False if locked out."""
    now = datetime.now()
    with _2FA_ATTEMPTS_LOCK:
        rec = _2FA_ATTEMPTS.get(username)
        if not rec:
            return True
        if rec.get('locked_until') and now < rec['locked_until']:
            return False
        # Lockout expired — reset the counter so the user gets a fresh window
        if rec.get('locked_until') and now >= rec['locked_until']:
            rec['count'] = 0
            rec['locked_until'] = None
        return True

def _record_2fa_failure(username: str):
    now = datetime.now()
    with _2FA_ATTEMPTS_LOCK:
        rec = _2FA_ATTEMPTS.setdefault(username, {'count': 0, 'locked_until': None})
        rec['count'] += 1
        if rec['count'] >= _2FA_MAX_ATTEMPTS:
            rec['locked_until'] = now + timedelta(minutes=_2FA_LOCKOUT_MIN)

def _clear_2fa_failures(username: str):
    with _2FA_ATTEMPTS_LOCK:
        _2FA_ATTEMPTS.pop(username, None)

def _check_login_rate(ip: str) -> bool:
    """Return True if IP is allowed to attempt login, False if locked out."""
    now = datetime.now()
    with _LOGIN_ATTEMPTS_LOCK:
        rec = _LOGIN_ATTEMPTS.get(ip)
        if not rec:
            return True
        if rec.get('locked_until') and now < rec['locked_until']:
            return False
        # Lockout expired — reset the counter so the IP gets a fresh window
        if rec.get('locked_until') and now >= rec['locked_until']:
            rec['count'] = 0
            rec['locked_until'] = None
        return True

def _record_login_failure(ip: str):
    now = datetime.now()
    with _LOGIN_ATTEMPTS_LOCK:
        # Prune expired entries periodically to prevent unbounded growth
        if len(_LOGIN_ATTEMPTS) > 5000:
            expired = [k for k, v in _LOGIN_ATTEMPTS.items()
                       if v.get('locked_until') and v['locked_until'] < now]
            for k in expired:
                del _LOGIN_ATTEMPTS[k]
            # If still too large after pruning, evict oldest IPs
            if len(_LOGIN_ATTEMPTS) > 5000:
                overflow = list(_LOGIN_ATTEMPTS.keys())[:len(_LOGIN_ATTEMPTS) - 4000]
                for k in overflow:
                    del _LOGIN_ATTEMPTS[k]
        rec = _LOGIN_ATTEMPTS.setdefault(ip, {'count': 0, 'locked_until': None})
        rec['count'] += 1
        if rec['count'] >= _LOGIN_MAX_ATTEMPTS:
            rec['locked_until'] = now + timedelta(minutes=_LOGIN_LOCKOUT_MIN)

def _clear_login_failures(ip: str):
    with _LOGIN_ATTEMPTS_LOCK:
        _LOGIN_ATTEMPTS.pop(ip, None)

# ── Routes ─── Auth ───────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    cfg_data = get_config()
    hcaptcha_site_key = cfg_data.get('hcaptcha_site_key', '')
    if request.method == 'POST':
        client_ip = request.remote_addr or '0.0.0.0'
        if not _check_login_rate(client_ip):
            flash(t('flash invalid credentials'), 'error')
            return render_template('login.html', hcaptcha_site_key=hcaptcha_site_key)
        if hcaptcha_site_key:
            token = request.form.get('h-captcha-response', '')
            secret = cfg_data.get('hcaptcha_secret_key', '')
            if not token:
                flash(t('flash captcha required'), 'error')
                return render_template('login.html', hcaptcha_site_key=hcaptcha_site_key)
            try:
                resp = req_lib.post('https://api.hcaptcha.com/siteverify',
                                     data={'secret': secret, 'response': token}, timeout=10)
                resp.raise_for_status()
                if not resp.json().get('success'):
                    flash(t('flash captcha failed'), 'error')
                    return render_template('login.html', hcaptcha_site_key=hcaptcha_site_key)
            except Exception as e:
                app.logger.error(f'hCaptcha verification error: {e}')
                flash(t('flash captcha error'), 'error')
                return render_template('login.html', hcaptcha_site_key=hcaptcha_site_key)
        u = request.form.get('username','').strip()[:64]
        p = request.form.get('password','')[:256]
        users = get_users()
        if u in cfg_data.get('disabled_users', []):
            flash(t('flash account disabled'), 'error')
            return render_template('login.html', hcaptcha_site_key=hcaptcha_site_key)
        # Always compute the hash and do a constant-time compare even for
        # non-existent users, so the response time doesn't leak whether a
        # username exists (prevents timing-based username enumeration).
        _submitted_hash = hashlib.sha256(p.encode()).hexdigest()
        _stored_hash = users.get(u, _submitted_hash)  # fallback = submitted so compare_digest still runs
        _creds_ok = _secrets.compare_digest(_stored_hash, _submitted_hash) and (u in users)
        if _creds_ok:
            _clear_login_failures(client_ip)
            # Check 2FA
            if cfg_data.get('2fa_secrets',{}).get(u) and HAS_2FA:
                session['_2fa_pending_user'] = u
                return redirect(url_for('two_fa_verify'))
            session['user'] = u
            roles = get_roles()
            session['role'] = roles.get(u, 'analyst')
            if not session.get('lang'):
                session['lang'] = cfg('language', 'en')
            session['_last_active'] = datetime.now().isoformat()
            with _CONFIG_LOCK:
                _login_cfg = get_config()
                _login_cfg.setdefault('user_last_login', {})[u] = datetime.now().isoformat()
                save_config(_login_cfg)
                reload_config()
            audit_system('login', user=u, detail=f'User {u} logged in')
            return redirect(url_for('dashboard'))
        _record_login_failure(client_ip)
        flash(t('flash invalid credentials'), 'error')
    return render_template('login.html', hcaptcha_site_key=hcaptcha_site_key)

@app.route('/logout')
@login_required
def logout():
    audit('logout', detail=f"User {session.get('user','')} logged out")
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/session/keepalive', methods=['POST'])
@login_required
def session_keepalive():
    session['_last_active'] = datetime.now().isoformat()
    return jsonify(ok=True, timeout_minutes=SESSION_TIMEOUT_MINUTES)

@app.route('/api/session/status')
@login_required
def session_status():
    last = session.get('_last_active')
    if last:
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(last)).total_seconds() / 60
        except (ValueError, TypeError):
            elapsed = 0
        remaining = max(0, SESSION_TIMEOUT_MINUTES - elapsed)
    else:
        remaining = SESSION_TIMEOUT_MINUTES
    return jsonify(remaining_minutes=round(remaining, 2), timeout_minutes=SESSION_TIMEOUT_MINUTES)

@app.route('/language/<lang>')
def set_language(lang):
    if lang in ('en', 'ar'):
        session['lang'] = lang
        session.modified = True
    raw_next = request.args.get('next') or ''
    # Only allow relative paths (must start with / but not //) to prevent open redirect.
    # Intentionally ignore request.referrer — it can be spoofed via HTTP header.
    next_url = raw_next if (raw_next.startswith('/') and not raw_next.startswith('//')) else url_for('dashboard')
    return redirect(next_url)

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    history = load_user_history()
    total_scans   = len(history)
    total_flows   = sum(h.get('total_flows',0)   for h in history)
    total_threats = sum(h.get('malicious_flows',0) for h in history)
    detect_rate   = round(total_threats / total_flows * 100, 1) if total_flows else 0

    threat_counts = {}
    for h in history:
        for tk, c in h.get('threat_breakdown',{}).items():
            threat_counts[tk] = threat_counts.get(tk,0) + c

    sev_counts = {'SAFE':0,'MEDIUM':0,'HIGH':0,'CRITICAL':0}
    for h in history:
        for s, c in h.get('severity_breakdown',{}).items():
            if s in sev_counts: sev_counts[s] += c

    timeline = [{'date': h.get('timestamp','')[:10],
                 'threats': h.get('malicious_flows',0),
                 'total':   h.get('total_flows',0)}
                for h in reversed(history[-20:])]

    # Recurring attackers: IPs that appear in 2+ scans as src_ip
    ip_scan_map = {}  # ip -> set of scan_ids
    ip_hits_map = {}  # ip -> total flow count
    SRC_VARIANTS = {'src_ip', 'source ip', 'srcip', 'src ip'}
    for scan_entry in history:
        sid = scan_entry.get('scan_id','')
        fp  = Path(scan_entry.get('flows_file') or '')
        if not fp.exists():
            continue
        try:
            # Peek at header only to find the src_ip column name
            header = pd.read_csv(fp, nrows=0)
            src_col = next((c for c in header.columns if c.strip().lower() in SRC_VARIANTS), None)
            if not src_col:
                continue
            # Read only that column (fast)
            col_data = pd.read_csv(fp, usecols=[src_col])[src_col].dropna()
            vc = col_data.value_counts()
            for ip, count in vc.items():
                ip = str(ip).strip()
                if ip and ip not in ('N/A', 'nan', 'none', 'None', 'NaN'):
                    ip_scan_map.setdefault(ip, set()).add(sid)
                    ip_hits_map[ip] = ip_hits_map.get(ip, 0) + int(count)
        except Exception:
            pass

    recurring_ips = []
    for ip, scan_set in ip_scan_map.items():
        if len(scan_set) >= 2:
            recurring_ips.append({'ip': ip, 'scan_count': len(scan_set), 'total_hits': ip_hits_map.get(ip, 0)})
    recurring_ips.sort(key=lambda x: x['scan_count'], reverse=True)
    recurring_ips = recurring_ips[:5]

    # Compute overall threat score for gauge (0-10)
    if total_flows > 0:
        threat_ratio = total_threats / total_flows
        crit_total = sum(h.get('severity_breakdown',{}).get('CRITICAL',0) for h in history)
        threat_score = min(10, round(threat_ratio * 8 + (crit_total / max(total_flows,1)) * 4))
    else:
        threat_score = 0

    return render_template('dashboard.html',
        total_scans=total_scans, total_flows=total_flows,
        total_threats=total_threats, detect_rate=detect_rate,
        recent=history[:8], threat_counts=threat_counts,
        sev_counts=sev_counts, timeline=timeline,
        recurring_ips=recurring_ips, threat_score=threat_score)

# ── Scan ──────────────────────────────────────────────────────────────────────
@app.route('/scan', methods=['GET','POST'])
@login_required
def scan():
    if request.method == 'POST':
        f = request.files.get('file')
        fname_lower = (f.filename or '').lower() if f else ''
        is_pcap = fname_lower.endswith('.pcap') or fname_lower.endswith('.pcapng')
        if not f or (not fname_lower.endswith('.csv') and not is_pcap):
            flash(t('flash invalid file type'), 'error')
            return redirect(request.url)
        if model is None:
            app.logger.error(f'Scan attempted but model not loaded: {model_error}')
            flash(t('flash model not loaded'), 'error')
            return redirect(request.url)

        scan_id  = datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
        filename = secure_filename(f.filename)
        filepath = UPLOAD_DIR / f'upload_{scan_id}.csv'

        if is_pcap:
            pcap_ext = '.pcapng' if fname_lower.endswith('.pcapng') else '.pcap'
            pcap_tmp = UPLOAD_DIR / f'upload_{scan_id}{pcap_ext}'
            f.save(str(pcap_tmp))
            try:
                # Use CICFlowMeter if available (exact feature match with training data)
                # otherwise fall back to built-in extractor + rule engine
                if cicflowmeter_available():
                    try:
                        flows_df = pcap_to_flows_cicflowmeter(pcap_tmp)
                    except Exception:
                        flows_df = pcap_to_flows_df(pcap_tmp)
                else:
                    flows_df = pcap_to_flows_df(pcap_tmp)
                flows_df.to_csv(str(filepath), index=False)
                pcap_tmp.unlink(missing_ok=True)
            except Exception as e:
                app.logger.error(f'PCAP conversion failed: {e}', exc_info=True)
                pcap_tmp.unlink(missing_ok=True)
                flash(t('flash pcap failed'), 'error')
                return redirect(request.url)
        else:
            f.save(str(filepath))

        state = make_state(scan_id, filename)
        state['is_pcap'] = is_pcap   # flag so rule engine activates for PCAP scans
        scan_user = session.get('user', 'system')
        state['user'] = scan_user
        state['lang'] = session.get('lang', 'en')
        with SCANS_LOCK:
            SCANS[scan_id] = state

        audit('scan_start', detail=f'Scan {scan_id} started on file {filename}')
        threading.Thread(target=_run_scan, args=(scan_id, filepath, scan_user), daemon=True).start()
        return redirect(url_for('scan_live', scan_id=scan_id))

    return render_template('scan.html')

@app.route('/scan/live/<scan_id>')
@login_required
def scan_live(scan_id):
    state = SCANS.get(scan_id)
    if not state:
        h = load_history()
        if any(x.get('scan_id') == scan_id for x in h):
            return redirect(url_for('result', scan_id=scan_id))
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('scan'))
    if not _scan_owned_by(state):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('scan'))
    return render_template('scan_live.html', scan_id=scan_id, filename=state['filename'])

@app.route('/api/scan/stream/<scan_id>')
@login_required
def scan_stream(scan_id):
    state = SCANS.get(scan_id)
    if not state:
        return Response('data: {"status":"not_found"}\n\n', mimetype='text/event-stream', status=404)
    if not _scan_owned_by(state):
        return Response('data: {"status":"forbidden"}\n\n', mimetype='text/event-stream', status=403)
    def generate():
        tick = 0
        while True:
            state = SCANS.get(scan_id)
            if not state:
                yield f"data: {json.dumps({'status':'not_found'})}\n\n"
                return
            # Drain live buffer (take up to 100 rows per tick)
            new_rows = []
            with state['_live_lock']:
                if state['_live_buf']:
                    new_rows = state['_live_buf'][:100]
                    state['_live_buf'] = state['_live_buf'][100:]
            payload = json.dumps({
                'status':    state['status'],
                'progress':  state['progress'],
                'processed': state['processed'],
                'total':     state['total'],
                'phase':     state['phase'],
                'error':     state['error'],
                'rows':      new_rows,
                'eta':       state.get('eta'),
                'elapsed':   state.get('elapsed', 0),
                'speed':     state.get('_speed', 1.0),
            })
            yield f"data: {payload}\n\n"
            # Check _live_buf under lock to avoid race with _run_scan appending
            with state['_live_lock']:
                _buf_empty = not state['_live_buf']
            if state['status'] in ('done','error') and _buf_empty:
                return
            tick += 1
            if tick % 50 == 0:   # keepalive every ~15 s
                yield ": keepalive\n\n"
            time.sleep(0.3)
    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/api/scan/pause/<scan_id>', methods=['POST'])
@login_required
def scan_pause(scan_id):
    s = SCANS.get(scan_id)
    if not s: return jsonify(error='Not found'), 404
    if not _scan_owned_by(s): return jsonify(error='Forbidden'), 403
    s['_pause'].clear(); s['status'] = 'paused'
    return jsonify(status='paused')

@app.route('/api/scan/resume/<scan_id>', methods=['POST'])
@login_required
def scan_resume(scan_id):
    s = SCANS.get(scan_id)
    if not s: return jsonify(error='Not found'), 404
    if not _scan_owned_by(s): return jsonify(error='Forbidden'), 403
    s['_pause'].set(); s['status'] = 'running'
    return jsonify(status='running')

@app.route('/api/scan/restart/<scan_id>', methods=['POST'])
@login_required
def scan_restart(scan_id):
    s = SCANS.get(scan_id)
    if not s: return jsonify(error='Not found'), 404
    if not _scan_owned_by(s): return jsonify(error='Forbidden'), 403
    s['_abort'].set(); s['_pause'].set()  # status is set by _restart(), not here
    return jsonify(status='restarting')

@app.route('/api/scan/speed/<scan_id>', methods=['POST'])
@login_required
def scan_speed(scan_id):
    s = SCANS.get(scan_id)
    if not s: return jsonify(error='Not found'), 404
    if not _scan_owned_by(s): return jsonify(error='Forbidden'), 403
    spd = (request.json or {}).get('speed', 1.0)
    try:
        spd = float(spd)
        if spd not in (0.0, 0.5, 1.0, 2.0):
            spd = 1.0
        s['_speed'] = spd
    except (ValueError, TypeError):
        return jsonify(error='Invalid speed value'), 400
    return jsonify(speed=s['_speed'])

# ── Result ────────────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>')
@login_required
def result(scan_id):
    state = SCANS.get(scan_id)
    if state and state['status'] == 'done':
        entry   = state['entry']
        _all    = normalise_results(state['results'])
        # Show malicious flows first so threats are always visible in the 2000-row window
        results = sorted(_all, key=lambda r: (0 if r.get('is_malicious') else 1, -r.get('rank', 0)))[:2000]
    else:
        entry, results = load_results(scan_id)
        if entry is None:
            flash(t('flash scan not found'), 'error')
            return redirect(url_for('history'))
        # Show malicious flows first so threats are always visible in the 2000-row window
        results = sorted(results, key=lambda r: (0 if r.get('is_malicious') else 1, -r.get('rank', 0)))[:2000]

    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))

    # Recompute accurate stats from the full flows file (fixes historical bugs)
    fp = Path(entry.get('flows_file') or '')
    full_df = None
    if fp.exists():
        try:
            full_df = pd.read_csv(fp)
            labels  = full_df['label'].astype(str) if 'label' in full_df.columns else pd.Series(dtype=str)
            mal_mask = labels.str.upper() != 'BENIGN'
            entry['malicious_flows'] = int(mal_mask.sum())
            entry['benign_flows']    = int((~mal_mask).sum())
            entry['threat_breakdown'] = {k: int(v) for k, v in full_df.loc[mal_mask, 'label'].value_counts().items()} if 'label' in full_df.columns else {}
            sev_counts_full = {}
            for lbl in labels:
                sv, _, _ = get_severity(lbl)
                sev_counts_full[sv] = sev_counts_full.get(sv, 0) + 1
            entry['severity_breakdown'] = sev_counts_full
        except Exception:
            pass

    sev_order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'SAFE':0,'UNKNOWN':1}
    top_sev   = max(entry.get('severity_breakdown', {}).keys(),
                    key=lambda s: sev_order.get(s, 0), default='SAFE')
    alert_sent = state.get('alert_sent', False) if state else False

    # Load triage data for this scan
    with _TRIAGE_LOCK:
        triage_all  = load_triage()
    triage_data = triage_all.get(scan_id, {})

    # Compute threat timeline (20 buckets) across ALL flows — reuse full_df already loaded above
    threat_timeline = []
    try:
        tl_df = full_df if full_df is not None else (pd.read_csv(fp) if fp.exists() else None)
        if tl_df is not None and 'label' in tl_df.columns:
            tl_mask = tl_df['label'].astype(str).str.upper() != 'BENIGN'
            total   = len(tl_df)
            buckets = 20
            bsize   = max(1, total // buckets)
            counts  = [0] * buckets
            for idx in tl_df.index[tl_mask]:
                b = min(int(idx / bsize), buckets - 1)
                counts[b] += 1
            threat_timeline = [{'minute': i + 1, 'count': counts[i]} for i in range(buckets)]
    except Exception:
        pass

    return render_template('result.html', entry=entry, results=results,
                           top_severity=top_sev, alert_sent=alert_sent,
                           triage_data=triage_data,
                           threat_timeline=threat_timeline)

# ── Attack detail ─────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>/attack/<string:attack_name>')
@login_required
def attack_detail(scan_id, attack_name):
    state = SCANS.get(scan_id)
    if state and state['status'] == 'done':
        entry, all_rows = state['entry'], normalise_results(state['results'])
    else:
        entry, all_rows = load_results(scan_id)
        if entry is None:
            flash(t('flash scan not found'), 'error')
            return redirect(url_for('history'))

    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))

    flows = [r for r in all_rows if r.get('label','').lower() == attack_name.lower()]
    sev, color, _ = get_severity(attack_name)
    total = entry.get('total_flows', len(all_rows)) or 1
    pct   = round(len(flows) / total * 100, 2)
    avg_conf = round(float(np.mean([r.get('confidence', 0) for r in flows])), 2) if flows else 0

    # unique IPs for watchlist add button
    src_ips = list(set(r.get('src_ip','N/A') for r in flows if r.get('src_ip','N/A') != 'N/A'))[:20]

    # Protocol breakdown for this attack type
    proto_bd = {}
    for r in flows:
        p = str(r.get('protocol', 'N/A'))
        proto_bd[p] = proto_bd.get(p, 0) + 1

    # Triage data
    with _TRIAGE_LOCK:
        triage_all  = load_triage()
    triage_data = triage_all.get(scan_id, {})

    definition, why_flagged = get_attack_info(attack_name)
    return render_template('attack_detail.html',
        scan_id=scan_id, attack_name=attack_name,
        flows=flows[:2000], sev=sev, color=color,
        count=len(flows), pct=pct, avg_conf=avg_conf,
        entry=entry, src_ips=src_ips,
        protocol_breakdown=proto_bd, triage_data=triage_data,
        mitre=get_mitre(attack_name),
        definition=definition, why_flagged=why_flagged)

# ── Per-Attack PDF Export ──────────────────────────────────────────────────────
@app.route('/result/<scan_id>/attack/<string:attack_name>/pdf')
@login_required
def attack_export_pdf(scan_id, attack_name):
    state = SCANS.get(scan_id)
    if state and state['status'] == 'done':
        entry, all_rows = state['entry'], normalise_results(state['results'])
    else:
        entry, all_rows = load_results(scan_id)
    if not entry:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))
    try:
        from fpdf import FPDF
    except ImportError:
        flash(t('flash fpdf2 missing'), 'error')
        return redirect(url_for('attack_detail', scan_id=scan_id, attack_name=attack_name))

    flows = [r for r in all_rows if r.get('label','').lower() == attack_name.lower()]
    sev, _, _ = get_severity(attack_name)
    total_flows = entry.get('total_flows', len(all_rows)) or 1
    count = len(flows)
    pct = round(count / total_flows * 100, 2)
    avg_conf = round(float(sum(float(r.get('confidence',0)) for r in flows) / count), 1) if count else 0

    # Attacker IP summary for this attack
    ip_map = {}
    for r in flows:
        ip = r.get('src_ip','N/A')
        if ip not in ip_map:
            ip_map[ip] = {'count':0,'confidences':[],'dst_ips':set(),'ports':set()}
        ip_map[ip]['count'] += 1
        ip_map[ip]['confidences'].append(float(r.get('confidence',0)))
        if r.get('dst_ip'): ip_map[ip]['dst_ips'].add(r['dst_ip'])
        if r.get('dst_port'): ip_map[ip]['ports'].add(str(r['dst_port']))
    top_ips = sorted(ip_map.items(), key=lambda x: x[1]['count'], reverse=True)

    # ── helpers (same pattern as export_pdf) ──────────────────────────────────
    def _safe(s):
        v = str(s).replace('\u2014','-').replace('\u2013','-').replace('\u2019',"'").replace('\u2018',"'").replace('\ufffd','?')
        return v.encode('latin-1', errors='replace').decode('latin-1')

    lang = session.get('lang', cfg('language', 'en'))
    is_rtl = lang == 'ar'
    _arabic_ok = False; _arabic_font = None; _arabic_font_bold = None
    if is_rtl:
        try:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Regular.ttf',
                        BASE_DIR / 'static/fonts/Amiri-Regular.ttf',
                        Path('C:/Windows/Fonts/Arial.ttf')]:
                if _fp.exists(): _arabic_font = str(_fp); _arabic_ok = True; break
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Bold.ttf',
                        BASE_DIR / 'static/fonts/NotoNaskhArabic-SemiBold.ttf']:
                if _fp.exists(): _arabic_font_bold = str(_fp); break
        except ImportError:
            pass

    def _txt(s):
        v = str(s)
        if is_rtl and _arabic_ok:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            return bidi_display(arabic_reshaper.reshape(v))
        return _safe(v)

    def _fit(text, w):
        maxc = max(1, int(w / 1.9))
        s = _txt(str(text)) if (is_rtl and _arabic_ok) else _safe(str(text))
        return (s[:maxc-2]+'..') if len(s) > maxc else s

    # PDF strings (reuse _PDF_STR from export_pdf — define inline subset)
    _PS = {
        'en': {
            'attack card title': 'Attack Card Report',
            'Scan ID': 'Scan ID', 'Attack Type': 'Attack Type', 'Severity': 'Severity',
            'Flow Count': 'Flow Count', '% of Total': '% of Total',
            'Avg Confidence': 'Avg Confidence', 'Analyst': 'Analyst', 'Generated': 'Generated',
            'Attack Summary': 'Attack Summary', 'What is this attack': 'What is this attack',
            'Why Flagged': 'Why It Was Flagged',
            'Top Source IPs': 'Top Source IPs',
            'Source IP': 'Source IP', 'Flows': 'Flows', 'Confidence': 'Avg Confidence %',
            'Target IPs': 'Target IPs', 'Ports': 'Ports',
            'Defense Recommendations': 'Defense Recommendations',
            'Flow Sample': 'Flow Sample (first 20)',
            'Flow ID': 'Flow ID', 'Src IP': 'Src IP', 'Src Port': 'Src Port',
            'Dst IP': 'Dst IP', 'Dst Port': 'Dst Port', 'Protocol': 'Protocol',
            'Conf %': 'Conf %',
        },
        'ar': {
            'attack card title': '\u062a\u0642\u0631\u064a\u0631 \u0628\u0637\u0627\u0642\u0629 \u0627\u0644\u0647\u062c\u0648\u0645',
            'Scan ID': '\u0645\u0639\u0631\u0641 \u0627\u0644\u0641\u062d\u0635', 'Attack Type': '\u0646\u0648\u0639 \u0627\u0644\u0647\u062c\u0648\u0645',
            'Severity': '\u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u062e\u0637\u0648\u0631\u0629',
            'Flow Count': '\u0639\u062f\u062f \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a',
            '% of Total': '% \u0645\u0646 \u0627\u0644\u0625\u062c\u0645\u0627\u0644\u064a',
            'Avg Confidence': '\u0645\u062a\u0648\u0633\u0637 \u0627\u0644\u062b\u0642\u0629',
            'Analyst': '\u0627\u0644\u0645\u062d\u0644\u0644', 'Generated': '\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u0625\u0646\u0634\u0627\u0621',
            'Attack Summary': '\u0645\u0644\u062e\u0635 \u0627\u0644\u0647\u062c\u0648\u0645',
            'What is this attack': '\u0645\u0627 \u0647\u0630\u0627 \u0627\u0644\u0647\u062c\u0648\u0645',
            'Why Flagged': '\u0644\u0645\u0627\u0630\u0627 \u062a\u0645 \u0627\u0644\u0625\u0628\u0644\u0627\u063a \u0639\u0646\u0647',
            'Top Source IPs': '\u0623\u0639\u0644\u0649 \u0639\u0646\u0627\u0648\u064a\u0646 IP \u0627\u0644\u0645\u0635\u062f\u0631',
            'Source IP': '\u0639\u0646\u0648\u0627\u0646 IP \u0627\u0644\u0645\u0635\u062f\u0631',
            'Flows': '\u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a',
            'Confidence': '\u0645\u062a\u0648\u0633\u0637 \u0627\u0644\u062b\u0642\u0629 %',
            'Target IPs': '\u0639\u0646\u0627\u0648\u064a\u0646 IP \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641\u0629',
            'Ports': '\u0627\u0644\u0645\u0646\u0627\u0641\u0630',
            'Defense Recommendations': '\u062a\u0648\u0635\u064a\u0627\u062a \u0627\u0644\u062f\u0641\u0627\u0639',
            'Flow Sample': '\u0639\u064a\u0646\u0629 \u062a\u062f\u0641\u0642\u0627\u062a (\u0623\u0648\u0644 20)',
            'Flow ID': '\u0645\u0639\u0631\u0641 \u0627\u0644\u062a\u062f\u0641\u0642', 'Src IP': 'IP \u0627\u0644\u0645\u0635\u062f\u0631',
            'Src Port': '\u0645\u0646\u0641\u0630 \u0627\u0644\u0645\u0635\u062f\u0631',
            'Dst IP': 'IP \u0627\u0644\u0648\u062c\u0647\u0629', 'Dst Port': '\u0645\u0646\u0641\u0630 \u0627\u0644\u0648\u062c\u0647\u0629',
            'Protocol': '\u0627\u0644\u0628\u0631\u0648\u062a\u0648\u0643\u0648\u0644', 'Conf %': '\u0627\u0644\u062b\u0642\u0629 %',
            'CRITICAL': '\u062d\u0631\u062c', 'HIGH': '\u0639\u0627\u0644\u0650', 'MEDIUM': '\u0645\u062a\u0648\u0633\u0637',
            'SAFE': '\u0622\u0645\u0646', 'UNKNOWN': '\u063a\u064a\u0631 \u0645\u0639\u0631\u0648\u0641',
        }
    }
    def ps(key, **kw):
        s = _PS.get(lang, _PS['en']).get(key, _PS['en'].get(key, key))
        return s.format(**kw) if kw else s

    # Colors
    C_BG=(255,255,255); C_NAVY=(20,50,110); C_ACCENT=(60,120,200)
    C_TXT=(25,35,55); C_MUTED=(100,110,130); C_TH_BG=(210,225,248)
    C_TH_TXT=(15,40,100); C_ROW_ALT=(245,248,254); C_ROW_EVEN=(255,255,255)
    C_BORDER=(180,195,220); C_FOOTER=(150,160,180)
    SEV_BG={'CRITICAL':(255,232,232),'HIGH':(255,243,222),'MEDIUM':(255,252,218),'SAFE':(228,250,234),'UNKNOWN':(240,242,246)}
    SEV_TXT={'CRITICAL':(170,0,15),'HIGH':(160,70,0),'MEDIUM':(120,90,0),'SAFE':(0,100,40),'UNKNOWN':(80,85,100)}
    SEV_BDR={'CRITICAL':(220,60,60),'HIGH':(220,130,0),'MEDIUM':(200,165,0),'SAFE':(0,160,70),'UNKNOWN':(160,165,180)}
    L_MARGIN=15; R_MARGIN=15; T_MARGIN=20; CONTENT_W=180

    class AttackPDF(FPDF):
        def header(self):
            self.set_fill_color(*C_BG); self.rect(0,0,210,297,'F')
            if self.page_no() > 1:
                self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
                self.line(L_MARGIN,12,210-R_MARGIN,12)
                self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
                self.set_xy(L_MARGIN,14)
                self.cell(CONTENT_W,5,_safe(f'BASTION IDS  |  {attack_name}  |  CONFIDENTIAL'),align='R'); self.ln(4)
        def footer(self):
            if self.page_no() == 1: return
            self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
            self.line(L_MARGIN,284,210-R_MARGIN,284)
            self.set_y(-13); self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
            self.cell(0,5,_safe(f'Generated {datetime.now().strftime("%Y-%m-%d %H:%M")}  |  Page {self.page_no()}  |  BASTION IDS Attack Card'),align='C')

    pdf = AttackPDF(); pdf.set_margins(L_MARGIN,T_MARGIN,R_MARGIN); pdf.set_auto_page_break(auto=True,margin=22)
    if is_rtl and _arabic_ok:
        pdf.add_font('Arabic','',_arabic_font)
        if _arabic_font_bold: pdf.add_font('ArabicB','',_arabic_font_bold)

    def _font(style='',size=10):
        if is_rtl and _arabic_ok:
            if style=='B' and _arabic_font_bold: pdf.set_font('ArabicB','',size)
            else: pdf.set_font('Arabic','',size)
        else: pdf.set_font('Helvetica',style,size)

    _a = 'R' if is_rtl else 'L'

    def section(title, desc=None):
        pdf.ln(4); _font('B',12); pdf.set_text_color(*C_NAVY)
        pdf.set_x(L_MARGIN); pdf.cell(CONTENT_W,8,_txt(title),align=_a,new_x='LMARGIN',new_y='NEXT')
        if desc:
            _font('I',9); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.multi_cell(CONTENT_W,5,_txt(desc),align=_a,new_x='LMARGIN',new_y='NEXT')
        pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.4)
        pdf.line(L_MARGIN,pdf.get_y(),L_MARGIN+CONTENT_W,pdf.get_y()); pdf.ln(3)

    def kv(label, value):
        if is_rtl:
            _font('',10); pdf.set_text_color(*C_TXT)
            pdf.set_x(L_MARGIN); pdf.cell(60,7,_txt(str(value)),align='L',new_x='RIGHT',new_y='LAST')
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.cell(CONTENT_W-60,7,_txt(label+':'),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.cell(65,7,_txt(label+':'),new_x='RIGHT',new_y='LAST')
            _font('',10); pdf.set_text_color(*C_TXT); pdf.cell(0,7,_txt(str(value)),new_x='LMARGIN',new_y='NEXT')

    def th(*cols_widths):
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*C_TH_BG); pdf.set_text_color(*C_TH_TXT)
        pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('B',9)
        for col,w in cols_widths: pdf.cell(w,7,_fit(col,w),border=1,fill=True,align=_a)
        pdf.ln()

    def tr(*vals_widths,alt=False):
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*(C_ROW_ALT if alt else C_ROW_EVEN))
        pdf.set_text_color(*C_TXT); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('',9)
        for val,w in vals_widths: pdf.cell(w,6,_fit(val,w),border=1,fill=True,align=_a)
        pdf.ln()

    # ── Cover ─────────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(*C_NAVY); pdf.rect(0,0,210,55,'F')
    pdf.set_y(15); _font('B',32); pdf.set_text_color(255,255,255)
    pdf.cell(0,14,'BASTION IDS',align='C',new_x='LMARGIN',new_y='NEXT')
    _font('',13); pdf.set_text_color(200,215,245)
    pdf.cell(0,7,_txt(ps('attack card title')),align='C',new_x='LMARGIN',new_y='NEXT')
    pdf.ln(12)

    # Severity banner
    bh=22; by=pdf.get_y()
    pdf.set_fill_color(*SEV_BG.get(sev,C_BG)); pdf.set_draw_color(*SEV_BDR.get(sev,C_BORDER)); pdf.set_line_width(0.5)
    pdf.rect(L_MARGIN,by,CONTENT_W,bh,'FD')
    pdf.set_fill_color(*SEV_TXT.get(sev,(80,85,100))); pdf.rect(L_MARGIN,by,28,bh,'F')
    _font('B',7); pdf.set_text_color(255,255,255)
    pdf.set_xy(L_MARGIN,by+8); pdf.cell(28,6,_txt(ps(sev)),align='C')
    _font('B',18); pdf.set_text_color(*SEV_TXT.get(sev,C_NAVY))
    pdf.set_xy(L_MARGIN+31,by+2); pdf.cell(CONTENT_W-33,10,_safe(attack_name))
    _font('',9); pdf.set_text_color(*C_MUTED)
    pdf.set_xy(L_MARGIN+31,by+13)
    pdf.cell(CONTENT_W-33,7,_safe(f'{count:,} flows  |  {pct}% of scan  |  Avg conf: {avg_conf}%'))
    pdf.set_y(by+bh+6)

    # Meta box
    meta_y=pdf.get_y()
    pdf.set_fill_color(245,248,254); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.4)
    pdf.rect(L_MARGIN,meta_y,CONTENT_W,42,'FD'); pdf.set_y(meta_y+4)
    for label,val in [(ps('Scan ID'),scan_id),(ps('Attack Type'),attack_name),
                      (ps('Severity'),ps(sev)),(ps('Flow Count'),f'{count:,}'),
                      (ps('% of Total'),f'{pct}%'),(ps('Avg Confidence'),f'{avg_conf}%'),
                      (ps('Analyst'),session.get('user','')),(ps('Generated'),datetime.now().strftime('%Y-%m-%d %H:%M'))]:
        if is_rtl:
            _font('',10); pdf.set_text_color(*C_TXT)
            pdf.set_x(L_MARGIN+5); pdf.cell(60,5,_txt(str(val)),align='L',new_x='RIGHT',new_y='LAST')
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.cell(CONTENT_W-65,5,_txt(label+':'),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN+5); pdf.cell(65,5,_safe(label+':'),new_x='RIGHT',new_y='LAST')
            _font('',10); pdf.set_text_color(*C_TXT); pdf.cell(0,5,_safe(str(val)),new_x='LMARGIN',new_y='NEXT')

    # ── Page 2: Summary + IPs + Defense ───────────────────────────────────────
    pdf.add_page()
    definition, why_flagged = get_attack_info(attack_name)

    section(ps('Attack Summary'))
    if definition:
        section(ps('What is this attack'))
        _font('',10); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN)
        pdf.multi_cell(CONTENT_W,5,_txt(definition),align=_a,new_x='LMARGIN',new_y='NEXT'); pdf.ln(2)

    if why_flagged:
        section(ps('Why Flagged'))
        _font('',10); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN)
        pdf.multi_cell(CONTENT_W,5,_txt(why_flagged),align=_a,new_x='LMARGIN',new_y='NEXT'); pdf.ln(2)

    if top_ips:
        section(ps('Top Source IPs'))
        th((ps('Source IP'),60),(ps('Flows'),25),(ps('Confidence'),35),(ps('Target IPs'),40),(ps('Ports'),20))
        for i,(ip,info) in enumerate(top_ips[:10]):
            ac=round(sum(info['confidences'])/len(info['confidences']),1) if info['confidences'] else 0
            tr((ip,60),(f"{info['count']:,}",25),(f'{ac}%',35),
               (','.join(list(info['dst_ips'])[:3]),40),
               (','.join(sorted(list(info['ports']))[:3]),20),alt=(i%2==1))

    # Defense
    _ATDEF_EN = {
        'PortScan':'1. Enable stateful firewall rules.\n2. Deploy IPS to auto-block scanners.\n3. Close unnecessary ports.\n4. Restrict ICMP replies.\n5. Monitor connection failures.',
        'DoS Hulk':'1. Deploy a WAF.\n2. Enable rate limiting.\n3. Use a CDN.\n4. Configure connection timeouts.\n5. Scale with load balancers.',
        'DoS GoldenEye':'1. Limit concurrent connections per IP.\n2. Disable or reduce Keep-Alive timeout.\n3. Deploy a reverse proxy.\n4. Configure request body size limits.\n5. Use WAF GoldenEye rules.',
        'DoS slowloris':'1. Set aggressive header read timeouts.\n2. Limit concurrent connections per IP.\n3. Use nginx or IIS over Apache.\n4. Deploy mod_reqtimeout.\n5. Use a CDN/scrubbing service.',
        'DoS Slowhttptest':'1. Enforce strict HTTP read timeouts.\n2. Limit max concurrent connections.\n3. Use a load balancer.\n4. Set minimum data rate thresholds.\n5. Tune OS TCP settings.',
        'DDoS':'1. Activate ISP-level DDoS mitigation.\n2. Use cloud DDoS scrubbing.\n3. Configure rate limiting at the edge.\n4. Implement anycast routing.\n5. Prepare escalation runbook.',
        'FTP-Patator':'1. Migrate to SFTP.\n2. Implement account lockout (fail2ban).\n3. Restrict FTP to known IPs.\n4. Enable MFA on remote access.\n5. Monitor FTP logs.',
        'SSH-Patator':'1. Use public key auth only.\n2. Deploy fail2ban.\n3. Change SSH to non-standard port.\n4. Restrict to trusted IPs.\n5. Enable MFA (PAM).',
        'Bot':'1. Isolate the compromised host.\n2. Run a full malware scan.\n3. Check for C2 beaconing in logs.\n4. Review startup/scheduled tasks.\n5. Reset all credentials.\n6. Block C2 IPs/domains at firewall.',
        'Heartbleed':'1. Patch OpenSSL to 1.0.1g+.\n2. Revoke and reissue TLS certificates.\n3. Rotate all server private keys.\n4. Invalidate active session tokens.\n5. Reset user passwords.',
        'Infiltration':'1. Isolate affected systems immediately.\n2. Preserve forensic evidence.\n3. Engage incident response procedures.\n4. Patch the exploited vulnerability.\n5. Review lateral movement paths.\n6. Conduct full post-incident review.',
        'Web Attack Brute Force':'1. Implement CAPTCHA on login forms.\n2. Enable account lockout.\n3. Rate-limit login endpoints.\n4. Alert on login failure spikes.\n5. Enforce strong passwords and MFA.',
        'Web Attack XSS':'1. Sanitize and encode all HTML output.\n2. Implement a strict CSP header.\n3. Use HttpOnly and Secure cookie flags.\n4. Enable X-XSS-Protection header.\n5. Deploy WAF with XSS rules.',
        'Web Attack Sql Injection':'1. Use parameterized queries only.\n2. Validate and whitelist all inputs.\n3. Deploy WAF with SQL injection rules.\n4. Limit DB user permissions.\n5. Enable query logging.',
    }
    _ATDEF_AR = {
        'PortScan':'\u0661. \u062a\u0641\u0639\u064a\u0644 \u0642\u0648\u0627\u0639\u062f \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629 \u0630\u0627\u062a \u0627\u0644\u062d\u0627\u0644\u0629 \u0644\u062d\u062c\u0628 \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u063a\u064a\u0631 \u0627\u0644\u0645\u0631\u063a\u0648\u0628\u0629.\n\u0662. \u0646\u0634\u0631 IPS \u0644\u062d\u0638\u0631 \u0627\u0644\u0645\u0627\u0633\u062d\u064a\u0646 \u062a\u0644\u0642\u0627\u0626\u064a\u064b\u0627 \u0628\u0639\u062f \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u0639\u062a\u0628\u0629.\n\u0663. \u0625\u063a\u0644\u0627\u0642 \u062c\u0645\u064a\u0639 \u0627\u0644\u0645\u0646\u0627\u0641\u0630 \u063a\u064a\u0631 \u0627\u0644\u0636\u0631\u0648\u0631\u064a\u0629 (\u0645\u0628\u062f\u0623 \u0627\u0644\u0635\u0644\u0627\u062d\u064a\u0629 \u0627\u0644\u0623\u062f\u0646\u0649).\n\u0664. \u062a\u0642\u064a\u064a\u062f \u0631\u062f\u0648\u062f ICMP echo \u0644\u062a\u0642\u0644\u064a\u0644 \u0631\u0624\u064a\u0629 \u0627\u0644\u0634\u0628\u0643\u0629.\n\u0665. \u0645\u0631\u0627\u0642\u0628\u0629 \u062d\u0627\u0644\u0627\u062a \u0641\u0634\u0644 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0627\u0644\u0645\u062a\u0643\u0631\u0631\u0629 \u0641\u064a \u0633\u062c\u0644\u0627\u062a \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.',
        'DoS Hulk':'\u0661. \u0646\u0634\u0631 WAF \u0644\u062a\u0635\u0641\u064a\u0629 \u062d\u0631\u0643\u0629 HTTP \u0627\u0644\u0641\u064a\u0636\u0627\u0646\u064a\u0629.\n\u0662. \u062a\u0641\u0639\u064a\u0644 \u062a\u062d\u062f\u064a\u062f \u0645\u0639\u062f\u0644 \u0627\u0644\u0637\u0644\u0628\u0627\u062a \u0639\u0644\u0649 \u062e\u0627\u062f\u0645 \u0627\u0644\u0648\u064a\u0628.\n\u0663. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 CDN \u0644\u0627\u0645\u062a\u0635\u0627\u0635 \u062d\u0631\u0643\u0629 \u0627\u0644\u0647\u062c\u0648\u0645.\n\u0664. \u0636\u0628\u0637 \u0645\u0647\u0644\u0627\u062a \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0644\u0625\u0633\u0642\u0627\u0637 \u0637\u0644\u0628\u0627\u062a HTTP \u0627\u0644\u062e\u0627\u0645\u0644\u0629.\n\u0665. \u0627\u0644\u062a\u0648\u0633\u0639 \u0627\u0644\u0623\u0641\u0642\u064a \u0628\u0645\u0648\u0627\u0632\u0646\u0627\u062a \u0627\u0644\u062a\u062d\u0645\u064a\u0644 \u062e\u0644\u0627\u0644 \u0627\u0644\u0647\u062c\u0645\u0627\u062a.',
        'DoS GoldenEye':'\u0661. \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0627\u0644\u0645\u062a\u0632\u0627\u0645\u0646\u0629 \u0644\u0643\u0644 IP.\n\u0662. \u062a\u0639\u0637\u064a\u0644 HTTP Keep-Alive \u0623\u0648 \u062a\u0642\u0644\u064a\u0644 \u0645\u0647\u0644\u062a\u0647.\n\u0663. \u0646\u0634\u0631 \u0648\u0643\u064a\u0644 \u0639\u0643\u0633\u064a \u0644\u0625\u0646\u0647\u0627\u0621 \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a.\n\u0664. \u0636\u0628\u0637 \u062d\u062f\u0648\u062f \u062d\u062c\u0645 \u062c\u0633\u0645 \u0627\u0644\u0637\u0644\u0628.\n\u0665. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 WAF \u0644\u0644\u0643\u0634\u0641 \u0639\u0646 \u0623\u0646\u0645\u0627\u0637 GoldenEye.',
        'DoS slowloris':'\u0661. \u0636\u0628\u0637 \u0645\u0647\u0644\u0629 \u0642\u0631\u0627\u0621\u0629 \u0627\u0644\u0631\u0623\u0633 \u0635\u0627\u0631\u0645\u0629.\n\u0662. \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0627\u0644\u0645\u062a\u0632\u0627\u0645\u0646\u0629 \u0644\u0643\u0644 IP.\n\u0663. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 nginx \u0623\u0648 IIS \u0628\u062f\u0644\u0627\u064b \u0645\u0646 Apache.\n\u0664. \u0646\u0634\u0631 mod_reqtimeout \u0641\u064a Apache.\n\u0665. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 CDN \u0644\u062a\u0635\u0641\u064a\u0629 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0628\u0637\u064a\u0626\u0629.',
        'DoS Slowhttptest':'\u0661. \u0641\u0631\u0636 \u0645\u0647\u0644 \u0635\u0627\u0631\u0645\u0629 \u0644\u0642\u0631\u0627\u0621\u0629 HTTP.\n\u0662. \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u062d\u062f \u0627\u0644\u0623\u0642\u0635\u0649 \u0644\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0644\u0643\u0644 IP.\n\u0663. \u0646\u0634\u0631 \u0645\u0648\u0627\u0632\u0646 \u062a\u062d\u0645\u064a\u0644 \u0644\u062a\u0641\u0631\u064a\u063a \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0627\u0644\u0628\u0637\u064a\u0621.\n\u0664. \u0636\u0628\u0637 \u062d\u062f\u0648\u062f \u0623\u062f\u0646\u0649 \u0644\u0645\u0639\u062f\u0644 \u0646\u0642\u0644 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a.\n\u0665. \u0636\u0628\u0637 TCP \u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u0646\u0638\u0627\u0645.',
        'DDoS':'\u0661. \u062a\u0641\u0639\u064a\u0644 \u062a\u062e\u0641\u064a\u0641 DDoS \u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u0645\u0632\u0648\u062f \u0627\u0644\u0625\u0646\u062a\u0631\u0646\u062a.\n\u0662. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u062e\u062f\u0645\u0629 \u062a\u0646\u0642\u064a\u0629 DDoS \u0633\u062d\u0627\u0628\u064a\u0629.\n\u0663. \u0636\u0628\u0637 \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0645\u0639\u062f\u0644 \u0648\u062d\u062f\u0648\u062f \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0639\u0644\u0649 \u062d\u0627\u0641\u0629 \u0627\u0644\u0634\u0628\u0643\u0629.\n\u0664. \u062a\u0637\u0628\u064a\u0642 \u062a\u0648\u062c\u064a\u0647 anycast \u0644\u062a\u0648\u0632\u064a\u0639 \u062d\u0631\u0643\u0629 \u0627\u0644\u0647\u062c\u0648\u0645.\n\u0665. \u0625\u0639\u062f\u0627\u062f \u062f\u0644\u064a\u0644 \u062a\u0634\u063a\u064a\u0644 \u0644\u0644\u062a\u0635\u0639\u064a\u062f.',
        'FTP-Patator':'\u0661. \u062a\u0639\u0637\u064a\u0644 FTP \u0648\u0627\u0644\u0627\u0646\u062a\u0642\u0627\u0644 \u0625\u0644\u0649 SFTP.\n\u0662. \u062a\u0637\u0628\u064a\u0642 \u0642\u0641\u0644 \u0627\u0644\u062d\u0633\u0627\u0628 \u0628\u0639\u062f \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u0641\u0627\u0634\u0644\u0629 (fail2ban).\n\u0663. \u062a\u0642\u064a\u064a\u062f \u0648\u0635\u0648\u0644 FTP \u0644\u0646\u0637\u0627\u0642\u0627\u062a IP \u0645\u0639\u0631\u0648\u0641\u0629.\n\u0664. \u062a\u0641\u0639\u064a\u0644 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629 \u0645\u062a\u0639\u062f\u062f\u0629 \u0627\u0644\u0639\u0648\u0627\u0645\u0644.\n\u0665. \u0645\u0631\u0627\u0642\u0628\u0629 \u0633\u062c\u0644\u0627\u062a FTP.',
        'SSH-Patator':'\u0661. \u062a\u0639\u0637\u064a\u0644 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629 \u0628\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u2014 \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0627\u0644\u0645\u0641\u062a\u0627\u062d \u0627\u0644\u0639\u0627\u0645 \u0641\u0642\u0637.\n\u0662. \u0646\u0634\u0631 fail2ban \u0644\u062d\u0638\u0631 IPs \u0630\u0627\u062a \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u0641\u0627\u0634\u0644\u0629 \u0645\u0641\u0631\u0637\u0629.\n\u0663. \u062a\u063a\u064a\u064a\u0631 SSH \u0625\u0644\u0649 \u0645\u0646\u0641\u0630 \u063a\u064a\u0631 \u0642\u064a\u0627\u0633\u064a.\n\u0664. \u062a\u0642\u064a\u064a\u062f \u0648\u0635\u0648\u0644 SSH \u0644\u0646\u0637\u0627\u0642\u0627\u062a IP \u0645\u0648\u062b\u0648\u0642\u0629 \u0641\u0642\u0637.\n\u0665. \u062a\u0641\u0639\u064a\u0644 MFA \u0644\u0640 SSH (PAM).',
        'Bot':'\u0661. \u0639\u0632\u0644 \u0627\u0644\u062c\u0647\u0627\u0632 \u0627\u0644\u0645\u062e\u062a\u0631\u0642 \u0641\u0648\u0631\u064b\u0627 \u0639\u0646 \u0627\u0644\u0634\u0628\u0643\u0629.\n\u0662. \u0625\u062c\u0631\u0627\u0621 \u0641\u062d\u0635 \u0634\u0627\u0645\u0644 \u0644\u0628\u0631\u0627\u0645\u062c \u0627\u0644\u062e\u0628\u064a\u062b\u0629.\n\u0663. \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u062d\u0631\u0643\u0629 C2 \u0641\u064a \u0627\u0644\u0633\u062c\u0644\u0627\u062a.\n\u0664. \u0645\u0631\u0627\u062c\u0639\u0629 \u0645\u0647\u0627\u0645 \u0628\u062f\u0621 \u0627\u0644\u062a\u0634\u063a\u064a\u0644 \u0648\u0627\u0644\u0645\u0647\u0627\u0645 \u0627\u0644\u0645\u062c\u062f\u0648\u0644\u0629.\n\u0665. \u0625\u0639\u0627\u062f\u0629 \u062a\u0639\u064a\u064a\u0646 \u062c\u0645\u064a\u0639 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0627\u0639\u062a\u0645\u0627\u062f.\n\u0666. \u062d\u0638\u0631 \u062d\u0631\u0643\u0629 C2 \u0639\u0644\u0649 \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.',
        'Heartbleed':'\u0661. \u062a\u0631\u0642\u064a\u0629 OpenSSL \u0641\u0648\u0631\u064b\u0627 (CVE-2014-0160).\n\u0662. \u0625\u0644\u063a\u0627\u0621 \u0648\u0625\u0639\u0627\u062f\u0629 \u0625\u0635\u062f\u0627\u0631 \u0634\u0647\u0627\u062f\u0627\u062a TLS.\n\u0663. \u062a\u062f\u0648\u064a\u0631 \u0645\u0641\u0627\u062a\u064a\u062d \u0627\u0644\u062e\u0627\u062f\u0645 \u0627\u0644\u062e\u0627\u0635\u0629.\n\u0664. \u0625\u0628\u0637\u0627\u0644 \u0631\u0645\u0648\u0632 \u0627\u0644\u062c\u0644\u0633\u0629 \u0627\u0644\u0646\u0634\u0637\u0629.\n\u0665. \u062a\u063a\u064a\u064a\u0631 \u062c\u0645\u064a\u0639 \u0643\u0644\u0645\u0627\u062a \u0627\u0644\u0645\u0631\u0648\u0631.',
        'Infiltration':'\u0661. \u0639\u0632\u0644 \u062c\u0645\u064a\u0639 \u0627\u0644\u0623\u0646\u0638\u0645\u0629 \u0627\u0644\u0645\u062a\u0623\u062b\u0631\u0629 \u0641\u0648\u0631\u064b\u0627.\n\u0662. \u0627\u0644\u062d\u0641\u0627\u0638 \u0639\u0644\u0649 \u0627\u0644\u0623\u062f\u0644\u0629 \u0627\u0644\u062c\u0646\u0627\u0626\u064a\u0629.\n\u0663. \u062a\u0637\u0628\u064a\u0642 \u0625\u062c\u0631\u0627\u0621\u0627\u062a \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b.\n\u0664. \u062a\u062d\u062f\u064a\u062f \u0645\u062a\u062c\u0647 \u0627\u0644\u0648\u0635\u0648\u0644 \u0627\u0644\u0623\u0648\u0644\u064a \u0648\u062a\u0635\u062d\u064a\u062d \u0627\u0644\u062b\u063a\u0631\u0629.\n\u0665. \u0645\u0631\u0627\u062c\u0639\u0629 \u0645\u0633\u0627\u0631\u0627\u062a \u0627\u0644\u062d\u0631\u0643\u0629 \u0627\u0644\u062c\u0627\u0646\u0628\u064a\u0629.\n\u0666. \u0625\u062c\u0631\u0627\u0621 \u0645\u0631\u0627\u062c\u0639\u0629 \u0643\u0627\u0645\u0644\u0629 \u0644\u0645\u0627 \u0628\u0639\u062f \u0627\u0644\u062d\u0627\u062f\u062b\u0629.',
        'Web Attack Brute Force':'\u0661. \u062a\u0637\u0628\u064a\u0642 CAPTCHA \u0639\u0644\u0649 \u0646\u0645\u0627\u0630\u062c \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644.\n\u0662. \u062a\u0641\u0639\u064a\u0644 \u0642\u0641\u0644 \u0627\u0644\u062d\u0633\u0627\u0628.\n\u0663. \u062a\u062d\u062f\u064a\u062f \u0645\u0639\u062f\u0644 \u0637\u0644\u0628\u0627\u062a \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644.\n\u0664. \u062a\u0646\u0628\u064a\u0647 \u0639\u0646\u062f \u0627\u0631\u062a\u0641\u0627\u0639 \u062d\u0627\u0644\u0627\u062a \u0627\u0644\u0641\u0634\u0644.\n\u0665. \u0641\u0631\u0636 \u0633\u064a\u0627\u0633\u0627\u062a \u0643\u0644\u0645\u0627\u062a \u0645\u0631\u0648\u0631 \u0642\u0648\u064a\u0629 \u0648MFA.',
        'Web Attack XSS':'\u0661. \u062a\u0639\u0642\u064a\u0645 \u0648\u062a\u0631\u0645\u064a\u0632 \u062c\u0645\u064a\u0639 \u0645\u062f\u062e\u0644\u0627\u062a HTML.\n\u0662. \u062a\u0637\u0628\u064a\u0642 \u0633\u064a\u0627\u0633\u0629 CSP \u0635\u0627\u0631\u0645\u0629.\n\u0663. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 HttpOnly \u0648Secure \u0639\u0644\u0649 \u0645\u0644\u0641\u0627\u062a \u0627\u0644\u062a\u0639\u0631\u064a\u0641.\n\u0664. \u062a\u0641\u0639\u064a\u0644 X-XSS-Protection.\n\u0665. \u0646\u0634\u0631 WAF \u0628\u0642\u0648\u0627\u0639\u062f XSS.',
        'Web Attack Sql Injection':'\u0661. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0627\u0644\u0627\u0633\u062a\u0639\u0644\u0627\u0645\u0627\u062a \u0627\u0644\u0645\u0639\u0644\u0645\u0629 \u0641\u0642\u0637.\n\u0662. \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0635\u062d\u0629 \u0627\u0644\u0645\u062f\u062e\u0644\u0627\u062a.\n\u0663. \u0646\u0634\u0631 WAF \u0628\u0642\u0648\u0627\u0639\u062f SQL.\n\u0664. \u062a\u062d\u062f\u064a\u062f \u0635\u0644\u0627\u062d\u064a\u0627\u062a \u0645\u0633\u062a\u062e\u062f\u0645 \u0642\u0627\u0639\u062f\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a.\n\u0665. \u062a\u0641\u0639\u064a\u0644 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u0627\u0633\u062a\u0639\u0644\u0627\u0645\u0627\u062a.',
    }
    _ATDEF = _ATDEF_AR if is_rtl else _ATDEF_EN
    _def_default = ('\u0661. \u0627\u062d\u062c\u0628 \u0639\u0646\u0627\u0648\u064a\u0646 IP \u0627\u0644\u0645\u0647\u0627\u062c\u0645\u064a\u0646 \u0639\u0644\u0649 \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.\n\u0662. \u0627\u0644\u062a\u062d\u0642\u064a\u0642 \u0641\u064a \u0627\u0644\u0623\u0646\u0638\u0645\u0629 \u0627\u0644\u0645\u062a\u0623\u062b\u0631\u0629.\n\u0663. \u0645\u0631\u0627\u062c\u0639\u0629 \u0627\u0644\u0633\u062c\u0644\u0627\u062a \u0628\u062d\u062b\u064b\u0627 \u0639\u0646 \u062a\u0633\u0631\u064a\u0628 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a.\n\u0664. \u0627\u0644\u062a\u0635\u0639\u064a\u062f \u0625\u0644\u0649 \u0641\u0631\u064a\u0642 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b.\n\u0665. \u062a\u062d\u062f\u064a\u062b \u062a\u0648\u0642\u064a\u0639\u0627\u062a IDS/IPS.'
        if is_rtl else
        '1. Block attacker IPs at the firewall.\n2. Investigate affected systems.\n3. Review logs for data exfiltration.\n4. Escalate to incident response.\n5. Update IDS/IPS signatures.')
    defense = ''
    for k,v in _ATDEF.items():
        if k.lower() in attack_name.lower(): defense = v; break
    if not defense:
        defense = _def_default

    section(ps('Defense Recommendations'))
    _font('',10); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN)
    pdf.multi_cell(CONTENT_W,5,_txt(defense),align=_a,new_x='LMARGIN',new_y='NEXT')

    # ── Flow sample table ──────────────────────────────────────────────────────
    if flows:
        pdf.add_page()
        section(ps('Flow Sample'))
        th((ps('Flow ID'),20),(ps('Src IP'),35),(ps('Src Port'),18),(ps('Dst IP'),35),(ps('Dst Port'),18),(ps('Protocol'),18),(ps('Conf %'),16))
        for i,r in enumerate(flows[:20]):
            tr((_safe(str(r.get('flow_id',''))),20),(_safe(r.get('src_ip','')),35),
               (_safe(str(r.get('src_port',''))),18),(_safe(r.get('dst_ip','')),35),
               (_safe(str(r.get('dst_port',''))),18),(_safe(str(r.get('protocol',''))),18),
               (_safe(str(r.get('confidence',0))),16),alt=(i%2==1))

    safe_name = attack_name.replace(' ','_').replace('/','_')

    # ── Companion CSV ──────────────────────────────────────────────────────────
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(['=== ATTACK CARD EXPORT ==='])
    writer.writerow(['Attack Type', attack_name])
    writer.writerow(['Severity', sev])
    writer.writerow(['Flow Count', count])
    writer.writerow(['% of Total', f'{pct}%'])
    writer.writerow(['Avg Confidence %', avg_conf])
    writer.writerow([])
    writer.writerow(['=== TOP SOURCE IPs ==='])
    writer.writerow(['Source IP', 'Flows', 'Avg Confidence %', 'Target IPs', 'Ports'])
    for ip, info in top_ips:
        ac = round(sum(info['confidences']) / len(info['confidences']), 1) if info['confidences'] else 0
        writer.writerow([_csv_safe(ip), info['count'], ac,
                         _csv_safe('|'.join(list(info['dst_ips'])[:10])),
                         _csv_safe('|'.join(sorted(list(info['ports']))[:10]))])
    writer.writerow([])
    writer.writerow(['=== ALL FLOWS FOR THIS ATTACK ==='])
    writer.writerow(['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Confidence %'])
    for r in flows:
        writer.writerow([r.get('flow_id', ''), _csv_safe(r.get('src_ip', '')), r.get('src_port', ''),
                         _csv_safe(r.get('dst_ip', '')), r.get('dst_port', ''), r.get('protocol', ''),
                         r.get('confidence', 0)])

    # ── ZIP bundle ─────────────────────────────────────────────────────────────
    pdf_fname = f'bastion_attack_{safe_name}_{scan_id}.pdf'
    csv_fname = f'bastion_attack_{safe_name}_{scan_id}.csv'
    zip_fname = f'bastion_attack_{safe_name}_{scan_id}.zip'
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(pdf_fname, bytes(pdf.output()))
        zf.writestr(csv_fname, csv_buf.getvalue())
    zip_buf.seek(0)
    return send_file(zip_buf, as_attachment=True,
                     download_name=_safe(zip_fname),
                     mimetype='application/zip')

# ── History ───────────────────────────────────────────────────────────────────
@app.route('/history')
@login_required
def history():
    return render_template('history.html', history=load_user_history())

@app.route('/history/<scan_id>')
@login_required
def history_detail(scan_id):
    entry, results = load_results(scan_id)
    if entry is None:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))
    sev_order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'SAFE':0,'UNKNOWN':1}
    top_sev   = max((r.get('severity','SAFE') for r in results),
                    key=lambda s: sev_order.get(s,0), default='SAFE')
    # Show malicious flows first so threats are always visible in the 2000-row window
    results_sorted = sorted(results, key=lambda r: (0 if r.get('is_malicious') else 1, -r.get('rank', 0)))[:2000]
    return render_template('history_detail.html', entry=entry,
                           results=results_sorted, top_severity=top_sev)

@app.route('/history/<scan_id>/download')
@login_required
def download_flows(scan_id):
    entry, _ = load_results(scan_id)
    if entry is None: return 'Not found', 404
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        return 'Access denied', 403
    fp = Path(entry.get('flows_file') or '')
    if not fp.exists(): return 'File not found', 404
    return send_file(fp, as_attachment=True, download_name=f'sentinel_scan_{scan_id}.csv')

# ── Geo Map ───────────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>/map')
@login_required
def geo_map(scan_id):
    entry, _ = load_results(scan_id)
    if not entry:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))
    return render_template('geo_map.html', entry=entry)

@app.route('/api/geo/<scan_id>')
@login_required
def api_geo(scan_id):
    entry, rows = load_results(scan_id)
    if not entry:
        return jsonify(error=t('api not found')), 404
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        return jsonify(error=t('api access denied')), 403

    # Collect unique non-private IPs
    ip_info = {}
    for r in rows:
        for key in ('src_ip', 'dst_ip'):
            ip = r.get(key, 'N/A')
            if ip and ip != 'N/A' and not is_private_ip(ip):
                if ip not in ip_info:
                    ip_info[ip] = {'count': 0, 'is_malicious': False}
                ip_info[ip]['count'] += 1
                if r.get('is_malicious'):
                    ip_info[ip]['is_malicious'] = True

    ips = list(ip_info.keys())[:100]
    if not ips:
        return jsonify([])

    try:
        resp = req_lib.post('http://ip-api.com/batch', json=[
            {'query': ip, 'fields': 'status,country,lat,lon,query'} for ip in ips
        ], timeout=15)
        geo_data = resp.json()
    except Exception as e:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=t('api internal error')), 500

    results = []
    for item in geo_data:
        if item.get('status') == 'success':
            ip = item['query']
            results.append({
                'ip':          ip,
                'lat':         item.get('lat', 0),
                'lon':         item.get('lon', 0),
                'country':     item.get('country', 'Unknown'),
                'count':       ip_info.get(ip, {}).get('count', 0),
                'is_malicious': ip_info.get(ip, {}).get('is_malicious', False),
            })
    return jsonify(results)

# ── SHAP ──────────────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>/shap')
@login_required
def shap_page(scan_id):
    entry, _ = load_results(scan_id)
    if not entry:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))
    return render_template('shap_page.html', entry=entry)

@app.route('/api/shap/<scan_id>')
@login_required
def api_shap(scan_id):
    entry, rows = load_results(scan_id)
    if not entry:
        return jsonify(error=t('api not found')), 404
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        return jsonify(error=t('api access denied')), 403

    try:
        import shap as shap_lib
    except ImportError:
        return jsonify(error=t('api shap not installed')), 503

    if model is None or preprocessor is None or feature_names is None:
        return jsonify(error=t('api model not loaded')), 503

    # Get first 50 malicious flows
    mal_rows = [r for r in rows if r.get('is_malicious')][:50]
    if not mal_rows:
        return jsonify(features=[], importances=[])

    # Read original flow CSV to get real ML features (result rows don't have them)
    flows_file = Path(entry.get('flows_file', ''))
    if flows_file.exists():
        df_flows = pd.read_csv(flows_file)
        df_flows.columns = df_flows.columns.str.strip()
        df_flows.replace([np.inf, -np.inf], np.nan, inplace=True)
        # Get indices of malicious flows (flow_id is 1-based)
        mal_indices = [r.get('flow_id', 0) - 1 for r in mal_rows if r.get('flow_id')]
        mal_indices = [i for i in mal_indices if 0 <= i < len(df_flows)]
        if mal_indices:
            df_mal = df_flows.iloc[mal_indices]
        else:
            df_mal = df_flows.head(len(mal_rows))
        X = pd.DataFrame(0.0, index=range(len(df_mal)), columns=feature_names)
        for col in feature_names:
            if col in df_mal.columns:
                X[col] = df_mal[col].values
        X = X.fillna(X.median(numeric_only=True)).fillna(0)
    else:
        # Fallback: use zeros (SHAP won't be meaningful but won't crash)
        X = pd.DataFrame(0.0, index=range(len(mal_rows)), columns=feature_names)

    try:
        X_scaled = preprocessor.transform(X)
        # Use XGB model if available
        xgb_path = MODELS_DIR / 'xgb_model.pkl'
        if xgb_path.exists():
            xgb_model = joblib.load(xgb_path)
            explainer = shap_lib.TreeExplainer(xgb_model)
            shap_values = explainer.shap_values(X_scaled)
        else:
            explainer = shap_lib.Explainer(model, X_scaled[:10])
            shap_values = explainer(X_scaled).values

        if isinstance(shap_values, list):
            shap_vals = np.abs(np.array(shap_values)).mean(axis=0).mean(axis=0)
        else:
            if shap_values.ndim == 3:
                shap_vals = np.abs(shap_values).mean(axis=2).mean(axis=0)
            else:
                shap_vals = np.abs(shap_values).mean(axis=0)

        # Top 10
        indices = np.argsort(shap_vals)[::-1][:10]
        features = [feature_names[i] for i in indices]
        importances = [round(float(shap_vals[i]), 4) for i in indices]
        return jsonify(features=features, importances=importances)
    except Exception as e:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=t('api internal error')), 500

# ── PDF Report ────────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>/export/pdf')
@login_required
def export_pdf(scan_id):
    entry, rows = load_results(scan_id)
    if not entry:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))
    try:
        from fpdf import FPDF
    except ImportError:
        flash(t('flash fpdf2 missing'), 'error')
        return redirect(url_for('result', scan_id=scan_id))

    def _safe(s):
        v = str(s).replace('\u2014','-').replace('\u2013','-').replace('\u2019',"'").replace('\u2018',"'").replace('\ufffd','?')
        return v.encode('latin-1', errors='replace').decode('latin-1')
    # ── Arabic support ─────────────────────────────────────────────────────────
    lang = session.get('lang', cfg('language', 'en'))
    is_rtl = lang == 'ar'
    _arabic_ok = False; _arabic_font = None; _arabic_font_bold = None
    if is_rtl:
        try:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Regular.ttf',
                        BASE_DIR / 'static/fonts/Amiri-Regular.ttf',
                        Path('C:/Windows/Fonts/Arial.ttf')]:
                if _fp.exists(): _arabic_font = str(_fp); _arabic_ok = True; break
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Bold.ttf',
                        BASE_DIR / 'static/fonts/NotoNaskhArabic-SemiBold.ttf']:
                if _fp.exists(): _arabic_font_bold = str(_fp); break
        except ImportError:
            pass

    def _txt(s):
        v = str(s)
        if is_rtl and _arabic_ok:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            return bidi_display(arabic_reshaper.reshape(v))
        return _safe(v)

    def _fit(text, w):
        maxc = max(1, int(w / 1.9))
        s = _txt(str(text)) if (is_rtl and _arabic_ok) else _safe(str(text))
        return (s[:maxc-2]+'..') if len(s) > maxc else s

    # ── PDF string translations ────────────────────────────────────────────────
    _PDF_STR = {
        'en': {
            'report subtitle': 'Network Intrusion Detection Report',
            'Scan ID': 'Scan ID', 'File Analyzed': 'File Analyzed',
            'Total Flows': 'Total Flows', 'Malicious Flows': 'Malicious Flows',
            'Benign Flows': 'Benign Flows', 'Detection Rate': 'Detection Rate',
            'Analyst': 'Analyst', 'Generated': 'Generated',
            'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'SAFE': 'SAFE', 'UNKNOWN': 'UNKNOWN',
            's1 title': 'Section 1 \u2014 Dashboard Summary',
            's1 desc': 'Overview of all analyses and traffic distribution for this scan.',
            'Total Flows Analyzed': 'Total Flows Analyzed',
            'Benign / Safe Flows': 'Benign / Safe Flows',
            'Average Confidence': 'Average Confidence',
            'Unique Attacker IPs': 'Unique Attacker IPs',
            'Attack Types Detected': 'Attack Types Detected',
            'Traffic Volume': 'Traffic Volume',
            'Malicious': 'Malicious', 'Benign': 'Benign',
            'Severity Distribution': 'Severity Distribution',
            'Severity': 'Severity', 'Flow Count': 'Flow Count',
            'Percentage': 'Percentage', 'Meaning': 'Meaning',
            'Attack Type Breakdown': 'Attack Type Breakdown',
            'atk bd desc': 'Top 8 attack types. Full breakdown in companion CSV.',
            'Attack Type': 'Attack Type', '% of Threats': '% of Threats',
            'Top Attacker IPs': 'Top Attacker IPs',
            'top ips desc': 'Top 5 by malicious flow count. Full attacker profiles in Section 2.',
            'Source IP': 'Source IP', 'Primary Attack': 'Primary Attack',
            'Suspected Attacker': 'Suspected Attacker',
            'card subtitle': '{count} malicious flows  |  Avg confidence: {avg_conf}%',
            'Reason for Suspicion': 'Reason for Suspicion',
            'flows flagged': '{count} flows flagged as attacks',
            'Highest Severity': 'Highest Severity',
            'Average ML Confidence': 'Average ML Confidence',
            'Attack Types Observed': 'Attack Types Observed',
            'Target IPs': 'Target IPs', 'Target Ports': 'Target Ports',
            'Attack Analysis': 'Attack Analysis',
            'Why Classified': 'Why This Was Classified as an Attack',
            'Defense Recommendations': 'Defense Recommendations',
            'For atk': 'For {atk}:',
            'default defense': '1. Block this IP at the perimeter firewall.\n2. Investigate affected systems for compromise.\n3. Review logs for any data exfiltration.\n4. Escalate to the incident response team.\n5. Update IDS/IPS signatures.',
            'csv ref': 'Full data available in companion file: {filename}',
            'sev_desc_critical': 'an immediate threat requiring urgent action',
            'sev_desc_high': 'a likely active attack',
            'sev_desc_medium': 'suspicious activity requiring investigation',
            'ml_analyzed': 'The BASTION IDS ML model analyzed {count} network flows originating from {ip} and classified them as malicious with an average confidence of {avg_conf}%.',
            'ml_patterns': 'The model identified patterns consistent with: {attacks}.',
            'ml_key_signals': 'Key signals: abnormal packet rates, unusual flow durations, high byte-to-packet ratios, and connection behavior deviating significantly from baseline benign traffic.',
            'ml_highest_sev': 'The highest severity assigned was {max_sev}, indicating {severity_desc}.',
            'sev_exp_CRITICAL': 'Confirmed attack requiring immediate action.',
            'sev_exp_HIGH': 'Active attack, urgent investigation needed.',
            'sev_exp_MEDIUM': 'Suspicious, warrants investigation.',
            'sev_exp_SAFE': 'Normal benign traffic.',
            'sev_exp_UNKNOWN': 'Unclassified, manual review needed.',
        },
        'ar': {
            'report subtitle': '\u062a\u0642\u0631\u064a\u0631 \u0627\u0643\u062a\u0634\u0627\u0641 \u0627\u0644\u062a\u0633\u0644\u0644 \u0625\u0644\u0649 \u0627\u0644\u0634\u0628\u0643\u0629',
            'Scan ID': '\u0645\u0639\u0631\u0641 \u0627\u0644\u0641\u062d\u0635', 'File Analyzed': '\u0627\u0644\u0645\u0644\u0641 \u0627\u0644\u0645\u062d\u0644\u0644',
            'Total Flows': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a', 'Malicious Flows': '\u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u0636\u0627\u0631\u0629',
            'Benign Flows': '\u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u062d\u0645\u064a\u062f\u0629', 'Detection Rate': '\u0645\u0639\u062f\u0644 \u0627\u0644\u0643\u0634\u0641',
            'Analyst': '\u0627\u0644\u0645\u062d\u0644\u0644', 'Generated': '\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u0625\u0646\u0634\u0627\u0621',
            'CRITICAL': '\u062d\u0631\u062c', 'HIGH': '\u0639\u0627\u0644\u0650', 'MEDIUM': '\u0645\u062a\u0648\u0633\u0637', 'SAFE': '\u0622\u0645\u0646', 'UNKNOWN': '\u063a\u064a\u0631 \u0645\u0639\u0631\u0648\u0641',
            's1 title': '\u0627\u0644\u0642\u0633\u0645 \u0627\u0644\u0623\u0648\u0644 \u2014 \u0645\u0644\u062e\u0635 \u0644\u0648\u062d\u0629 \u0627\u0644\u062a\u062d\u0643\u0645',
            's1 desc': '\u0646\u0638\u0631\u0629 \u0639\u0627\u0645\u0629 \u0639\u0644\u0649 \u062c\u0645\u064a\u0639 \u0627\u0644\u062a\u062d\u0644\u064a\u0644\u0627\u062a \u0648\u062a\u0648\u0632\u064a\u0639 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0644\u0647\u0630\u0627 \u0627\u0644\u0641\u062d\u0635.',
            'Total Flows Analyzed': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u0645\u062d\u0644\u0644\u0629',
            'Benign / Safe Flows': '\u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u062d\u0645\u064a\u062f\u0629 / \u0627\u0644\u0622\u0645\u0646\u0629',
            'Average Confidence': '\u0645\u062a\u0648\u0633\u0637 \u0627\u0644\u062b\u0642\u0629',
            'Unique Attacker IPs': '\u0639\u0646\u0627\u0648\u064a\u0646 IP \u0627\u0644\u0645\u0647\u0627\u062c\u0645\u0629 \u0627\u0644\u0641\u0631\u064a\u062f\u0629',
            'Attack Types Detected': '\u0623\u0646\u0648\u0627\u0639 \u0627\u0644\u0647\u062c\u0645\u0627\u062a \u0627\u0644\u0645\u0643\u062a\u0634\u0641\u0629',
            'Traffic Volume': '\u062d\u062c\u0645 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631',
            'Malicious': '\u0636\u0627\u0631', 'Benign': '\u062d\u0645\u064a\u062f',
            'Severity Distribution': '\u062a\u0648\u0632\u064a\u0639 \u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u062e\u0637\u0648\u0631\u0629',
            'Severity': '\u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u062e\u0637\u0648\u0631\u0629', 'Flow Count': '\u0639\u062f\u062f \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a',
            'Percentage': '\u0627\u0644\u0646\u0633\u0628\u0629 \u0627\u0644\u0645\u0626\u0648\u064a\u0629', 'Meaning': '\u0627\u0644\u0645\u0639\u0646\u0649',
            'Attack Type Breakdown': '\u062a\u0641\u0635\u064a\u0644 \u0623\u0646\u0648\u0627\u0639 \u0627\u0644\u0647\u062c\u0645\u0627\u062a',
            'atk bd desc': '\u0623\u0639\u0644\u0649 8 \u0623\u0646\u0648\u0627\u0639 \u0647\u062c\u0645\u0627\u062a. \u0627\u0644\u062a\u0641\u0627\u0635\u064a\u0644 \u0627\u0644\u0643\u0627\u0645\u0644\u0629 \u0641\u064a \u0645\u0644\u0641 CSV \u0627\u0644\u0645\u0631\u0641\u0642.',
            'Attack Type': '\u0646\u0648\u0639 \u0627\u0644\u0647\u062c\u0648\u0645', '% of Threats': '% \u0645\u0646 \u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a',
            'Top Attacker IPs': '\u0623\u0639\u0644\u0649 \u0639\u0646\u0627\u0648\u064a\u0646 IP \u0645\u0647\u0627\u062c\u0645\u0629',
            'top ips desc': '\u0623\u0639\u0644\u0649 5 \u0628\u062d\u0633\u0628 \u0639\u062f\u062f \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u0636\u0627\u0631\u0629. \u0645\u0644\u0641\u0627\u062a \u062a\u0639\u0631\u064a\u0641 \u0627\u0644\u0645\u0647\u0627\u062c\u0645\u064a\u0646 \u0641\u064a \u0627\u0644\u0642\u0633\u0645 \u0627\u0644\u062b\u0627\u0646\u064a.',
            'Source IP': '\u0639\u0646\u0648\u0627\u0646 IP \u0627\u0644\u0645\u0635\u062f\u0631', 'Primary Attack': '\u0627\u0644\u0647\u062c\u0648\u0645 \u0627\u0644\u0631\u0626\u064a\u0633\u064a',
            'Suspected Attacker': '\u0645\u0647\u0627\u062c\u0645 \u0645\u0634\u062a\u0628\u0647 \u0628\u0647',
            'card subtitle': '{count} \u062a\u062f\u0641\u0642\u0627\u062a \u0636\u0627\u0631\u0629  |  \u0645\u062a\u0648\u0633\u0637 \u0627\u0644\u062b\u0642\u0629: {avg_conf}%',
            'Reason for Suspicion': '\u0623\u0633\u0628\u0627\u0628 \u0627\u0644\u0627\u0634\u062a\u0628\u0627\u0647',
            'flows flagged': '{count} \u062a\u062f\u0641\u0642\u0627\u062a \u0645\u064f\u0635\u0646\u064e\u0651\u0641\u0629 \u0643\u0647\u062c\u0645\u0627\u062a',
            'Highest Severity': '\u0623\u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u062e\u0637\u0648\u0631\u0629',
            'Average ML Confidence': '\u0645\u062a\u0648\u0633\u0637 \u062b\u0642\u0629 \u0627\u0644\u0646\u0645\u0648\u0630\u062c',
            'Attack Types Observed': '\u0623\u0646\u0648\u0627\u0639 \u0627\u0644\u0647\u062c\u0645\u0627\u062a \u0627\u0644\u0645\u0631\u0635\u0648\u062f\u0629',
            'Target IPs': '\u0639\u0646\u0627\u0648\u064a\u0646 IP \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641\u0629', 'Target Ports': '\u0627\u0644\u0645\u0646\u0627\u0641\u0630 \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641\u0629',
            'Attack Analysis': '\u062a\u062d\u0644\u064a\u0644 \u0627\u0644\u0647\u062c\u0645\u0627\u062a',
            'Why Classified': '\u0644\u0645\u0627\u0630\u0627 \u0635\u064f\u0646\u0650\u0651\u0641 \u0647\u0630\u0627 \u0643\u0647\u062c\u0648\u0645',
            'Defense Recommendations': '\u062a\u0648\u0635\u064a\u0627\u062a \u0627\u0644\u062f\u0641\u0627\u0639',
            'For atk': '\u0644\u0644\u0647\u062c\u0648\u0645 {atk}:',
            'default defense': '1. \u0627\u062d\u062c\u0628 \u0639\u0646\u0648\u0627\u0646 IP \u0647\u0630\u0627 \u0639\u0644\u0649 \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629 \u0627\u0644\u062e\u0627\u0631\u062c\u064a.\n2. \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u0623\u0646\u0638\u0645\u0629 \u0627\u0644\u0645\u062a\u0636\u0631\u0631\u0629 \u0628\u062d\u062b\u0627\u064b \u0639\u0646 \u0627\u062e\u062a\u0631\u0627\u0642.\n3. \u0645\u0631\u0627\u062c\u0639\u0629 \u0627\u0644\u0633\u062c\u0644\u0627\u062a \u0628\u062d\u062b\u0627\u064b \u0639\u0646 \u0623\u064a \u062a\u0633\u0631\u064a\u0628 \u0644\u0644\u0628\u064a\u0627\u0646\u0627\u062a.\n4. \u0627\u0644\u062a\u0635\u0639\u064a\u062f \u0625\u0644\u0649 \u0641\u0631\u064a\u0642 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b.\n5. \u062a\u062d\u062f\u064a\u062b \u062a\u0648\u0642\u064a\u0639\u0627\u062a IDS/IPS.',
            'csv ref': '\u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0643\u0627\u0645\u0644\u0629 \u0645\u062a\u0627\u062d\u0629 \u0641\u064a \u0627\u0644\u0645\u0644\u0641 \u0627\u0644\u0645\u0631\u0641\u0642: {filename}',
            'sev_desc_critical': '\u062a\u0647\u062f\u064a\u062f \u0641\u0648\u0631\u064a \u064a\u0633\u062a\u062f\u0639\u064a \u0625\u062c\u0631\u0627\u0621\u064b \u0639\u0627\u062c\u0644\u0627\u064b',
            'sev_desc_high': '\u0647\u062c\u0648\u0645 \u0646\u0634\u0637 \u0645\u062d\u062a\u0645\u0644',
            'sev_desc_medium': '\u0646\u0634\u0627\u0637 \u0645\u0634\u0628\u0648\u0647 \u064a\u0633\u062a\u0648\u062c\u0628 \u0627\u0644\u062a\u062d\u0642\u064a\u0642',
            'ml_analyzed': '\u062d\u0644\u0651\u0644 \u0646\u0645\u0648\u0630\u062c \u0627\u0644\u062a\u0639\u0644\u0645 \u0627\u0644\u0622\u0644\u064a \u0641\u064a BASTION IDS {count} \u062a\u062f\u0641\u0642\u0627\u064b \u0634\u0628\u0643\u064a\u0627\u064b \u0646\u0634\u0623 \u0645\u0646 {ip} \u0648\u0635\u0646\u0651\u0641\u0647\u0627 \u0639\u0644\u0649 \u0623\u0646\u0647\u0627 \u0636\u0627\u0631\u0629 \u0628\u0645\u062a\u0648\u0633\u0637 \u062b\u0642\u0629 \u0628\u0644\u063a {avg_conf}%.',
            'ml_patterns': '\u0631\u0635\u062f \u0627\u0644\u0646\u0645\u0648\u0630\u062c \u0623\u0646\u0645\u0627\u0637\u0627\u064b \u062a\u062a\u0648\u0627\u0641\u0642 \u0645\u0639: {attacks}.',
            'ml_key_signals': '\u0627\u0644\u0625\u0634\u0627\u0631\u0627\u062a \u0627\u0644\u0631\u0626\u064a\u0633\u064a\u0629: \u0645\u0639\u062f\u0644\u0627\u062a \u062d\u0632\u0645 \u063a\u064a\u0631 \u0637\u0628\u064a\u0639\u064a\u0629\u060c \u0648\u0645\u062f\u062f \u062a\u062f\u0641\u0642 \u063a\u064a\u0631 \u0645\u0623\u0644\u0648\u0641\u0629\u060c \u0648\u0646\u0633\u0628 \u0628\u0627\u064a\u062a \u0625\u0644\u0649 \u062d\u0632\u0645\u0629 \u0645\u0631\u062a\u0641\u0639\u0629\u060c \u0648\u0633\u0644\u0648\u0643 \u0627\u062a\u0635\u0627\u0644 \u064a\u0646\u062d\u0631\u0641 \u0628\u0634\u0643\u0644 \u0645\u0644\u062d\u0648\u0638 \u0639\u0646 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u062d\u0645\u064a\u062f\u0629 \u0627\u0644\u0623\u0633\u0627\u0633\u064a\u0629.',
            'ml_highest_sev': '\u0623\u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u062e\u0637\u0648\u0631\u0629 \u0645\u064f\u0639\u064a\u064e\u0651\u0646 \u0643\u0627\u0646 {max_sev}\u060c \u0645\u0645\u0627 \u064a\u0634\u064a\u0631 \u0625\u0644\u0649 {severity_desc}.',
            'sev_exp_CRITICAL': '\u0647\u062c\u0648\u0645 \u0645\u0624\u0643\u062f \u064a\u0633\u062a\u062f\u0639\u064a \u062a\u062f\u062e\u0644\u0627\u064b \u0641\u0648\u0631\u064a\u0627\u064b.',
            'sev_exp_HIGH': '\u0647\u062c\u0648\u0645 \u0646\u0634\u0637\u060c \u064a\u0633\u062a\u0648\u062c\u0628 \u0627\u0644\u062a\u062d\u0642\u064a\u0642 \u0627\u0644\u0639\u0627\u062c\u0644.',
            'sev_exp_MEDIUM': '\u0646\u0634\u0627\u0637 \u0645\u0634\u0628\u0648\u0647 \u064a\u0633\u062a\u062d\u0642 \u0627\u0644\u062a\u062d\u0642\u064a\u0642.',
            'sev_exp_SAFE': '\u062d\u0631\u0643\u0629 \u0645\u0631\u0648\u0631 \u0637\u0628\u064a\u0639\u064a\u0629 \u062d\u0645\u064a\u062f\u0629.',
            'sev_exp_UNKNOWN': '\u063a\u064a\u0631 \u0645\u0635\u0646\u0641\u060c \u064a\u062a\u0637\u0644\u0628 \u0645\u0631\u0627\u062c\u0639\u0629 \u064a\u062f\u0648\u064a\u0629.',
        }
    }
    def ps(key, **kwargs):
        s = _PDF_STR.get(lang, _PDF_STR['en']).get(key, _PDF_STR['en'].get(key, key))
        return s.format(**kwargs) if kwargs else s

    # ── Data ──────────────────────────────────────────────────────────────────
    total_flows = entry.get('total_flows', 0)
    malicious   = entry.get('malicious_flows', 0)
    benign      = entry.get('benign_flows', 0)
    detect_rate = round(malicious / total_flows * 100, 1) if total_flows else 0
    threat_bd   = entry.get('threat_breakdown', {})
    sev_bd      = entry.get('severity_breakdown', {})
    mal_rows    = [r for r in rows if r.get('is_malicious')]

    # Build per-IP attacker profiles
    ip_map = {}
    for r in mal_rows:
        ip = r.get('src_ip', 'N/A')
        lbl = r.get('label', 'Unknown'); sev = r.get('severity', 'UNKNOWN')
        conf = float(r.get('confidence', 0))
        if ip not in ip_map:
            ip_map[ip] = {'count':0,'attacks':set(),'severities':[],'confidences':[],'dst_ips':set(),'ports':set()}
        ip_map[ip]['count'] += 1; ip_map[ip]['attacks'].add(lbl)
        ip_map[ip]['severities'].append(sev); ip_map[ip]['confidences'].append(conf)
        dst = r.get('dst_ip','')
        if dst: ip_map[ip]['dst_ips'].add(dst)
        dport = r.get('dst_port','')
        if dport: ip_map[ip]['ports'].add(str(dport))

    SEV_ORDER = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'UNKNOWN':3,'SAFE':4}
    top_ips = sorted(ip_map.items(), key=lambda x: x[1]['count'], reverse=True)

    ATTACK_EXPLAIN = {
        'PortScan':'Attacker systematically probing network ports to map open services and identify attack surfaces.',
        'DoS Hulk':'High-volume HTTP flood attack overwhelming web servers by generating massive request bursts.',
        'DoS GoldenEye':'Layer-7 DoS attack exploiting HTTP keep-alive to exhaust server connection slots.',
        'DoS slowloris':'Slow HTTP attack holding connections open with partial requests to exhaust server capacity.',
        'DoS Slowhttptest':'Slow HTTP attack testing server limits by sending data at a very low rate.',
        'DDoS':'Distributed Denial of Service flood from multiple coordinated sources targeting bandwidth or services.',
        'FTP-Patator':'Automated credential brute-force attack against FTP login endpoints.',
        'SSH-Patator':'Automated credential brute-force attack against SSH login endpoints.',
        'Bot':'Botnet traffic indicating a compromised host under remote Command and Control (C2).',
        'Heartbleed':'Exploitation of CVE-2014-0160 in OpenSSL to read sensitive memory (keys, passwords).',
        'Infiltration':'Confirmed network perimeter breach — attacker has gained internal access.',
        'Web Attack Brute Force':'Automated credential stuffing or brute-force attack against web application login.',
        'Web Attack XSS':'Cross-Site Scripting injection attempt to execute malicious scripts in browsers.',
        'Web Attack Sql Injection':'SQL injection attempt to manipulate backend database queries.',
    }
    DEFENSE_DETAIL = {
        'PortScan':'1. Enable stateful firewall rules to block unsolicited inbound connection attempts.\n2. Deploy an IPS to auto-block scanners after threshold is exceeded.\n3. Close all unnecessary ports (principle of least privilege).\n4. Restrict ICMP echo replies to reduce network visibility.\n5. Monitor for repeated connection failures in firewall and syslog.',
        'DoS Hulk':'1. Deploy a WAF (Web Application Firewall) to filter HTTP flood traffic.\n2. Enable rate limiting on your web server (nginx: limit_req, Apache: mod_ratelimit).\n3. Use a CDN (Cloudflare, Akamai) to absorb volumetric traffic.\n4. Configure aggressive connection timeouts to drop idle HTTP connections.\n5. Scale horizontally with load balancers during active attacks.',
        'DoS GoldenEye':'1. Limit concurrent HTTP connections per IP (nginx: limit_conn).\n2. Disable HTTP Keep-Alive or reduce its timeout on web servers.\n3. Deploy a reverse proxy (HAProxy, nginx) to terminate connections before the backend.\n4. Configure request body size limits to drop oversized requests early.\n5. Use a WAF rule to detect and block GoldenEye User-Agent patterns.',
        'DoS slowloris':'1. Set aggressive connection/header timeout values (Apache: RequestReadTimeout).\n2. Limit simultaneous connections per IP at the firewall or load balancer.\n3. Use nginx or IIS instead of Apache, which are less vulnerable to Slowloris.\n4. Deploy mod_reqtimeout (Apache) or equivalent to enforce read deadlines.\n5. Use a CDN or DDoS scrubbing service to filter slow-read attack traffic.',
        'DoS Slowhttptest':'1. Enforce strict HTTP request and header read timeouts on all web servers.\n2. Limit maximum concurrent connections per source IP.\n3. Deploy a load balancer to offload slow connection handling from app servers.\n4. Configure minimum data rate thresholds — drop connections below the threshold.\n5. Apply OS-level TCP tuning (tcp_keepalive, tcp_fin_timeout).',
        'DDoS':'1. Activate DDoS mitigation at the ISP or upstream provider level (BGP blackholing).\n2. Use a cloud-based DDoS scrubbing service (Cloudflare Magic Transit, AWS Shield).\n3. Configure rate limiting and connection caps at the network edge.\n4. Implement anycast routing to distribute attack traffic across PoPs.\n5. Prepare a runbook with escalation contacts for ISP-level null routing.',
        'FTP-Patator':'1. Disable FTP entirely and migrate to SFTP (SSH File Transfer Protocol).\n2. Implement account lockout after N failed login attempts (e.g., fail2ban).\n3. Restrict FTP access to known IP ranges via firewall ACLs.\n4. Enable multi-factor authentication on all remote access services.\n5. Monitor FTP logs for rapid sequential failed login attempts.',
        'SSH-Patator':'1. Disable password-based SSH authentication — use public key authentication only.\n2. Deploy fail2ban to auto-ban IPs with excessive failed logins.\n3. Change SSH to a non-standard port to reduce automated scanning noise.\n4. Restrict SSH access to trusted IP ranges only via firewall rules.\n5. Enable MFA for SSH using tools like Google Authenticator (PAM module).',
        'Bot':'1. Immediately isolate the suspected compromised host from the network.\n2. Run a full malware scan using an endpoint security tool.\n3. Check for C2 traffic: DNS lookups, beaconing patterns in network logs.\n4. Review startup entries, scheduled tasks, and unusual running processes.\n5. Reset all credentials on the compromised machine after remediation.\n6. Block outbound traffic to known botnet C2 IPs/domains at the firewall.',
        'Heartbleed':'1. Immediately patch OpenSSL to version 1.0.1g or later (CVE-2014-0160).\n2. Revoke and reissue all TLS certificates that may have been exposed.\n3. Rotate all server private keys as they may have been leaked.\n4. Invalidate all active session tokens and force re-authentication.\n5. Change all passwords users may have entered during the vulnerable period.',
        'Infiltration':'1. Immediately isolate all affected systems to contain the breach.\n2. Preserve forensic evidence: capture memory dumps and disk images.\n3. Engage incident response procedures — escalate to the security team lead.\n4. Identify the initial access vector and patch the exploited vulnerability.\n5. Review lateral movement paths and reset all privileged credentials.\n6. Conduct a full post-incident review and update detection rules.',
        'Web Attack Brute Force':'1. Implement CAPTCHA on login forms to block automated attempts.\n2. Enable account lockout or progressive delays after failed login attempts.\n3. Deploy a WAF rule to rate-limit login endpoint requests per IP.\n4. Monitor login failure rates and alert on anomalous spikes.\n5. Enforce strong password policies and MFA for all web accounts.',
        'Web Attack XSS':'1. Sanitize and encode all user-supplied input before rendering in HTML.\n2. Implement a strict Content Security Policy (CSP) header on all pages.\n3. Use HttpOnly and Secure flags on all session cookies.\n4. Enable X-XSS-Protection: 1; mode=block header on all responses.\n5. Deploy a WAF with XSS detection rules (OWASP ModSecurity Core Rule Set).',
        'Web Attack Sql Injection':'1. Use parameterized queries / prepared statements — never concatenate SQL strings.\n2. Apply input validation and whitelist allowable characters for each field.\n3. Deploy a WAF with SQL injection rules (OWASP ModSecurity CRS).\n4. Limit database user permissions — web app accounts should not have DROP/ALTER.\n5. Enable database query logging and alert on error spikes.',
    }
    SEV_EXPLAIN = {sev: ps(f'sev_exp_{sev}') for sev in ['CRITICAL','HIGH','MEDIUM','UNKNOWN','SAFE']}

    ATTACK_EXPLAIN_AR = {
        'PortScan':'\u064a\u0642\u0648\u0645 \u0627\u0644\u0645\u0647\u0627\u062c\u0645 \u0628\u0645\u0633\u062d \u0645\u0646\u0647\u062c\u064a \u0644\u0645\u0646\u0627\u0641\u0630 \u0627\u0644\u0634\u0628\u0643\u0629 \u0644\u0631\u0635\u062f \u0627\u0644\u062e\u062f\u0645\u0627\u062a \u0627\u0644\u0645\u0641\u062a\u0648\u062d\u0629 \u0648\u062a\u062d\u062f\u064a\u062f \u0646\u0642\u0627\u0637 \u0627\u0644\u0647\u062c\u0648\u0645 \u0627\u0644\u0645\u062d\u062a\u0645\u0644\u0629.',
        'DoS Hulk':'\u0647\u062c\u0648\u0645 \u0641\u064a\u0636\u0627\u0646 HTTP \u0639\u0627\u0644\u064a \u0627\u0644\u062d\u062c\u0645 \u064a\u064f\u062b\u0642\u0644 \u062e\u0648\u0627\u062f\u0645 \u0627\u0644\u0648\u064a\u0628 \u0628\u062a\u0648\u0644\u064a\u062f \u0645\u0648\u062c\u0627\u062a \u0636\u062e\u0645\u0629 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a.',
        'DoS GoldenEye':'\u0647\u062c\u0648\u0645 DoS \u0639\u0644\u0649 \u0627\u0644\u0637\u0628\u0642\u0629 \u0627\u0644\u0633\u0627\u0628\u0639\u0629 \u064a\u0633\u062a\u063a\u0644 HTTP keep-alive \u0644\u0627\u0633\u062a\u0646\u0632\u0627\u0641 \u062e\u0627\u0646\u0627\u062a \u0627\u062a\u0635\u0627\u0644 \u0627\u0644\u062e\u0627\u062f\u0645.',
        'DoS slowloris':'\u0647\u062c\u0648\u0645 HTTP \u0628\u0637\u064a\u0621 \u064a\u064f\u0628\u0642\u064a \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0645\u0641\u062a\u0648\u062d\u0629 \u0628\u0637\u0644\u0628\u0627\u062a \u062c\u0632\u0626\u064a\u0629 \u0644\u0627\u0633\u062a\u0646\u0632\u0627\u0641 \u0633\u0639\u0629 \u0627\u0644\u062e\u0627\u062f\u0645.',
        'DoS Slowhttptest':'\u0647\u062c\u0648\u0645 HTTP \u0628\u0637\u064a\u0621 \u064a\u062e\u062a\u0628\u0631 \u062d\u062f\u0648\u062f \u0627\u0644\u062e\u0627\u062f\u0645 \u0628\u0625\u0631\u0633\u0627\u0644 \u0628\u064a\u0627\u0646\u0627\u062a \u0628\u0645\u0639\u062f\u0644 \u0645\u0646\u062e\u0641\u0636 \u062c\u062f\u0627\u064b.',
        'DDoS':'\u0647\u062c\u0648\u0645 \u062d\u062c\u0628 \u0627\u0644\u062e\u062f\u0645\u0629 \u0627\u0644\u0645\u0648\u0632\u0639 \u0645\u0646 \u0645\u0635\u0627\u062f\u0631 \u0645\u062a\u0639\u062f\u062f\u0629 \u0645\u0646\u0633\u0642\u0629 \u064a\u0633\u062a\u0647\u062f\u0641 \u0639\u0631\u0636 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u062a\u0631\u062f\u062f\u064a \u0623\u0648 \u0627\u0644\u062e\u062f\u0645\u0627\u062a.',
        'FTP-Patator':'\u0647\u062c\u0648\u0645 \u062a\u062e\u0645\u064a\u0646 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0639\u062a\u0645\u0627\u062f \u0622\u0644\u064a \u0639\u0644\u0649 \u0646\u0642\u0627\u0637 \u062a\u0633\u062c\u064a\u0644 \u062f\u062e\u0648\u0644 FTP.',
        'SSH-Patator':'\u0647\u062c\u0648\u0645 \u062a\u062e\u0645\u064a\u0646 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0639\u062a\u0645\u0627\u062f \u0622\u0644\u064a \u0639\u0644\u0649 \u0646\u0642\u0627\u0637 \u062a\u0633\u062c\u064a\u0644 \u062f\u062e\u0648\u0644 SSH.',
        'Bot':'\u062d\u0631\u0643\u0629 \u0645\u0631\u0648\u0631 \u0634\u0628\u0643\u0629 \u0627\u0644\u0631\u0648\u0628\u0648\u062a\u0627\u062a \u062a\u0634\u064a\u0631 \u0625\u0644\u0649 \u062c\u0647\u0627\u0632 \u0645\u062e\u062a\u0631\u0642 \u062a\u062d\u062a \u0633\u064a\u0637\u0631\u0629 \u0645\u0631\u0643\u0632 \u0642\u064a\u0627\u062f\u0629 \u0648\u062a\u062d\u0643\u0645 \u0639\u0646 \u0628\u064f\u0639\u062f (C2).',
        'Heartbleed':'\u0627\u0633\u062a\u063a\u0644\u0627\u0644 \u062b\u063a\u0631\u0629 CVE-2014-0160 \u0641\u064a OpenSSL \u0644\u0642\u0631\u0627\u0621\u0629 \u0627\u0644\u0630\u0627\u0643\u0631\u0629 \u0627\u0644\u062d\u0633\u0627\u0633\u0629 (\u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d \u0648\u0643\u0644\u0645\u0627\u062a \u0627\u0644\u0645\u0631\u0648\u0631).',
        'Infiltration':'\u0627\u062e\u062a\u0631\u0627\u0642 \u0645\u0624\u0643\u062f \u0644\u0645\u062d\u064a\u0637 \u0627\u0644\u0634\u0628\u0643\u0629 \u2014 \u062d\u0635\u0644 \u0627\u0644\u0645\u0647\u0627\u062c\u0645 \u0639\u0644\u0649 \u0635\u0644\u0627\u062d\u064a\u0629 \u0627\u0644\u0648\u0635\u0648\u0644 \u0627\u0644\u062f\u0627\u062e\u0644\u064a.',
        'Web Attack Brute Force':'\u0647\u062c\u0648\u0645 \u062d\u0634\u0648 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0639\u062a\u0645\u0627\u062f \u0623\u0648 \u0642\u0648\u0629 \u063a\u0627\u0634\u0645\u0629 \u0622\u0644\u064a \u0639\u0644\u0649 \u0646\u0645\u0627\u0630\u062c \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0641\u064a \u062a\u0637\u0628\u064a\u0642 \u0627\u0644\u0648\u064a\u0628.',
        'Web Attack XSS':'\u0645\u062d\u0627\u0648\u0644\u0629 \u062d\u0642\u0646 \u0646\u0635\u0648\u0635 \u0628\u0631\u0645\u062c\u064a\u0629 \u0639\u0628\u0631 \u0627\u0644\u0645\u0648\u0627\u0642\u0639 (XSS) \u0644\u062a\u0646\u0641\u064a\u0630 \u0633\u0643\u0631\u064a\u0628\u062a \u0636\u0627\u0631 \u0641\u064a \u0627\u0644\u0645\u062a\u0635\u0641\u062d\u0627\u062a.',
        'Web Attack Sql Injection':'\u0645\u062d\u0627\u0648\u0644\u0629 \u062d\u0642\u0646 SQL \u0644\u0644\u062a\u0644\u0627\u0639\u0628 \u0628\u0627\u0633\u062a\u0639\u0644\u0627\u0645\u0627\u062a \u0642\u0627\u0639\u062f\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u062e\u0644\u0641\u064a\u0629.',
    }
    DEFENSE_DETAIL_AR = {
        'PortScan':'1. \u062a\u0641\u0639\u064a\u0644 \u0642\u0648\u0627\u0639\u062f \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629 \u0630\u0627\u062a \u0627\u0644\u062d\u0627\u0644\u0629 \u0644\u062d\u062c\u0628 \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0627\u0644\u0648\u0627\u0631\u062f\u0629 \u063a\u064a\u0631 \u0627\u0644\u0645\u0631\u063a\u0648\u0628 \u0628\u0647\u0627.\n2. \u0646\u0634\u0631 IPS \u0644\u062d\u0638\u0631 \u0627\u0644\u0645\u0627\u0633\u062d\u064a\u0646 \u062a\u0644\u0642\u0627\u0626\u064a\u0627\u064b \u0628\u0639\u062f \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u0639\u062a\u0628\u0629.\n3. \u0625\u063a\u0644\u0627\u0642 \u062c\u0645\u064a\u0639 \u0627\u0644\u0645\u0646\u0627\u0641\u0630 \u063a\u064a\u0631 \u0627\u0644\u0636\u0631\u0648\u0631\u064a\u0629 (\u0645\u0628\u062f\u0623 \u0627\u0644\u0635\u0644\u0627\u062d\u064a\u0629 \u0627\u0644\u0623\u062f\u0646\u0649).\n4. \u062a\u0642\u064a\u064a\u062f \u0631\u062f\u0648\u062f ICMP echo \u0644\u062a\u0642\u0644\u064a\u0644 \u0631\u0624\u064a\u0629 \u0627\u0644\u0634\u0628\u0643\u0629.\n5. \u0645\u0631\u0627\u0642\u0628\u0629 \u062d\u0627\u0644\u0627\u062a \u0641\u0634\u0644 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0627\u0644\u0645\u062a\u0643\u0631\u0631\u0629 \u0641\u064a \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629 \u0648\u0633\u062c\u0644\u0627\u062a \u0627\u0644\u0646\u0638\u0627\u0645.',
        'DoS Hulk':'1. \u0646\u0634\u0631 WAF \u0644\u062a\u0635\u0641\u064a\u0629 \u062d\u0631\u0643\u0629 \u0645\u0631\u0648\u0631 HTTP \u0627\u0644\u0641\u064a\u0636\u0627\u0646\u064a\u0629.\n2. \u062a\u0641\u0639\u064a\u0644 \u062a\u062d\u062f\u064a\u062f \u0645\u0639\u062f\u0644 \u0627\u0644\u0637\u0644\u0628\u0627\u062a \u0639\u0644\u0649 \u062e\u0627\u062f\u0645 \u0627\u0644\u0648\u064a\u0628.\n3. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 CDN \u0644\u0627\u0645\u062a\u0635\u0627\u0635 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0647\u062c\u0648\u0645\u064a\u0629 \u0627\u0644\u0636\u062e\u0645\u0629.\n4. \u0636\u0628\u0637 \u0645\u0647\u0644\u0627\u062a \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0644\u0625\u0633\u0642\u0627\u0637 \u0627\u062a\u0635\u0627\u0644\u0627\u062a HTTP \u0627\u0644\u062e\u0627\u0645\u0644\u0629.\n5. \u0627\u0644\u062a\u0648\u0633\u0639 \u0627\u0644\u0623\u0641\u0642\u064a \u0628\u0645\u0648\u0627\u0632\u0646\u0627\u062a \u0627\u0644\u062a\u062d\u0645\u064a\u0644 \u062e\u0644\u0627\u0644 \u0627\u0644\u0647\u062c\u0645\u0627\u062a \u0627\u0644\u0646\u0634\u0637\u0629.',
        'DoS GoldenEye':'1. \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0627\u0644\u0645\u062a\u0632\u0627\u0645\u0646\u0629 \u0644\u0643\u0644 IP.\n2. \u062a\u0639\u0637\u064a\u0644 HTTP Keep-Alive \u0623\u0648 \u062a\u0642\u0644\u064a\u0644 \u0645\u0647\u0644\u062a\u0647.\n3. \u0646\u0634\u0631 \u0648\u0643\u064a\u0644 \u0639\u0643\u0633\u064a \u0644\u0625\u0646\u0647\u0627\u0621 \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0642\u0628\u0644 \u0627\u0644\u062e\u0627\u062f\u0645 \u0627\u0644\u062e\u0644\u0641\u064a.\n4. \u0636\u0628\u0637 \u062d\u062f\u0648\u062f \u062d\u062c\u0645 \u062c\u0633\u0645 \u0627\u0644\u0637\u0644\u0628 \u0644\u0631\u0641\u0636 \u0627\u0644\u0637\u0644\u0628\u0627\u062a \u0627\u0644\u0643\u0628\u064a\u0631\u0629 \u0645\u0628\u0643\u0631\u0627\u064b.\n5. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0642\u0627\u0639\u062f\u0629 WAF \u0644\u0644\u0643\u0634\u0641 \u0639\u0646 \u0623\u0646\u0645\u0627\u0637 User-Agent \u0627\u0644\u062e\u0627\u0635\u0629 \u0628\u0640 GoldenEye.',
        'DoS slowloris':'1. \u0636\u0628\u0637 \u0642\u064a\u0645 \u0645\u0647\u0644\u0629 \u0627\u062a\u0635\u0627\u0644/\u0631\u0623\u0633 \u0635\u0627\u0631\u0645\u0629 (Apache: RequestReadTimeout).\n2. \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0627\u0644\u0645\u062a\u0632\u0627\u0645\u0646\u0629 \u0644\u0643\u0644 IP \u0639\u0644\u0649 \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.\n3. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 nginx \u0623\u0648 IIS \u0628\u062f\u0644\u0627\u064b \u0645\u0646 Apache \u0643\u0648\u0646\u0647\u0645\u0627 \u0623\u0642\u0644 \u0639\u0631\u0636\u0629 \u0644\u0640 Slowloris.\n4. \u0646\u0634\u0631 mod_reqtimeout \u0641\u064a Apache \u0644\u0641\u0631\u0636 \u0645\u0648\u0627\u0639\u064a\u062f \u0646\u0647\u0627\u0626\u064a\u0629 \u0644\u0644\u0642\u0631\u0627\u0621\u0629.\n5. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 CDN \u0623\u0648 \u062e\u062f\u0645\u0629 \u062a\u0646\u0642\u064a\u0629 DDoS \u0644\u062a\u0635\u0641\u064a\u0629 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0628\u0637\u064a\u0626\u0629.',
        'DoS Slowhttptest':'1. \u0641\u0631\u0636 \u0645\u0647\u0644 \u0635\u0627\u0631\u0645\u0629 \u0644\u0642\u0631\u0627\u0621\u0629 \u0637\u0644\u0628\u0627\u062a HTTP \u0648\u0627\u0644\u0631\u0624\u0648\u0633 \u0639\u0644\u0649 \u062c\u0645\u064a\u0639 \u062e\u0648\u0627\u062f\u0645 \u0627\u0644\u0648\u064a\u0628.\n2. \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u062d\u062f \u0627\u0644\u0623\u0642\u0635\u0649 \u0644\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0627\u0644\u0645\u062a\u0632\u0627\u0645\u0646\u0629 \u0644\u0643\u0644 IP \u0645\u0635\u062f\u0631.\n3. \u0646\u0634\u0631 \u0645\u0648\u0627\u0632\u0646 \u062a\u062d\u0645\u064a\u0644 \u0644\u062a\u0641\u0631\u064a\u063a \u0645\u0639\u0627\u0644\u062c\u0629 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0627\u0644\u0628\u0637\u064a\u0621 \u0645\u0646 \u062e\u0648\u0627\u062f\u0645 \u0627\u0644\u062a\u0637\u0628\u064a\u0642.\n4. \u0636\u0628\u0637 \u062d\u062f\u0648\u062f \u0623\u062f\u0646\u0649 \u0644\u0645\u0639\u062f\u0644 \u0646\u0642\u0644 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u2014 \u0642\u0637\u0639 \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u062f\u0648\u0646 \u0627\u0644\u0639\u062a\u0628\u0629.\n5. \u0636\u0628\u0637 TCP \u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u0646\u0638\u0627\u0645 \u0627\u0644\u062a\u0634\u063a\u064a\u0644 (tcp_keepalive, tcp_fin_timeout).',
        'DDoS':'1. \u062a\u0641\u0639\u064a\u0644 \u062a\u062e\u0641\u064a\u0641 DDoS \u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u0645\u0632\u0648\u062f \u0627\u0644\u0625\u0646\u062a\u0631\u0646\u062a (BGP blackholing).\n2. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u062e\u062f\u0645\u0629 \u062a\u0646\u0642\u064a\u0629 DDoS \u0633\u062d\u0627\u0628\u064a\u0629 (Cloudflare Magic Transit, AWS Shield).\n3. \u0636\u0628\u0637 \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0645\u0639\u062f\u0644 \u0648\u062d\u062f\u0648\u062f \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0639\u0644\u0649 \u062d\u0627\u0641\u0629 \u0627\u0644\u0634\u0628\u0643\u0629.\n4. \u062a\u0637\u0628\u064a\u0642 \u062a\u0648\u062c\u064a\u0647 anycast \u0644\u062a\u0648\u0632\u064a\u0639 \u062d\u0631\u0643\u0629 \u0627\u0644\u0647\u062c\u0648\u0645.\n5. \u0625\u0639\u062f\u0627\u062f \u062f\u0644\u064a\u0644 \u062a\u0634\u063a\u064a\u0644 \u0645\u0639 \u062c\u0647\u0627\u062a \u0627\u062a\u0635\u0627\u0644 \u0627\u0644\u062a\u0635\u0639\u064a\u062f \u0644\u0644\u062a\u0648\u062c\u064a\u0647 \u0627\u0644\u0641\u0627\u0631\u063a \u0639\u0644\u0649 \u0645\u0633\u062a\u0648\u0649 \u0645\u0632\u0648\u062f \u0627\u0644\u0625\u0646\u062a\u0631\u0646\u062a.',
        'FTP-Patator':'1. \u062a\u0639\u0637\u064a\u0644 FTP \u0648\u0627\u0644\u0627\u0646\u062a\u0642\u0627\u0644 \u0625\u0644\u0649 SFTP (\u0628\u0631\u0648\u062a\u0648\u0643\u0648\u0644 \u0646\u0642\u0644 \u0627\u0644\u0645\u0644\u0641\u0627\u062a \u0639\u0628\u0631 SSH).\n2. \u062a\u0637\u0628\u064a\u0642 \u0642\u0641\u0644 \u0627\u0644\u062d\u0633\u0627\u0628 \u0628\u0639\u062f N \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u062a\u0633\u062c\u064a\u0644 \u062f\u062e\u0648\u0644 \u0641\u0627\u0634\u0644\u0629 (fail2ban).\n3. \u062a\u0642\u064a\u064a\u062f \u0648\u0635\u0648\u0644 FTP \u0644\u0646\u0637\u0627\u0642\u0627\u062a IP \u0645\u0639\u0631\u0648\u0641\u0629 \u0639\u0628\u0631 ACL \u0641\u064a \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.\n4. \u062a\u0641\u0639\u064a\u0644 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629 \u0645\u062a\u0639\u062f\u062f\u0629 \u0627\u0644\u0639\u0648\u0627\u0645\u0644 \u0639\u0644\u0649 \u062c\u0645\u064a\u0639 \u062e\u062f\u0645\u0627\u062a \u0627\u0644\u0648\u0635\u0648\u0644 \u0639\u0646 \u0628\u064f\u0639\u062f.\n5. \u0645\u0631\u0627\u0642\u0628\u0629 \u0633\u062c\u0644\u0627\u062a FTP \u0644\u0644\u0643\u0634\u0641 \u0639\u0646 \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u062a\u0633\u062c\u064a\u0644 \u062f\u062e\u0648\u0644 \u0641\u0627\u0634\u0644\u0629 \u0645\u062a\u0633\u0644\u0633\u0644\u0629.',
        'SSH-Patator':'1. \u062a\u0639\u0637\u064a\u0644 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629 \u0628\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0639\u0628\u0631 SSH \u2014 \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629 \u0628\u0627\u0644\u0645\u0641\u062a\u0627\u062d \u0627\u0644\u0639\u0627\u0645 \u0641\u0642\u0637.\n2. \u0646\u0634\u0631 fail2ban \u0644\u062d\u0638\u0631 IPs \u0630\u0627\u062a \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u062a\u0633\u062c\u064a\u0644 \u062f\u062e\u0648\u0644 \u0641\u0627\u0634\u0644\u0629 \u0645\u0641\u0631\u0637\u0629 \u062a\u0644\u0642\u0627\u0626\u064a\u0627\u064b.\n3. \u062a\u063a\u064a\u064a\u0631 SSH \u0625\u0644\u0649 \u0645\u0646\u0641\u0630 \u063a\u064a\u0631 \u0642\u064a\u0627\u0633\u064a \u0644\u0644\u062d\u062f \u0645\u0646 \u0627\u0644\u0641\u062d\u0635 \u0627\u0644\u0622\u0644\u064a.\n4. \u062a\u0642\u064a\u064a\u062f \u0648\u0635\u0648\u0644 SSH \u0644\u0646\u0637\u0627\u0642\u0627\u062a IP \u0645\u0648\u062b\u0648\u0642\u0629 \u0641\u0642\u0637 \u0639\u0628\u0631 \u0642\u0648\u0627\u0639\u062f \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.\n5. \u062a\u0641\u0639\u064a\u0644 MFA \u0644\u0640 SSH \u0628\u0627\u0633\u062a\u062e\u062f\u0627\u0645 Google Authenticator (\u0648\u062d\u062f\u0629 PAM).',
        'Bot':'1. \u0639\u0632\u0644 \u0627\u0644\u062c\u0647\u0627\u0632 \u0627\u0644\u0645\u062e\u062a\u0631\u0642 \u0627\u0644\u0645\u0634\u062a\u0628\u0647 \u0628\u0647 \u0641\u0648\u0631\u0627\u064b \u0639\u0646 \u0627\u0644\u0634\u0628\u0643\u0629.\n2. \u0625\u062c\u0631\u0627\u0621 \u0641\u062d\u0635 \u0634\u0627\u0645\u0644 \u0644\u0628\u0631\u0627\u0645\u062c \u0627\u0644\u062e\u0628\u064a\u062b\u0629 \u0628\u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0623\u062f\u0627\u0629 \u0623\u0645\u0627\u0646 \u0627\u0644\u0646\u0642\u0637\u0629 \u0627\u0644\u0646\u0647\u0627\u0626\u064a\u0629.\n3. \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u062d\u0631\u0643\u0629 \u0645\u0631\u0648\u0631 C2: \u0627\u0633\u062a\u0639\u0644\u0627\u0645\u0627\u062a DNS \u0648\u0623\u0646\u0645\u0627\u0637 \u0627\u0644\u0628\u062b \u0641\u064a \u0633\u062c\u0644\u0627\u062a \u0627\u0644\u0634\u0628\u0643\u0629.\n4. \u0645\u0631\u0627\u062c\u0639\u0629 \u0625\u062f\u062e\u0627\u0644\u0627\u062a \u0628\u062f\u0621 \u0627\u0644\u062a\u0634\u063a\u064a\u0644 \u0648\u0627\u0644\u0645\u0647\u0627\u0645 \u0627\u0644\u0645\u062c\u062f\u0648\u0644\u0629 \u0648\u0627\u0644\u0639\u0645\u0644\u064a\u0627\u062a \u063a\u064a\u0631 \u0627\u0644\u0627\u0639\u062a\u064a\u0627\u062f\u064a\u0629.\n5. \u0625\u0639\u0627\u062f\u0629 \u062a\u0639\u064a\u064a\u0646 \u062c\u0645\u064a\u0639 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0627\u0639\u062a\u0645\u0627\u062f \u0639\u0644\u0649 \u0627\u0644\u062c\u0647\u0627\u0632 \u0627\u0644\u0645\u062e\u062a\u0631\u0642 \u0628\u0639\u062f \u0627\u0644\u0645\u0639\u0627\u0644\u062c\u0629.\n6. \u062d\u0638\u0631 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0635\u0627\u062f\u0631\u0629 \u0644\u0639\u0646\u0627\u0648\u064a\u0646 IP \u0648\u0646\u0637\u0627\u0642\u0627\u062a C2 \u0627\u0644\u0645\u0639\u0631\u0648\u0641\u0629 \u0639\u0644\u0649 \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.',
        'Heartbleed':'1. \u062a\u0631\u0642\u064a\u0629 OpenSSL \u0641\u0648\u0631\u0627\u064b \u0625\u0644\u0649 \u0627\u0644\u0625\u0635\u062f\u0627\u0631 1.0.1g \u0623\u0648 \u0623\u062d\u062f\u062b (CVE-2014-0160).\n2. \u0625\u0644\u063a\u0627\u0621 \u0648\u0625\u0639\u0627\u062f\u0629 \u0625\u0635\u062f\u0627\u0631 \u062c\u0645\u064a\u0639 \u0634\u0647\u0627\u062f\u0627\u062a TLS \u0627\u0644\u062a\u064a \u0631\u0628\u0645\u0627 \u062a\u0639\u0631\u0636\u062a \u0644\u0644\u0643\u0634\u0641.\n3. \u062a\u062f\u0648\u064a\u0631 \u062c\u0645\u064a\u0639 \u0645\u0641\u0627\u062a\u064a\u062d \u0627\u0644\u062e\u0627\u062f\u0645 \u0627\u0644\u062e\u0627\u0635\u0629 \u0644\u0623\u0646\u0647\u0627 \u0631\u0628\u0645\u0627 \u062a\u0633\u0631\u0628\u062a.\n4. \u0625\u0628\u0637\u0627\u0644 \u062c\u0645\u064a\u0639 \u0631\u0645\u0648\u0632 \u0627\u0644\u062c\u0644\u0633\u0629 \u0627\u0644\u0646\u0634\u0637\u0629 \u0648\u0625\u062c\u0628\u0627\u0631 \u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645\u064a\u0646 \u0639\u0644\u0649 \u0625\u0639\u0627\u062f\u0629 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629.\n5. \u062a\u063a\u064a\u064a\u0631 \u062c\u0645\u064a\u0639 \u0643\u0644\u0645\u0627\u062a \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u062a\u064a \u0623\u062f\u062e\u0644\u0647\u0627 \u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645\u0648\u0646 \u062e\u0644\u0627\u0644 \u0627\u0644\u0641\u062a\u0631\u0629 \u0627\u0644\u0636\u0639\u064a\u0641\u0629.',
        'Infiltration':'1. \u0639\u0632\u0644 \u062c\u0645\u064a\u0639 \u0627\u0644\u0623\u0646\u0638\u0645\u0629 \u0627\u0644\u0645\u062a\u0623\u062b\u0631\u0629 \u0641\u0648\u0631\u0627\u064b \u0644\u0627\u062d\u062a\u0648\u0627\u0621 \u0627\u0644\u0627\u062e\u062a\u0631\u0627\u0642.\n2. \u0627\u0644\u062d\u0641\u0627\u0638 \u0639\u0644\u0649 \u0627\u0644\u0623\u062f\u0644\u0629 \u0627\u0644\u062c\u0646\u0627\u0626\u064a\u0629: \u0627\u0644\u062a\u0642\u0627\u0637 \u062a\u0641\u0631\u064a\u063a\u0627\u062a \u0627\u0644\u0630\u0627\u0643\u0631\u0629 \u0648\u0635\u0648\u0631 \u0627\u0644\u0642\u0631\u0635.\n3. \u062a\u0637\u0628\u064a\u0642 \u0625\u062c\u0631\u0627\u0621\u0627\u062a \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b \u2014 \u0627\u0644\u062a\u0635\u0639\u064a\u062f \u0625\u0644\u0649 \u0642\u0627\u0626\u062f \u0641\u0631\u064a\u0642 \u0627\u0644\u0623\u0645\u0646.\n4. \u062a\u062d\u062f\u064a\u062f \u0645\u062a\u062c\u0647 \u0627\u0644\u0648\u0635\u0648\u0644 \u0627\u0644\u0623\u0648\u0644\u064a \u0648\u062a\u0635\u062d\u064a\u062d \u0627\u0644\u062b\u063a\u0631\u0629 \u0627\u0644\u0645\u0633\u062a\u063a\u0644\u0629.\n5. \u0645\u0631\u0627\u062c\u0639\u0629 \u0645\u0633\u0627\u0631\u0627\u062a \u0627\u0644\u062d\u0631\u0643\u0629 \u0627\u0644\u062c\u0627\u0646\u0628\u064a\u0629 \u0648\u0625\u0639\u0627\u062f\u0629 \u062a\u0639\u064a\u064a\u0646 \u062c\u0645\u064a\u0639 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0627\u0639\u062a\u0645\u0627\u062f \u0630\u0627\u062a \u0627\u0644\u0627\u0645\u062a\u064a\u0627\u0632\u0627\u062a.\n6. \u0625\u062c\u0631\u0627\u0621 \u0645\u0631\u0627\u062c\u0639\u0629 \u0643\u0627\u0645\u0644\u0629 \u0644\u0645\u0627 \u0628\u0639\u062f \u0627\u0644\u062d\u0627\u062f\u062b\u0629 \u0648\u062a\u062d\u062f\u064a\u062b \u0642\u0648\u0627\u0639\u062f \u0627\u0644\u0643\u0634\u0641.',
        'Web Attack Brute Force':'1. \u062a\u0637\u0628\u064a\u0642 CAPTCHA \u0639\u0644\u0649 \u0646\u0645\u0627\u0630\u062c \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0644\u062d\u0638\u0631 \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0627\u062a \u0627\u0644\u0622\u0644\u064a\u0629.\n2. \u062a\u0641\u0639\u064a\u0644 \u0642\u0641\u0644 \u0627\u0644\u062d\u0633\u0627\u0628 \u0623\u0648 \u0627\u0644\u062a\u0623\u062e\u064a\u0631\u0627\u062a \u0627\u0644\u062a\u062f\u0631\u064a\u062c\u064a\u0629 \u0628\u0639\u062f \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0627\u0644\u0641\u0627\u0634\u0644\u0629.\n3. \u0646\u0634\u0631 \u0642\u0627\u0639\u062f\u0629 WAF \u0644\u062a\u062d\u062f\u064a\u062f \u0645\u0639\u062f\u0644 \u0637\u0644\u0628\u0627\u062a \u0646\u0642\u0637\u0629 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0644\u0643\u0644 IP.\n4. \u0645\u0631\u0627\u0642\u0628\u0629 \u0645\u0639\u062f\u0644\u0627\u062a \u0641\u0634\u0644 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0648\u0627\u0644\u062a\u0646\u0628\u064a\u0647 \u0639\u0644\u0649 \u0627\u0644\u0627\u0631\u062a\u0641\u0627\u0639\u0627\u062a \u0627\u0644\u0634\u0627\u0630\u0629.\n5. \u0641\u0631\u0636 \u0633\u064a\u0627\u0633\u0627\u062a \u0643\u0644\u0645\u0627\u062a \u0645\u0631\u0648\u0631 \u0642\u0648\u064a\u0629 \u0648MFA \u0639\u0644\u0649 \u062c\u0645\u064a\u0639 \u062d\u0633\u0627\u0628\u0627\u062a \u0627\u0644\u0648\u064a\u0628.',
        'Web Attack XSS':'1. \u062a\u0639\u0642\u064a\u0645 \u0648\u062a\u0631\u0645\u064a\u0632 \u062c\u0645\u064a\u0639 \u0645\u062f\u062e\u0644\u0627\u062a \u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645 \u0642\u0628\u0644 \u0639\u0631\u0636\u0647\u0627 \u0641\u064a HTML.\n2. \u062a\u0637\u0628\u064a\u0642 \u0633\u064a\u0627\u0633\u0629 \u0623\u0645\u0627\u0646 \u0627\u0644\u0645\u062d\u062a\u0648\u0649 (CSP) \u0627\u0644\u0635\u0627\u0631\u0645\u0629 \u0639\u0644\u0649 \u062c\u0645\u064a\u0639 \u0627\u0644\u0635\u0641\u062d\u0627\u062a.\n3. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0639\u0644\u0627\u0645\u062a\u064e\u064a HttpOnly \u0648Secure \u0639\u0644\u0649 \u062c\u0645\u064a\u0639 \u0645\u0644\u0641\u0627\u062a \u062a\u0639\u0631\u064a\u0641 \u0627\u0631\u062a\u0628\u0627\u0637 \u0627\u0644\u062c\u0644\u0633\u0629.\n4. \u062a\u0641\u0639\u064a\u0644 \u0627\u0644\u0631\u0623\u0633 X-XSS-Protection: 1; mode=block \u0639\u0644\u0649 \u062c\u0645\u064a\u0639 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0627\u062a.\n5. \u0646\u0634\u0631 WAF \u0628\u0642\u0648\u0627\u0639\u062f \u0627\u0643\u062a\u0634\u0627\u0641 XSS (OWASP ModSecurity Core Rule Set).',
        'Web Attack Sql Injection':'1. \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0627\u0644\u0627\u0633\u062a\u0639\u0644\u0627\u0645\u0627\u062a \u0627\u0644\u0645\u0639\u0644\u0645\u0629/\u0627\u0644\u0639\u0628\u0627\u0631\u0627\u062a \u0627\u0644\u0645\u064f\u0639\u062f\u064e\u0651\u062f\u0629 \u2014 \u0639\u062f\u0645 \u0631\u0628\u0637 \u0633\u0644\u0627\u0633\u0644 SQL \u0623\u0628\u062f\u0627\u064b.\n2. \u062a\u0637\u0628\u064a\u0642 \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0635\u062d\u0629 \u0627\u0644\u0645\u062f\u062e\u0644\u0627\u062a \u0648\u0625\u062f\u0631\u0627\u062c \u0627\u0644\u0623\u062d\u0631\u0641 \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627 \u0641\u064a \u0627\u0644\u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u0628\u064a\u0636\u0627\u0621.\n3. \u0646\u0634\u0631 WAF \u0628\u0642\u0648\u0627\u0639\u062f \u062d\u0642\u0646 SQL (OWASP ModSecurity CRS).\n4. \u062a\u062d\u062f\u064a\u062f \u0635\u0644\u0627\u062d\u064a\u0627\u062a \u0645\u0633\u062a\u062e\u062f\u0645 \u0642\u0627\u0639\u062f\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u2014 \u062d\u0633\u0627\u0628\u0627\u062a \u062a\u0637\u0628\u064a\u0642 \u0627\u0644\u0648\u064a\u0628 \u064a\u062c\u0628 \u0623\u0644\u0627 \u062a\u0645\u0644\u0643 DROP/ALTER.\n5. \u062a\u0641\u0639\u064a\u0644 \u062a\u0633\u062c\u064a\u0644 \u0627\u0633\u062a\u0639\u0644\u0627\u0645\u0627\u062a \u0642\u0627\u0639\u062f\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0648\u0627\u0644\u062a\u0646\u0628\u064a\u0647 \u0639\u0644\u0649 \u0627\u0631\u062a\u0641\u0627\u0639\u0627\u062a \u0627\u0644\u0623\u062e\u0637\u0627\u0621.',
    }
    _ATTACK_EXPLAIN = ATTACK_EXPLAIN_AR if is_rtl else ATTACK_EXPLAIN
    _DEFENSE_DETAIL = DEFENSE_DETAIL_AR if is_rtl else DEFENSE_DETAIL

    # ── Light color palette ────────────────────────────────────────────────────
    C_BG=(255,255,255); C_NAVY=(20,50,110); C_ACCENT=(60,120,200)
    C_TXT=(25,35,55); C_MUTED=(100,110,130); C_TH_BG=(210,225,248)
    C_TH_TXT=(15,40,100); C_ROW_ALT=(245,248,254); C_ROW_EVEN=(255,255,255)
    C_BORDER=(180,195,220); C_FOOTER=(150,160,180)
    SEV_BG={'CRITICAL':(255,232,232),'HIGH':(255,243,222),'MEDIUM':(255,252,218),'SAFE':(228,250,234),'UNKNOWN':(240,242,246)}
    SEV_TXT={'CRITICAL':(170,0,15),'HIGH':(160,70,0),'MEDIUM':(120,90,0),'SAFE':(0,100,40),'UNKNOWN':(80,85,100)}
    SEV_BDR={'CRITICAL':(220,60,60),'HIGH':(220,130,0),'MEDIUM':(200,165,0),'SAFE':(0,160,70),'UNKNOWN':(160,165,180)}
    L_MARGIN=15; R_MARGIN=15; T_MARGIN=20; CONTENT_W=180

    class BastionPDF(FPDF):
        def header(self):
            self.set_fill_color(*C_BG); self.rect(0,0,210,297,'F')
            if self.page_no() > 1:
                self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
                self.line(L_MARGIN, 12, 210-R_MARGIN, 12)
                self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
                self.set_xy(L_MARGIN, 14)
                self.cell(CONTENT_W, 5, _safe(f'BASTION IDS  |  Scan {scan_id}  |  CONFIDENTIAL'), align='R'); self.ln(4)
        def footer(self):
            if self.page_no() == 1: return
            self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
            self.line(L_MARGIN, 284, 210-R_MARGIN, 284)
            self.set_y(-13); self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
            self.cell(0, 5, _safe(f'Generated {datetime.now().strftime("%Y-%m-%d %H:%M")}  |  Page {self.page_no()}  |  BASTION IDS Network Intrusion Detection'), align='C')

    pdf = BastionPDF(); pdf.set_margins(L_MARGIN, T_MARGIN, R_MARGIN); pdf.set_auto_page_break(auto=True, margin=22)
    if is_rtl and _arabic_ok:
        pdf.add_font('Arabic', '', _arabic_font)
        if _arabic_font_bold: pdf.add_font('ArabicB', '', _arabic_font_bold)

    def _font(style='', size=10):
        if is_rtl and _arabic_ok:
            if style == 'B' and _arabic_font_bold: pdf.set_font('ArabicB', '', size)
            else: pdf.set_font('Arabic', '', size)
        else: pdf.set_font('Helvetica', style, size)

    def section(title, desc=None):
        _a = 'R' if is_rtl else 'L'
        pdf.ln(5); _font('B',13); pdf.set_text_color(*C_NAVY)
        pdf.set_x(L_MARGIN); pdf.cell(CONTENT_W, 9, _txt(title), align=_a, new_x='LMARGIN', new_y='NEXT')
        if desc:
            _font('I',9); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.multi_cell(CONTENT_W, 5, _txt(desc), align=_a, new_x='LMARGIN', new_y='NEXT')
        pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.5)
        pdf.line(L_MARGIN, pdf.get_y(), L_MARGIN+CONTENT_W, pdf.get_y()); pdf.ln(3)

    def kv(label, value):
        if is_rtl:
            _font('',10); pdf.set_text_color(*C_TXT)
            pdf.set_x(L_MARGIN); pdf.cell(60,7,_txt(str(value)),align='L',new_x='RIGHT',new_y='LAST')
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.cell(CONTENT_W-60,7,_txt(label+':'),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.cell(65,7,_txt(label+':'),new_x='RIGHT',new_y='LAST')
            _font('',10); pdf.set_text_color(*C_TXT); pdf.cell(0,7,_txt(str(value)),new_x='LMARGIN',new_y='NEXT')

    def th(*cols_widths):
        _a = 'R' if is_rtl else 'L'
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*C_TH_BG); pdf.set_text_color(*C_TH_TXT)
        pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('B',9)
        for col,w in cols_widths: pdf.cell(w,7,_fit(col,w),border=1,fill=True,align=_a)
        pdf.ln()

    def tr(*vals_widths, alt=False):
        _a = 'R' if is_rtl else 'L'
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*(C_ROW_ALT if alt else C_ROW_EVEN))
        pdf.set_text_color(*C_TXT); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('',9)
        for val,w in vals_widths: pdf.cell(w,6,_fit(val,w),border=1,fill=True,align=_a)
        pdf.ln()

    def csv_ref(filename):
        _a = 'R' if is_rtl else 'L'
        pdf.ln(2); pdf.set_fill_color(235,243,255); pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.3)
        pdf.set_x(L_MARGIN); pdf.rect(L_MARGIN, pdf.get_y(), CONTENT_W, 8, 'FD')
        _font('I',8); pdf.set_text_color(*C_NAVY); pdf.set_x(L_MARGIN+2)
        pdf.cell(CONTENT_W-4, 8, _txt(ps('csv ref', filename=filename)), align=_a, new_x='LMARGIN', new_y='NEXT'); pdf.ln(2)

    # ── Cover ─────────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(*C_NAVY); pdf.rect(0,0,210,60,'F')
    pdf.set_y(18); _font('B',36); pdf.set_text_color(255,255,255)
    pdf.cell(0,16,'BASTION IDS',align='C',new_x='LMARGIN',new_y='NEXT')
    _font('',14); pdf.set_text_color(200,215,245)
    pdf.cell(0,8,_txt(ps('report subtitle')),align='C',new_x='LMARGIN',new_y='NEXT')
    pdf.ln(18)
    # Meta info box
    meta_y = pdf.get_y()
    pdf.set_fill_color(245,248,254); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.4)
    pdf.rect(L_MARGIN, meta_y, CONTENT_W, 60, 'FD')
    pdf.set_y(meta_y+5)
    for label,val in [(ps('Scan ID'),scan_id),(ps('File Analyzed'),entry.get('filename','')),
                      (ps('Total Flows'),f'{total_flows:,}'),(ps('Malicious Flows'),f'{malicious:,}'),
                      (ps('Benign Flows'),f'{benign:,}'),(ps('Detection Rate'),f'{detect_rate}%'),
                      (ps('Analyst'),session.get('user','')),
                      (ps('Generated'),datetime.now().strftime('%Y-%m-%d %H:%M:%S'))]:
        if is_rtl:
            _font('',10); pdf.set_text_color(*C_TXT)
            pdf.set_x(L_MARGIN+5); pdf.cell(60,7,_txt(str(val)),align='L',new_x='RIGHT',new_y='LAST')
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.cell(CONTENT_W-65,7,_txt(label+':'),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN+5); pdf.cell(60,7,_txt(label+':'),align='L',new_x='RIGHT',new_y='LAST')
            _font('',10); pdf.set_text_color(*C_TXT); pdf.cell(0,7,_txt(str(val)),new_x='LMARGIN',new_y='NEXT')
    # Severity badges
    pdf.ln(6)
    bw = CONTENT_W / 4; badge_y = pdf.get_y()
    for i,(sev,cnt) in enumerate([('CRITICAL',sev_bd.get('CRITICAL',0)),('HIGH',sev_bd.get('HIGH',0)),
                                   ('MEDIUM',sev_bd.get('MEDIUM',0)),('SAFE',sev_bd.get('SAFE',0))]):
        bx = L_MARGIN + i*bw
        pdf.set_fill_color(*SEV_BG[sev]); pdf.set_draw_color(*SEV_BDR[sev]); pdf.set_line_width(0.3)
        pdf.rect(bx, badge_y, bw-2, 18, 'FD')
        _font('B',15); pdf.set_text_color(*SEV_TXT[sev])
        pdf.set_xy(bx, badge_y+2); pdf.cell(bw-2,9,f'{cnt:,}',align='C')
        _font('',7); pdf.set_text_color(*C_MUTED)
        pdf.set_xy(bx, badge_y+11); pdf.cell(bw-2,6,_txt(ps(sev)),align='C')

    # ── Section 1 — Dashboard Summary ─────────────────────────────────────────
    pdf.add_page()
    section(ps('s1 title'), ps('s1 desc'))
    kv(ps('Total Flows Analyzed'), f'{total_flows:,}'); kv(ps('Malicious Flows'), f'{malicious:,}')
    kv(ps('Benign / Safe Flows'), f'{benign:,}'); kv(ps('Detection Rate'), f'{detect_rate}%')
    kv(ps('Average Confidence'), f"{entry.get('avg_confidence',0)}%")
    kv(ps('Unique Attacker IPs'), str(len(ip_map))); kv(ps('Attack Types Detected'), str(len(threat_bd)))
    pdf.ln(3)

    # Traffic bar visualization
    section(ps('Traffic Volume'))
    csv_fname = f'bastion_data_{scan_id}.csv'
    bar_w = 110
    for label, cnt, clr in [(ps('Malicious'), malicious, SEV_TXT['CRITICAL']), (ps('Benign'), benign, SEV_TXT['SAFE'])]:
        frac = cnt/total_flows if total_flows else 0
        filled = int(frac*bar_w); pct = f'{frac*100:.1f}%'
        _font('B',9); pdf.set_text_color(*C_MUTED)
        pdf.set_x(L_MARGIN); pdf.cell(38,6,_txt(label),new_x='RIGHT',new_y='LAST')
        pdf.set_fill_color(*clr)
        if filled>0: pdf.rect(pdf.get_x(), pdf.get_y()+1, filled, 4, 'F')
        pdf.set_fill_color(225,230,242)
        if bar_w-filled>0: pdf.rect(pdf.get_x()+filled, pdf.get_y()+1, bar_w-filled, 4, 'F')
        pdf.set_x(pdf.get_x()+bar_w+3)
        _font('',9); pdf.set_text_color(*C_TXT)
        pdf.cell(40,6,_safe(f'{cnt:,}  ({pct})'),new_x='LMARGIN',new_y='NEXT')
    pdf.ln(3)

    section(ps('Severity Distribution'))
    th((ps('Severity'),45),(ps('Flow Count'),40),(ps('Percentage'),35),(ps('Meaning'),60))
    for i,sev in enumerate(['CRITICAL','HIGH','MEDIUM','UNKNOWN','SAFE']):
        cnt=sev_bd.get(sev,0); pct=f"{round(cnt/total_flows*100,2)}%" if total_flows else '0%'
        tr((ps(sev),45),(f'{cnt:,}',40),(pct,35),(SEV_EXPLAIN.get(sev,''),60),alt=(i%2==1))
    pdf.ln(3)

    section(ps('Attack Type Breakdown'), ps('atk bd desc'))
    th((ps('Attack Type'),80),(ps('Flow Count'),35),(ps('% of Threats'),35),(ps('Severity'),30))
    sorted_threats = sorted(threat_bd.items(), key=lambda x: x[1], reverse=True)
    for i,(lbl,cnt) in enumerate(sorted_threats[:8]):
        sev,_,_=get_severity(lbl); pct=f"{round(cnt/malicious*100,1)}%" if malicious else '0%'
        tr((lbl,80),(f'{cnt:,}',35),(pct,35),(ps(sev),30),alt=(i%2==1))
    if len(sorted_threats)>8: csv_ref(csv_fname)
    pdf.ln(2)

    if top_ips:
        section(ps('Top Attacker IPs'), ps('top ips desc'))
        th((ps('Source IP'),65),(ps('Malicious Flows'),45),(ps('% of Threats'),40),(ps('Primary Attack'),30))
        for i,(ip,info) in enumerate(top_ips[:5]):
            pct=f"{round(info['count']/malicious*100,1)}%" if malicious else '0%'
            primary=sorted(info['attacks'],key=lambda a:threat_bd.get(a,0),reverse=True)
            tr((ip,65),(f"{info['count']:,}",45),(pct,40),(list(primary)[0] if primary else '',30),alt=(i%2==1))
        if len(top_ips)>5: csv_ref(csv_fname)

    # ── Section 2 — Attacker Cards (one page each) ────────────────────────────
    for ip, info in top_ips[:20]:
        pdf.add_page()
        count=info['count']; attacks=list(info['attacks']); sevs=info['severities']
        confs=info['confidences']
        max_sev=min(sevs,key=lambda s:SEV_ORDER.get(s,3)) if sevs else 'UNKNOWN'
        avg_conf=round(sum(confs)/len(confs),1) if confs else 0

        # Header banner
        bh=26; by=T_MARGIN
        pdf.set_fill_color(*SEV_BG.get(max_sev,C_BG)); pdf.set_draw_color(*SEV_BDR.get(max_sev,C_BORDER)); pdf.set_line_width(0.5)
        pdf.rect(L_MARGIN, by, CONTENT_W, bh, 'FD')
        # Severity stripe
        pdf.set_fill_color(*SEV_TXT.get(max_sev,(80,85,100))); pdf.rect(L_MARGIN, by, 30, bh, 'F')
        _font('B',8); pdf.set_text_color(255,255,255)
        pdf.set_xy(L_MARGIN, by+10); pdf.cell(30,6,_txt(ps(max_sev)),align='C')
        # IP address
        _font('B',20); pdf.set_text_color(*SEV_TXT.get(max_sev,C_NAVY))
        pdf.set_xy(L_MARGIN+34, by+3); pdf.cell(CONTENT_W-36,12,_safe(ip))
        _font('',9); pdf.set_text_color(*C_MUTED)
        pdf.set_xy(L_MARGIN+34, by+16); pdf.cell(CONTENT_W-36,8,_txt(f"{ps('Suspected Attacker')}  |  {ps('card subtitle', count=f'{count:,}', avg_conf=avg_conf)}"))
        pdf.set_y(by+bh+4)

        section(ps('Reason for Suspicion'))
        kv(ps('Source IP'),ip); kv(ps('Malicious Flows'),ps('flows flagged', count=f'{count:,}'))
        kv(ps('Highest Severity'),ps(max_sev)); kv(ps('Average ML Confidence'),f'{avg_conf}%')
        kv(ps('Attack Types Observed'),', '.join(attacks))
        kv(ps('Target IPs'),', '.join(list(info['dst_ips'])[:5]) if info['dst_ips'] else 'N/A')
        kv(ps('Target Ports'),', '.join(sorted(list(info['ports']))[:8]) if info['ports'] else 'N/A')
        pdf.ln(2)

        section(ps('Attack Analysis'))
        for atk in attacks:
            exp='';
            for k,v in _ATTACK_EXPLAIN.items():
                if k.lower() in atk.lower(): exp=v; break
            sev_a,_,_=get_severity(atk)
            ay=pdf.get_y(); pdf.set_fill_color(*SEV_BG.get(sev_a,(240,242,246)))
            pdf.set_draw_color(*SEV_BDR.get(sev_a,(160,165,180))); pdf.set_line_width(0.2)
            pdf.rect(L_MARGIN, ay, CONTENT_W, 7, 'FD')
            _font('B',9); pdf.set_text_color(*SEV_TXT.get(sev_a,C_TXT))
            _a = 'R' if is_rtl else 'L'
            pdf.set_x(L_MARGIN+2); pdf.cell(CONTENT_W-4,7,_txt(f'{atk}  [{ps(sev_a)}]'),align=_a,new_x='LMARGIN',new_y='NEXT')
            if exp:
                _font('',9); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN+4)
                pdf.multi_cell(CONTENT_W-8,5,_txt(exp),align=_a,new_x='LMARGIN',new_y='NEXT')
            pdf.ln(1)

        section(ps('Why Classified'))
        _font('',10); pdf.set_text_color(*C_TXT)
        severity_desc = (ps('sev_desc_critical') if max_sev=='CRITICAL'
                         else ps('sev_desc_high') if max_sev=='HIGH' else ps('sev_desc_medium'))
        for line in [
            ps('ml_analyzed', count=f'{count:,}', ip=ip, avg_conf=avg_conf),
            ps('ml_patterns', attacks=', '.join(attacks)),
            ps('ml_key_signals'),
            ps('ml_highest_sev', max_sev=ps(max_sev), severity_desc=severity_desc),
        ]:
            pdf.set_x(L_MARGIN); pdf.multi_cell(CONTENT_W,5,_txt(line),align='R' if is_rtl else 'L',new_x='LMARGIN',new_y='NEXT'); pdf.ln(1)

        section(ps('Defense Recommendations'))
        shown=set()
        for atk in attacks:
            for k,v in _DEFENSE_DETAIL.items():
                if k.lower() in atk.lower() and k not in shown:
                    shown.add(k)
                    _font('B',9); pdf.set_text_color(*C_NAVY); pdf.set_x(L_MARGIN)
                    pdf.cell(CONTENT_W,6,_txt(ps('For atk', atk=atk)),align='R' if is_rtl else 'L',new_x='LMARGIN',new_y='NEXT')
                    _font('',9); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN+4)
                    _v = v.translate(str.maketrans('0123456789','\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669')) if is_rtl else v
                    pdf.multi_cell(CONTENT_W-8,5,_txt(_v),align='R' if is_rtl else 'L',new_x='LMARGIN',new_y='NEXT'); pdf.ln(2)
                    break
        if not shown:
            _font('',9); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN)
            pdf.multi_cell(CONTENT_W,5,_txt(ps('default defense')),align='R' if is_rtl else 'L',new_x='LMARGIN',new_y='NEXT')

    # ── Companion CSV ──────────────────────────────────────────────────────────
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(['=== FULL THREAT BREAKDOWN ==='])
    writer.writerow(['Attack Type','Flow Count','% of Threats','Severity'])
    for lbl,cnt in sorted(threat_bd.items(),key=lambda x:x[1],reverse=True):
        sev,_,_=get_severity(lbl); pct=f"{round(cnt/malicious*100,1)}%" if malicious else '0%'
        writer.writerow([lbl,cnt,pct,sev])
    writer.writerow([])
    writer.writerow(['=== ATTACKER IP SUMMARY ==='])
    writer.writerow(['Source IP','Malicious Flows','% of Threats','Attack Types','Max Severity','Avg Confidence %','Target IPs','Target Ports'])
    for ip,info in top_ips:
        ms=min(info['severities'],key=lambda s:SEV_ORDER.get(s,3)) if info['severities'] else 'UNKNOWN'
        ac=round(sum(info['confidences'])/len(info['confidences']),1) if info['confidences'] else 0
        pct=f"{round(info['count']/malicious*100,1)}%" if malicious else '0%'
        writer.writerow([_csv_safe(ip),info['count'],pct,_csv_safe('|'.join(info['attacks'])),ms,ac,
                         _csv_safe('|'.join(list(info['dst_ips'])[:10])),_csv_safe('|'.join(sorted(list(info['ports']))[:10]))])
    writer.writerow([])
    writer.writerow(['=== ALL MALICIOUS FLOWS ==='])
    writer.writerow(['Flow ID','Label','Src IP','Src Port','Dst IP','Dst Port','Protocol','Severity','Confidence %'])
    for r in mal_rows:
        writer.writerow([r.get('flow_id',''),r.get('label',''),_csv_safe(r.get('src_ip','')),r.get('src_port',''),
                         _csv_safe(r.get('dst_ip','')),r.get('dst_port',''),r.get('protocol',''),r.get('severity',''),r.get('confidence',0)])

    # ── ZIP bundle ─────────────────────────────────────────────────────────────
    pdf_fname = f'bastion_report_{scan_id}.pdf'
    zip_fname = f'bastion_report_{scan_id}.zip'
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(pdf_fname, bytes(pdf.output()))
        zf.writestr(csv_fname, csv_buf.getvalue())
    zip_buf.seek(0)
    return send_file(zip_buf, as_attachment=True,
                     download_name=_safe(zip_fname),
                     mimetype='application/zip')

# ── CEF Export ────────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>/export/cef')
@login_required
def export_cef(scan_id):
    entry, rows = load_results(scan_id)
    if not entry:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))

    mal_rows = [r for r in rows if r.get('is_malicious')]
    lines = [f"# BASTION IDS — CEF Export — Scan {scan_id}",
             f"# Generated: {datetime.now().isoformat()}",
             f"# Total malicious flows: {len(mal_rows)}", ""]

    def _cef_hdr(v):
        """Escape characters for CEF header fields (backslash and pipe must be escaped)."""
        return str(v).replace('\\', '\\\\').replace('|', '\\|').replace('\r', '').replace('\n', '')

    def _cef_ext(v):
        """Escape characters for CEF extension values (backslash and equals must be escaped)."""
        return str(v).replace('\\', '\\\\').replace('=', '\\=').replace('\r', '').replace('\n', '')

    for r in mal_rows:
        sev_num = SEVERITY_NUM.get(r.get('severity','UNKNOWN'), 3)
        attack  = _cef_hdr(r.get('label', 'Unknown'))
        src_ip  = _cef_ext(r.get('src_ip', '0.0.0.0'))
        dst_ip  = _cef_ext(r.get('dst_ip', '0.0.0.0'))
        src_pt  = _cef_ext(r.get('src_port', '0'))
        dst_pt  = _cef_ext(r.get('dst_port', '0'))
        proto   = _cef_ext(r.get('protocol', '0'))
        conf    = r.get('confidence', 0)
        cef = (f"CEF:0|BASTION-IDS|NetworkIDS|1.0|{attack}|{attack} Detected|{sev_num}|"
               f"src={src_ip} dst={dst_ip} spt={src_pt} dpt={dst_pt} "
               f"proto={proto} cs1={_cef_ext(r.get('severity','UNKNOWN'))} cs1Label=Severity "
               f"cs2={conf} cs2Label=Confidence flexNumber1={_cef_ext(r.get('flow_id',0))} flexNumber1Label=FlowID")
        lines.append(cef)

    content = '\n'.join(lines)
    buf = io.BytesIO(content.encode('utf-8'))
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f'sentinel_cef_{scan_id}.txt',
                     mimetype='text/plain')

# ── Watchlist ─────────────────────────────────────────────────────────────────
@app.route('/watchlist')
@login_required
def watchlist():
    with _WATCHLIST_LOCK:
        wl = load_watchlist()
    return render_template('watchlist.html', watchlist=wl)

@app.route('/watchlist/add', methods=['POST'])
@login_required
def watchlist_add():
    # Support both JSON (AJAX) and form POST
    if request.is_json:
        data = request.get_json(silent=True) or {}
        ip            = data.get('ip', '').strip()[:64]
        note          = data.get('note', '').strip()[:500]
        threat_level  = data.get('threat_level', '').strip()[:32]
        alert_on_hit  = bool(data.get('alert_on_hit', False))
        expires_at    = data.get('expires_at', '').strip()[:32]
    else:
        ip            = request.form.get('ip', '').strip()[:64]
        note          = request.form.get('note', '').strip()[:500]
        threat_level  = request.form.get('threat_level', '').strip()[:32]
        alert_on_hit  = bool(request.form.get('alert_on_hit', False))
        expires_at    = request.form.get('expires_at', '').strip()[:32]

    if not ip:
        if request.is_json:
            return jsonify(ok=False, error=t('flash ip required')), 400
        flash(t('flash ip required'), 'error')
        return redirect(url_for('watchlist'))

    try:
        # Accept both exact IPs and CIDR notation (e.g. 10.0.0.0/8)
        if '/' in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
    except ValueError:
        if request.is_json:
            return jsonify(ok=False, error=t('flash invalid ip')), 400
        flash(t('flash invalid ip'), 'error')
        return redirect(url_for('watchlist'))

    with _WATCHLIST_LOCK:
        wl = load_watchlist()
        if any(w.get('ip') == ip for w in wl):
            if request.is_json:
                return jsonify(ok=False, error=t('flash ip already watchlist').replace('{ip}', ip))
            flash(t('flash ip already watchlist').replace('{ip}', ip), 'error')
            return redirect(url_for('watchlist'))

        wl.append({'ip': ip, 'added_at': datetime.now().isoformat(), 'note': note,
                   'hit_count': 0, 'threat_level': threat_level,
                   'alert_on_hit': alert_on_hit, 'expires_at': expires_at})
        save_watchlist(wl)
    audit('watchlist_add', detail=f'Added {ip} to watchlist')

    if request.is_json:
        return jsonify(ok=True, message=t('flash ip added watchlist').replace('{ip}', ip))
    flash(t('flash ip added watchlist').replace('{ip}', ip), 'success')
    return redirect(url_for('watchlist'))

@app.route('/watchlist/remove', methods=['POST'])
@login_required
def watchlist_remove():
    ip = request.form.get('ip', '').strip()[:64]
    if not ip:
        flash(t('flash ip required'), 'error')
        return redirect(url_for('watchlist'))
    # Validate IP/CIDR to prevent audit-log injection with arbitrary strings
    try:
        if '/' in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
    except ValueError:
        flash(t('flash invalid ip'), 'error')
        return redirect(url_for('watchlist'))
    with _WATCHLIST_LOCK:
        wl = [w for w in load_watchlist() if w.get('ip') != ip]
        save_watchlist(wl)
    audit('watchlist_remove', detail=f'Removed {ip} from watchlist')
    flash(t('flash ip removed watchlist').replace('{ip}', ip), 'success')
    return redirect(url_for('watchlist'))

@app.route('/watchlist/edit', methods=['POST'])
@login_required
def watchlist_edit():
    data = request.get_json(silent=True) or request.form
    ip = data.get('ip','').strip()[:64]
    note = data.get('note','').strip()[:500]
    threat_level = data.get('threat_level','').strip()[:32]
    alert_on_hit = bool(data.get('alert_on_hit', False))
    expires_at = data.get('expires_at','').strip()[:32]
    if not ip:
        if request.is_json:
            return jsonify(ok=False, error=t('flash ip required')), 400
        flash(t('flash ip required'), 'error')
        return redirect(url_for('watchlist'))
    try:
        # Accept both exact IPs and CIDR notation
        if '/' in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
    except ValueError:
        if request.is_json:
            return jsonify(ok=False, error=t('flash invalid ip')), 400
        flash(t('flash invalid ip'), 'error')
        return redirect(url_for('watchlist'))
    with _WATCHLIST_LOCK:
        wl = load_watchlist()
        for w in wl:
            if w.get('ip') == ip:
                w['note'] = note
                if threat_level: w['threat_level'] = threat_level
                w['alert_on_hit'] = alert_on_hit
                if expires_at: w['expires_at'] = expires_at
                break
        save_watchlist(wl)
    audit('watchlist_edit', detail=f'Edited watchlist entry for {ip}')
    if request.is_json:
        return jsonify(ok=True)
    flash(t('flash watchlist updated').replace('{ip}', ip), 'success')
    return redirect(url_for('watchlist'))

@app.route('/watchlist/toggle_alert', methods=['POST'])
@login_required
def watchlist_toggle_alert():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip','').strip()[:64]
    with _WATCHLIST_LOCK:
        wl = load_watchlist()
        for w in wl:
            if w.get('ip') == ip:
                w['alert_on_hit'] = not w.get('alert_on_hit', False)
                save_watchlist(wl)
                return jsonify(ok=True, alert_on_hit=w['alert_on_hit'])
    return jsonify(ok=False, error=t('api not found')), 404

@app.route('/watchlist/import', methods=['POST'])
@login_required
def watchlist_import():
    f = request.files.get('file')
    if not f:
        flash(t('flash no file'), 'error')
        return redirect(url_for('watchlist'))
    # Parse the uploaded file first (outside the lock — no need to hold it during I/O)
    import_filename = f.filename
    new_entries = []
    try:
        raw = f.read()
        text = raw.decode('utf-8-sig')
        lines = text.splitlines()
        if not lines:
            flash(t('flash file empty'), 'error')
            return redirect(url_for('watchlist'))
        first = lines[0]
        _MAX_WL_IMPORT = 10_000   # cap to prevent memory exhaustion from huge uploads
        seen_ips: set = set()
        if ',' in first:
            reader = csv.DictReader(lines)
            fieldnames = reader.fieldnames or []
            ip_cols = [k for k in fieldnames if k.strip().lower() in ('source ip', 'destination ip', 'src ip', 'dst ip', 'ip', 'source_ip', 'destination_ip', 'src_ip', 'dst_ip')]
            for row in reader:
                if len(new_entries) >= _MAX_WL_IMPORT:
                    break
                for col in ip_cols:
                    ip = row.get(col, '').strip()
                    if not ip or ip in seen_ips:
                        continue
                    try:
                        if '/' in ip:
                            ipaddress.ip_network(ip, strict=False)
                        else:
                            ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    new_entries.append({'ip': ip, 'added_at': datetime.now().isoformat(), 'note': f'Imported from {secure_filename(import_filename)}', 'threat_level': '', 'hit_count': 0, 'alert_on_hit': False})
                    seen_ips.add(ip)
                    if len(new_entries) >= _MAX_WL_IMPORT:
                        break
        else:
            for line in lines:
                if len(new_entries) >= _MAX_WL_IMPORT:
                    break
                ip = line.strip()
                if not ip or ip in seen_ips:
                    continue
                try:
                    if '/' in ip:
                        ipaddress.ip_network(ip, strict=False)
                    else:
                        ipaddress.ip_address(ip)
                except ValueError:
                    continue
                new_entries.append({'ip': ip, 'added_at': datetime.now().isoformat(), 'note': '', 'threat_level': '', 'hit_count': 0, 'alert_on_hit': False})
                seen_ips.add(ip)
    except Exception as e:
        app.logger.error(f'Watchlist CSV import error: {e}', exc_info=True)
        flash(t('flash import error'), 'error')
        return redirect(url_for('watchlist'))
    # Merge under lock to avoid TOCTOU with concurrent watchlist writes
    added = 0
    with _WATCHLIST_LOCK:
        wl = load_watchlist()
        existing = {w['ip'] for w in wl if 'ip' in w}
        for entry in new_entries:
            if entry['ip'] not in existing:
                wl.append(entry)
                existing.add(entry['ip'])
                added += 1
        save_watchlist(wl)
    audit('watchlist_import', detail=f'Imported {added} IPs')
    flash(t('flash imported ips').replace('{n}', str(added)), 'success')
    return redirect(url_for('watchlist'))

@app.route('/watchlist/sample')
@login_required
def watchlist_sample():
    import io as _io
    sample_rows = [
        ['ip', 'note', 'threat_level'],
        ['192.168.1.100', 'Suspicious internal host', 'High'],
        ['10.0.0.55',     'Lateral movement detected', 'Critical'],
        ['172.16.0.200',  'Rogue device', 'Medium'],
        ['203.0.113.10',  'Known scanner', 'High'],
        ['198.51.100.25', 'C2 server', 'Critical'],
        ['185.220.101.5', 'Tor exit node', 'High'],
        ['45.33.32.156',  'Port scanner (Nmap)', 'Medium'],
        ['91.108.4.1',    'Telegram abuse IP', 'Low'],
        ['1.1.1.1',       'Cloudflare DNS', 'Low'],
        ['8.8.8.8',       'Google DNS', 'Low'],
    ]
    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(sample_rows)
    buf.seek(0)
    return send_file(io.BytesIO(buf.getvalue().encode()), as_attachment=True, download_name='watchlist_sample.csv', mimetype='text/csv')

@app.route('/watchlist/export')
@login_required
def watchlist_export():
    with _WATCHLIST_LOCK:
        wl = load_watchlist()
    import io as _io
    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['ip','note','threat_level','hit_count','last_seen','added_at','expires_at','alert_on_hit'])
    for w in wl:
        writer.writerow([_csv_safe(w.get('ip','')),_csv_safe(w.get('note','')),_csv_safe(w.get('threat_level','')),w.get('hit_count',0),_csv_safe(w.get('last_seen','')),_csv_safe(w.get('added_at','')),_csv_safe(w.get('expires_at','')),w.get('alert_on_hit',False)])
    buf.seek(0)
    return send_file(io.BytesIO(buf.getvalue().encode()), as_attachment=True, download_name='watchlist.csv', mimetype='text/csv')

# ── Alert Rules ───────────────────────────────────────────────────────────────
def load_alert_rules():
    if ALERT_RULES_PATH.exists():
        try:
            with open(ALERT_RULES_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def save_alert_rules(rules):
    _safe_write(ALERT_RULES_PATH, rules)

@app.route('/rules', methods=['GET','POST'])
@admin_required
def alert_rules():
    if request.method == 'POST':
        action = request.form.get('action')
        with _ALERT_RULES_LOCK:
            rules = load_alert_rules()
            if action == 'add':
                rule_name = request.form.get('name','').strip()[:128]
                condition = request.form.get('condition','').strip()[:256]
                try:
                    threshold = max(1, int(request.form.get('threshold', 100)))
                except (ValueError, TypeError):
                    threshold = 100
                try:
                    window_min = max(1, int(request.form.get('window_min', 5)))
                except (ValueError, TypeError):
                    window_min = 5
                rule_action = request.form.get('rule_action', 'email')
                if rule_action not in ('email', 'webhook', 'both'):
                    rule_action = 'email'
                rules.append({'id': str(uuid.uuid4())[:8], 'name': rule_name,
                    'condition': condition,
                    'threshold': threshold,
                    'window_min': window_min,
                    'action': rule_action,
                    'enabled': True, 'created': datetime.now().isoformat(),
                    'created_at': datetime.now().isoformat()})
                save_alert_rules(rules)
                flash(t('flash alert rule added'), 'success')
            elif action == 'delete':
                rid = request.form.get('rule_id', '')[:64]
                rules = [r for r in rules if r.get('id') != rid]
                save_alert_rules(rules)
                flash(t('flash rule deleted'), 'success')
            elif action == 'toggle':
                rid = request.form.get('rule_id', '')[:64]
                for r in rules:
                    if r.get('id') == rid: r['enabled'] = not r.get('enabled', True)
                save_alert_rules(rules)
        return redirect(url_for('alert_rules'))
    with _ALERT_RULES_LOCK:
        rules = load_alert_rules()
    return render_template('rules.html', rules=rules)

# ── Schedules ─────────────────────────────────────────────────────────────────
def load_schedules():
    if SCHEDULES_PATH.exists():
        try:
            with open(SCHEDULES_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def save_schedules(scheds):
    _safe_write(SCHEDULES_PATH, scheds)

def _run_scheduled_scan(sched):
    fp = Path(sched.get('file_path') or '')
    # Re-validate the stored path is within UPLOAD_DIR to guard against tampered schedules.json
    try:
        fp.resolve().relative_to(UPLOAD_DIR.resolve())
    except (ValueError, OSError):
        app.logger.warning(f'[Scheduler] Rejecting out-of-bounds file path: {fp}')
        return
    if not fp.exists(): return
    scan_id = datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
    dest = UPLOAD_DIR / f'upload_{scan_id}.csv'
    import shutil; shutil.copy(str(fp), str(dest))
    state = make_state(scan_id, fp.name)
    state['user'] = 'scheduler'
    state['lang'] = cfg('language', 'en')
    with SCANS_LOCK: SCANS[scan_id] = state
    threading.Thread(target=_run_scan, args=(scan_id, dest, 'scheduler'), daemon=True).start()

def _scheduler_thread():
    import time as _time
    _last_fired: set = set()  # set of (sched_id, HH:MM) already triggered this minute
    while True:
        _time.sleep(60)
        try:
            now = datetime.now().strftime('%H:%M')
            # Purge stale entries from previous minutes
            _last_fired = {k for k in _last_fired if k[1] == now}
            with _SCHEDULE_LOCK:
                _current_scheds = load_schedules()
            for sched in _current_scheds:
                if not sched.get('enabled'):
                    continue
                if sched.get('cron_time') != now:
                    continue
                key = (sched.get('id', ''), now)
                if key in _last_fired:
                    continue
                _last_fired.add(key)
                _run_scheduled_scan(sched)
        except Exception as e:
            print(f'[BASTION] Scheduler error: {e}')

threading.Thread(target=_scheduler_thread, daemon=True).start()

@app.route('/schedule', methods=['GET','POST'])
@admin_required
def schedule():
    if request.method == 'POST':
        action = request.form.get('action')
        # Validate path before acquiring lock (no I/O risk, avoids lock-during-validation)
        if action == 'add':
            cron_time = request.form.get('cron_time','00:00').strip()
            if not re.match(r'^([01]\d|2[0-3]):[0-5]\d$', cron_time):
                cron_time = '00:00'
            raw_fp = request.form.get('file_path','').strip()
            sched_fp = Path(raw_fp)
            try:
                sched_fp.resolve().relative_to(UPLOAD_DIR.resolve())
            except (ValueError, OSError):
                flash(t('flash invalid file path'), 'error')
                return redirect(url_for('schedule'))
        with _SCHEDULE_LOCK:
            scheds = load_schedules()
            if action == 'add':
                scheds.append({'id': str(uuid.uuid4())[:8],
                    'name': request.form.get('name','').strip()[:128],
                    'cron_time': cron_time,
                    'time': cron_time,
                    'file_path': str(sched_fp),
                    'enabled': 'enabled' in request.form,
                    'created': datetime.now().isoformat(),
                    'last_run': None})
                save_schedules(scheds)
                flash(t('flash schedule added'), 'success')
            elif action == 'delete':
                sid = request.form.get('schedule_id', '')[:64]
                scheds = [s for s in scheds if s.get('id') != sid]
                save_schedules(scheds)
                flash(t('flash schedule deleted'), 'success')
            elif action == 'toggle':
                sid = request.form.get('schedule_id', '')[:64]
                for s in scheds:
                    if s.get('id') == sid: s['enabled'] = not s.get('enabled', True)
                save_schedules(scheds)
        return redirect(url_for('schedule'))
    with _SCHEDULE_LOCK:
        scheds_list = load_schedules()
    return render_template('schedule.html', schedules=scheds_list)

# ── Correlation ───────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>/correlation')
@login_required
def correlation(scan_id):
    entry, rows = load_results(scan_id)
    if not entry:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))

    mal_rows = [r for r in rows if r.get('is_malicious')]
    grouped = {}
    for r in mal_rows:
        src = r.get('src_ip', 'N/A')
        if src not in grouped:
            grouped[src] = {'src_ip': src, 'attack_types': set(), 'flow_count': 0,
                            'max_severity_rank': 0, 'max_severity': 'SAFE', 'confidences': []}
        grouped[src]['attack_types'].add(r.get('label', 'Unknown'))
        grouped[src]['flow_count'] += 1
        rank = SEVERITY_RANK.get(r.get('severity', 'SAFE'), 0)
        if rank > grouped[src]['max_severity_rank']:
            grouped[src]['max_severity_rank'] = rank
            grouped[src]['max_severity'] = r.get('severity', 'SAFE')
        grouped[src]['confidences'].append(r.get('confidence', 0))

    corr_list = []
    for ip, g in grouped.items():
        avg_conf = round(float(np.mean(g['confidences'])), 2) if g['confidences'] else 0
        threat_score = g['flow_count'] * g['max_severity_rank']
        corr_list.append({
            'src_ip':       ip,
            'attack_types': list(g['attack_types']),
            'flow_count':   g['flow_count'],
            'max_severity': g['max_severity'],
            'avg_confidence': avg_conf,
            'threat_score': threat_score,
        })
    corr_list.sort(key=lambda x: x['threat_score'], reverse=True)
    return render_template('correlation.html', entry=entry, correlations=corr_list)

# ── Compare ───────────────────────────────────────────────────────────────────
@app.route('/compare')
@login_required
def compare_select():
    return render_template('compare_select.html', history=load_user_history())

@app.route('/compare/<id1>/<id2>')
@login_required
def compare_legacy(id1, id2):
    return redirect(url_for('compare_multi', ids=f'{id1},{id2}'))

@app.route('/compare/multi')
@login_required
def compare_multi():
    ids_param = request.args.get('ids', '')
    ids = [i.strip() for i in ids_param.split(',') if i.strip()][:5]
    if len(ids) < 2:
        flash(t('flash compare min 2'), 'error')
        return redirect(url_for('compare_select'))
    current_user = session.get('user', '')
    scans = []
    for sid in ids:
        entry, rows = load_results(sid)
        if not entry:
            flash(t('flash scan id not found').replace('{sid}', str(sid)), 'error')
            return redirect(url_for('compare_select'))
        if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
            flash(t('flash access denied scan'), 'error')
            return redirect(url_for('compare_select'))
        scans.append({'entry': entry, 'rows': rows[:2000]})
    return render_template('compare.html', scans=scans)

# ── Threat Intelligence Feed ──────────────────────────────────────────────────
@app.route('/threat-intel')
@login_required
def threat_intel():
    role = get_roles().get(session.get('user', ''), 'analyst')
    history = load_history() if role in ('admin', 'cc_admin') else load_user_history()
    recent = history[:50]  # last 50 scans

    # --- Top malicious IPs ---
    ip_stats = {}   # ip -> {count, scans, attack_types}
    attack_totals = {}
    for entry in recent:
        fp = Path(entry.get('flows_file') or '')
        if not fp.exists():
            # fall back to threat_breakdown if no flows file
            for lbl, cnt in entry.get('threat_breakdown', {}).items():
                attack_totals[lbl] = attack_totals.get(lbl, 0) + cnt
            continue
        try:
            df = pd.read_csv(fp, nrows=50_000, usecols=lambda c: c.strip() in
                             {'label', 'Label', 'src_ip', 'Source IP', 'dst_ip', 'Destination IP'})
            df.columns = [c.strip() for c in df.columns]
            label_col = next((c for c in ('label', 'Label') if c in df.columns), None)
            ip_col    = next((c for c in ('src_ip', 'Source IP') if c in df.columns), None)
            dst_col   = next((c for c in ('dst_ip', 'Destination IP') if c in df.columns), None)
            if label_col:
                mal = df[df[label_col].astype(str).str.upper() != 'BENIGN']
                for lbl, cnt in mal[label_col].value_counts().items():
                    lbl = clean_label(str(lbl))
                    attack_totals[lbl] = attack_totals.get(lbl, 0) + int(cnt)
                _ip_cols = [c for c in (ip_col, dst_col) if c]
                if _ip_cols:
                    for _, row in mal.iterrows():
                        lbl = clean_label(str(row.get(label_col, '')))
                        _sid = entry.get('scan_id', '')
                        for _ic in _ip_cols:
                            ip = str(row.get(_ic, '')).strip()
                            if not ip or ip in ('nan', 'N/A', ''):
                                continue
                            try:
                                ipaddress.ip_address(ip)
                            except ValueError:
                                continue
                            rec = ip_stats.setdefault(ip, {'count': 0, 'scans': set(), 'attack_types': set()})
                            rec['count'] += 1
                            if _sid:
                                rec['scans'].add(_sid)
                            if lbl:
                                rec['attack_types'].add(lbl)
        except Exception:
            for lbl, cnt in entry.get('threat_breakdown', {}).items():
                attack_totals[lbl] = attack_totals.get(lbl, 0) + cnt

    # Sort top IPs by frequency, cap to 20
    top_ips = sorted(ip_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:20]
    top_ips_out = []
    ip_cache = load_ip_cache()
    for ip, stats in top_ips:
        cached = ip_cache.get(ip, {})
        _priv = is_private_ip(ip)
        top_ips_out.append({
            'ip':           ip,
            'count':        stats['count'],
            'scan_count':   len(stats['scans']),
            'attack_types': sorted(stats['attack_types']),
            'abuse_score':  cached.get('abuseScore', None),
            'country':      cached.get('country', 'Private' if _priv else 'N/A'),
            'isp':          cached.get('isp', 'Internal' if _priv else 'N/A'),
            'last_reported': cached.get('lastReported', 'N/A'),
            'is_private':   _priv,
        })

    # Attack breakdown: top 10 by volume
    attack_chart = sorted(attack_totals.items(), key=lambda x: x[1], reverse=True)[:10]

    # Cached intel: IPs with AbuseIPDB data, sorted by score
    cached_intel = []
    for ip, data in ip_cache.items():
        if ip.startswith('shodan_') or ip.startswith('vt_'):
            continue
        score = data.get('abuseScore')
        if score is None:
            continue
        cached_intel.append({
            'ip':           ip,
            'abuse_score':  score,
            'country':      data.get('country', 'N/A'),
            'isp':          data.get('isp', 'N/A'),
            'total_reports': data.get('totalReports', 0),
            'last_reported': data.get('lastReported', 'N/A'),
            'cached_at':    data.get('cached_at', ''),
            'vt_score':     data.get('vtScore'),
            'vt_malicious': data.get('vtMalicious'),
            'vt_total':     data.get('vtTotal'),
        })
    cached_intel.sort(key=lambda x: x['abuse_score'], reverse=True)
    cached_intel = cached_intel[:30]

    has_abuseipdb = bool(get_config().get('abuseipdb_key', ''))

    return render_template('threat_intel.html',
                           top_ips=top_ips_out,
                           attack_chart=attack_chart,
                           cached_intel=cached_intel,
                           has_abuseipdb=has_abuseipdb,
                           scan_count=len(recent))


# ── IP Reputation ─────────────────────────────────────────────────────────────
@app.route('/api/reputation/<ip>')
@login_required
def api_reputation(ip):
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(error=t('api invalid ip')), 400
    if is_private_ip(ip):
        return jsonify(private=True, note=t('private IP query note'))

    c = get_config()
    api_key = c.get('abuseipdb_key', '')
    if not api_key:
        return jsonify(error=t('api abuseipdb key not set'), configure=True), 503

    cache = load_ip_cache()
    now = datetime.now()
    if ip in cache:
        cached = cache[ip]
        try:
            cached_at = datetime.fromisoformat(cached.get('cached_at', '2000-01-01'))
        except (ValueError, TypeError):
            cached_at = datetime(2000, 1, 1)
        if now - cached_at < timedelta(hours=24):
            return jsonify(cached)

    try:
        resp = req_lib.get('https://api.abuseipdb.com/api/v2/check',
                           headers={'Key': api_key, 'Accept': 'application/json'},
                           params={'ipAddress': ip, 'maxAgeInDays': 90},
                           timeout=10)
        if resp.status_code == 429:
            return jsonify(error=t('api rate limited')), 429
        if resp.status_code == 401:
            return jsonify(error=t('api abuseipdb invalid key')), 401
        if not resp.ok:
            return jsonify(error=f'AbuseIPDB HTTP {resp.status_code}'), resp.status_code
        data = resp.json().get('data', {})
        result = {
            'ip':            ip,
            'abuseScore':    data.get('abuseConfidenceScore', 0),
            'country':       data.get('countryCode', 'N/A'),
            'isp':           data.get('isp', 'N/A'),
            'domain':        data.get('domain', 'N/A'),
            'totalReports':  data.get('totalReports', 0),
            'lastReported':  data.get('lastReportedAt', 'N/A'),
            'cached_at':     now.isoformat(),
        }
    except Exception:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=t('api internal error')), 500

    # ── VirusTotal enrichment (silent fail — AbuseIPDB result always returned) ──
    vt_key = c.get('virustotal_key', '')
    if vt_key:
        try:
            vt_resp = req_lib.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': vt_key},
                timeout=10
            )
            if vt_resp.status_code == 200:
                attrs = vt_resp.json().get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                vt_malicious  = stats.get('malicious', 0)
                vt_suspicious = stats.get('suspicious', 0)
                vt_harmless   = stats.get('harmless', 0)
                vt_undetected = stats.get('undetected', 0)
                vt_total = vt_malicious + vt_suspicious + vt_harmless + vt_undetected
                result['vtScore']     = round((vt_malicious / vt_total) * 100) if vt_total > 0 else 0
                result['vtMalicious'] = vt_malicious
                result['vtTotal']     = vt_total
        except Exception:
            pass  # VirusTotal failure does not block the AbuseIPDB result

    with _IP_CACHE_LOCK:
        fresh_cache = load_ip_cache()
        fresh_cache[ip] = result
        save_ip_cache(fresh_cache)
    return jsonify(result)

# ── VirusTotal IP Lookup ───────────────────────────────────────────────────────
@app.route('/api/virustotal/<ip>')
@login_required
def api_virustotal(ip):
    ip = ip.strip()
    if not ip or ip == 'nan':
        return jsonify(error=t('api no ip')), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(error=t('api invalid ip')), 400
    if is_private_ip(ip):
        return jsonify(private=True, note=t('private IP query note'))

    c = get_config()
    api_key = c.get('virustotal_key', '')
    if not api_key:
        return jsonify(error=t('api vt key not set'), configure=True), 503

    cache = load_ip_cache()
    cache_key = f'vt_{ip}'
    now = datetime.now()
    if cache_key in cache:
        cached = cache[cache_key]
        try:
            cached_at = datetime.fromisoformat(cached.get('cached_at', '2000-01-01'))
        except (ValueError, TypeError):
            cached_at = datetime(2000, 1, 1)
        if now - cached_at < timedelta(hours=24):
            return jsonify(cached)

    try:
        resp = req_lib.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={'x-apikey': api_key},
            timeout=10
        )
        if resp.status_code == 404:
            return jsonify(error=t('api vt ip not found')), 404
        resp.raise_for_status()
        attrs = resp.json().get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        result = {
            'ip':          ip,
            'malicious':   stats.get('malicious', 0),
            'suspicious':  stats.get('suspicious', 0),
            'harmless':    stats.get('harmless', 0),
            'undetected':  stats.get('undetected', 0),
            'country':     attrs.get('country', 'N/A'),
            'as_owner':    attrs.get('as_owner', 'N/A'),
            'reputation':  attrs.get('reputation', 0),
            'cached_at':   now.isoformat(),
        }
        with _IP_CACHE_LOCK:
            fresh_cache = load_ip_cache()
            fresh_cache[cache_key] = result
            save_ip_cache(fresh_cache)
        return jsonify(result)
    except Exception as e:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=t('api internal error')), 500

# ── Shodan IP Lookup ───────────────────────────────────────────────────────────
@app.route('/api/shodan/<ip>')
@login_required
def api_shodan(ip):
    ip = ip.strip()
    if not ip or ip == 'nan':
        return jsonify(error=t('api no ip')), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(error=t('api invalid ip')), 400
    if is_private_ip(ip):
        return jsonify(private=True, note=t('private IP query note'))

    c = get_config()
    api_key = c.get('shodan_key', '')
    if not api_key:
        return jsonify(error=t('api shodan key not set'), configure=True), 503

    cache = load_ip_cache()
    cache_key = f'shodan_{ip}'
    now = datetime.now()
    if cache_key in cache:
        cached = cache[cache_key]
        try:
            cached_at = datetime.fromisoformat(cached.get('cached_at', '2000-01-01'))
        except (ValueError, TypeError):
            cached_at = datetime(2000, 1, 1)
        if now - cached_at < timedelta(hours=24):
            return jsonify(cached)

    try:
        resp = req_lib.get(
            f'https://api.shodan.io/shodan/host/{ip}',
            params={'key': api_key},
            timeout=10
        )
        if resp.status_code == 401:
            return jsonify(error=t('api shodan invalid key')), 401
        if resp.status_code == 404:
            return jsonify(error=t('api shodan ip not found')), 404
        if not resp.ok:
            # Return the actual Shodan error message if available
            try:
                shodan_err = resp.json().get('error', resp.text[:200])
            except Exception:
                shodan_err = resp.text[:200]
            return jsonify(error=str(shodan_err)), resp.status_code
        d = resp.json()
        result = {
            'ip':          ip,
            'org':         d.get('org', 'N/A'),
            'isp':         d.get('isp', 'N/A'),
            'country':     d.get('country_name', 'N/A'),
            'city':        d.get('city', 'N/A'),
            'ports':       d.get('ports', []),
            'hostnames':   d.get('hostnames', []),
            'tags':        d.get('tags', []),
            'vulns':       list(d.get('vulns', {}).keys()),
            'last_update': d.get('last_update', 'N/A'),
            'cached_at':   now.isoformat(),
        }
        with _IP_CACHE_LOCK:
            fresh_cache = load_ip_cache()
            fresh_cache[cache_key] = result
            save_ip_cache(fresh_cache)
        return jsonify(result)
    except req_lib.exceptions.Timeout:
        return jsonify(error=t('api shodan timed out')), 504
    except req_lib.exceptions.ConnectionError:
        return jsonify(error=t('api shodan conn failed')), 503
    except Exception as e:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=f'{type(e).__name__}: {str(e)[:120]}'), 500

# ── Model page ────────────────────────────────────────────────────────────────
@app.route('/model')
@login_required
def model_page():
    report_path = OUTPUTS / 'training_report.txt'
    report_text = report_path.read_text(encoding='utf-8', errors='replace') if report_path.exists() else 'No training report found.'
    return render_template('model_page.html', report_text=report_text,
                           model_loaded=model is not None, retrain_running=RETRAIN_STATE['running'])

@app.route('/model/retrain/start', methods=['POST'])
@admin_required
def model_retrain_start():
    with _RETRAIN_LOCK:
        if RETRAIN_STATE['running']:
            return jsonify(error=t('retrain already running')), 409
        RETRAIN_STATE['running'] = True   # claim the slot before releasing the lock
    RETRAIN_STATE['log'] = []
    main_py = BASE_DIR / 'main.py'
    try:
        proc = subprocess.Popen(
            [sys.executable, str(main_py)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=str(BASE_DIR)
        )
        RETRAIN_STATE['proc'] = proc
        def _watch():
            for line in proc.stdout:
                RETRAIN_STATE['log'].append(line.rstrip())
            proc.wait()
            RETRAIN_STATE['running'] = False
            RETRAIN_STATE['proc'] = None
        threading.Thread(target=_watch, daemon=True).start()
        return jsonify(status='started')
    except Exception as e:
        RETRAIN_STATE['running'] = False
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=t('api internal error')), 500

@app.route('/api/model/retrain/status')
@admin_required
def model_retrain_status():
    def generate():
        idx = 0
        while True:
            lines = RETRAIN_STATE['log']
            while idx < len(lines):
                yield f"data: {json.dumps({'line': lines[idx]})}\n\n"
                idx += 1
            if not RETRAIN_STATE['running'] and idx >= len(lines):
                yield f"data: {json.dumps({'done': True})}\n\n"
                return
            time.sleep(0.5)
    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/model/reload')
@admin_required
def model_reload():
    load_models()
    flash(t('flash models reloaded'), 'success')
    return redirect(url_for('model_page'))

# ── Settings ──────────────────────────────────────────────────────────────────
@app.route('/settings', methods=['GET','POST'])
@admin_required
def settings():
    if request.method == 'POST':
        # Validate inputs before acquiring the lock
        smtp_to = request.form.get('smtp_to', '').strip()
        if smtp_to and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', smtp_to):
            flash(t('flash invalid recipient email'), 'error')
            return redirect(url_for('settings'))
        webhook_url = request.form.get('webhook_url', '').strip()
        _webhook_error = None
        if webhook_url:
            from urllib.parse import urlparse as _urlparse
            _pu = _urlparse(webhook_url)
            _host = _pu.hostname or ''
            if _pu.scheme not in ('http', 'https'):
                _webhook_error = t('flash webhook must use https')
            elif _host == 'localhost':
                _webhook_error = t('flash webhook no localhost')
            else:
                try:
                    _addr = ipaddress.ip_address(_host)
                    if _addr.is_private or _addr.is_loopback or _addr.is_link_local or _addr.is_unspecified or _addr.is_reserved or _addr.is_multicast:
                        _webhook_error = t('flash webhook no private ip')
                except ValueError:
                    pass  # hostname is a domain name, not a raw IP — allow it
        if _webhook_error:
            flash(_webhook_error, 'error')
            return redirect(url_for('settings'))
        with _CONFIG_LOCK:
            c = get_config()
            c['smtp_host']        = request.form.get('smtp_host', '').strip()
            try:
                smtp_port = int(request.form.get('smtp_port', 587))
                c['smtp_port'] = smtp_port if 1 <= smtp_port <= 65535 else 587
            except (ValueError, TypeError):
                c['smtp_port'] = 587
            c['smtp_user']        = request.form.get('smtp_user', '').strip()
            smtp_pass             = request.form.get('smtp_pass', '')
            if smtp_pass:
                c['smtp_pass']    = smtp_pass
            c['smtp_to'] = smtp_to
            c['webhook_url'] = webhook_url
            abuseipdb_key         = request.form.get('abuseipdb_key', '').strip()
            if abuseipdb_key:
                c['abuseipdb_key'] = abuseipdb_key
            virustotal_key        = request.form.get('virustotal_key', '').strip()
            if virustotal_key:
                c['virustotal_key'] = virustotal_key
            shodan_key            = request.form.get('shodan_key', '').strip()
            if shodan_key:
                c['shodan_key'] = shodan_key
            c['alert_on_critical'] = 'alert_on_critical' in request.form
            c['alert_on_high']     = 'alert_on_high' in request.form
            save_config(c)
            reload_config()
        audit('settings_save', detail='System settings updated')
        flash(t('flash settings saved'), 'success')
        return redirect(url_for('settings'))
    c = get_config()
    return render_template('settings.html', config=c)

@app.route('/settings/test_email', methods=['POST'])
@admin_required
def test_email():
    c = get_config()
    if not c.get('smtp_host'):
        return jsonify(error=t('smtp not configured')), 400
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '[BASTION IDS] Test Email'
        msg['From']    = c.get('smtp_user')
        msg['To']      = c.get('smtp_to')
        msg.attach(MIMEText('<h2>BASTION IDS test email - OK</h2>', 'html'))
        with smtplib.SMTP(c.get('smtp_host'), int(c.get('smtp_port', 587))) as srv:
            srv.ehlo(); srv.starttls()
            srv.login(c.get('smtp_user'), c.get('smtp_pass', ''))
            srv.sendmail(c.get('smtp_user'), c.get('smtp_to'), msg.as_string())
        return jsonify(status=t('test email ok'))
    except Exception as e:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=t('api internal error')), 500

@app.route('/settings/test_webhook', methods=['POST'])
@admin_required
def test_webhook():
    c = get_config()
    if not c.get('webhook_url'):
        return jsonify(error=t('webhook url not configured')), 400
    try:
        resp = req_lib.post(c.get('webhook_url'), json={'test': True, 'source': 'BASTION IDS'}, timeout=10)
        return jsonify(status=t('webhook responded').replace('{code}', str(resp.status_code)))
    except Exception as e:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error=t('api internal error')), 500

# ── Admin ─────────────────────────────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin():
    c = get_config()
    users = c.get('users', {})
    roles = c.get('roles', {})
    history = load_history()
    stats = {
        'total_scans':   len(history),
        'total_flows':   sum(h.get('total_flows', 0) for h in history),
        'model_loaded':  model is not None,
        'config_status': 'OK' if CONFIG_PATH.exists() else 'Missing',
        'watchlist_count': len(load_watchlist()),
    }
    last_login = c.get('user_last_login', {})
    managed_by = c.get('managed_by', {})
    disabled_users = c.get('disabled_users', [])
    all_users = list(users.keys())
    role_order = {'admin': 0, 'cc_admin': 1, 'analyst': 2}
    user_list = sorted(
        [{'username': u, 'role': roles.get(u, 'analyst'),
          'last_login': last_login.get(u, 'Never'),
          'disabled': u in disabled_users} for u in users],
        key=lambda x: (role_order.get(x['role'], 9), x['username'])
    )
    cc_admin_list = [u for u in users if roles.get(u) == 'cc_admin']

    # Build CC Admin overview: for each cc_admin, list their managed analysts
    cc_admins = [u for u in users if roles.get(u) == 'cc_admin']
    cc_admin_data = []
    audit_data = []
    with _AUDIT_LOCK:
        if AUDIT_PATH.exists():
            try:
                with open(AUDIT_PATH) as f:
                    audit_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                audit_data = []
    for cca in cc_admins:
        my_analysts = [u for u in users if roles.get(u) == 'analyst' and managed_by.get(u) == cca]
        analyst_list = [{'username': a, 'last_login': last_login.get(a, 'Never')} for a in my_analysts]
        # Recent activity for these analysts
        names = set(my_analysts)
        activity = [ev for ev in reversed(audit_data)
                    if ev.get('action') in ('login','logout') and ev.get('user') in names][:50]
        cc_admin_data.append({'username': cca, 'analysts': analyst_list, 'activity': activity})

    return render_template('admin.html', user_list=user_list, stats=stats,
                           last_login=last_login, all_users=all_users,
                           cc_admin_data=cc_admin_data, cc_admin_list=cc_admin_list)

@app.route('/admin/add_user', methods=['POST'])
@admin_required
def admin_add_user():
    u    = request.form.get('username', '').strip()
    p    = request.form.get('password', '')[:256]
    role = request.form.get('role', 'analyst')
    if not u or not p:
        flash(t('flash user pass required'), 'error')
        return redirect(url_for('admin'))
    if not re.match(r'^[A-Za-z0-9_]{1,32}$', u):
        flash(t('flash invalid username'), 'error')
        return redirect(url_for('admin'))
    if len(p) < 8:
        flash(t('flash password too short'), 'error')
        return redirect(url_for('admin'))
    if role not in ('analyst', 'cc_admin', 'admin'):
        flash(t('flash invalid role'), 'error')
        return redirect(url_for('admin'))
    with _CONFIG_LOCK:
        c = get_config()
        users = c.get('users', {})
        roles = c.get('roles', {})
        if u in users:
            flash(t('flash user exists').replace('{u}', u), 'error')
            return redirect(url_for('admin'))
        users[u] = hashlib.sha256(p.encode()).hexdigest()
        roles[u] = role
        c['users'] = users
        c['roles'] = roles
        # If analyst, optionally assign to a cc_admin
        if role == 'analyst':
            assign_to = request.form.get('assign_to_cc_admin', '').strip()
            if assign_to and assign_to in users and roles.get(assign_to) == 'cc_admin':
                managed_by = c.get('managed_by', {})
                managed_by[u] = assign_to
                c['managed_by'] = managed_by
        save_config(c)
        reload_config()
    audit('user_add', detail=f'Added user {u} with role {role}')
    flash(t('flash user added').replace('{u}', u), 'success')
    return redirect(url_for('admin'))

@app.route('/admin/remove_user', methods=['POST'])
@admin_required
def admin_remove_user():
    u = request.form.get('username', '').strip()
    if u == session.get('user'):
        flash(t('flash cannot remove self'), 'error')
        return redirect(url_for('admin'))
    with _CONFIG_LOCK:
        c = get_config()
        roles = c.get('roles', {})
        # Prevent removing the last admin account
        if roles.get(u) == 'admin':
            remaining_admins = [name for name, role in roles.items() if role == 'admin' and name != u]
            if not remaining_admins:
                flash(t('flash cannot remove last admin'), 'error')
                return redirect(url_for('admin'))
        c.get('users', {}).pop(u, None)
        roles.pop(u, None)
        c.get('managed_by', {}).pop(u, None)
        # Clean up stale user metadata to prevent inheritance if username is re-created
        c.get('2fa_secrets', {}).pop(u, None)
        c.get('user_last_login', {}).pop(u, None)
        disabled = c.get('disabled_users', [])
        if u in disabled:
            disabled.remove(u)
            c['disabled_users'] = disabled
        save_config(c)
        reload_config()
    audit('user_remove', detail=f'Removed user {u}')
    flash(t('flash user removed').replace('{u}', u), 'success')
    return redirect(url_for('admin'))

@app.route('/admin/toggle_user', methods=['POST'])
@admin_required
def admin_toggle_user():
    u = request.form.get('username', '').strip()
    if u == session.get('user'):
        flash(t('flash cannot disable self'), 'error')
        return redirect(url_for('admin'))
    was_disabled = False
    with _CONFIG_LOCK:
        c = get_config()
        disabled = c.get('disabled_users', [])
        if u in disabled:
            disabled.remove(u)
            was_disabled = True
        else:
            disabled.append(u)
        c['disabled_users'] = disabled
        save_config(c)
        reload_config()
    if was_disabled:
        flash(t('flash user enabled').replace('{u}', u), 'success')
        audit('user_enable', detail=f'Enabled user {u}')
    else:
        flash(t('flash user disabled').replace('{u}', u), 'success')
        audit('user_disable', detail=f'Disabled user {u}')
    return redirect(url_for('admin'))

@app.route('/admin/set_role', methods=['POST'])
@admin_required
def admin_set_role():
    u    = request.form.get('username', '').strip()
    role = request.form.get('role', '').strip()
    if u == session.get('user'):
        flash(t('flash cannot change own role'), 'error')
        return redirect(url_for('admin'))
    if role not in ('analyst', 'cc_admin', 'admin'):
        flash(t('flash invalid role'), 'error')
        return redirect(url_for('admin'))
    with _CONFIG_LOCK:
        c = get_config()
        if u not in c.get('users', {}):
            flash(t('flash user not found').replace('{u}', u), 'error')
            return redirect(url_for('admin'))
        c.get('roles', {})[u] = role
        save_config(c)
        reload_config()
    audit('user_role_change', detail=f'Changed {u} role to {role}')
    flash(t('flash role set').replace('{u}', u).replace('{role}', role), 'success')
    return redirect(url_for('admin'))

@app.route('/admin/promote_analyst', methods=['POST'])
@admin_required
def admin_promote_analyst():
    u = request.form.get('username', '').strip()
    if u == session.get('user'):
        flash(t('flash cannot change own role'), 'error')
        return redirect(url_for('admin'))
    with _CONFIG_LOCK:
        c = get_config()
        roles = c.get('roles', {})
        if u not in c.get('users', {}):
            flash(t('flash user not found').replace('{u}', u), 'error')
            return redirect(url_for('admin'))
        if roles.get(u, 'analyst') != 'analyst':
            flash(t('flash invalid role'), 'error')
            return redirect(url_for('admin'))
        roles[u] = 'cc_admin'
        c['roles'] = roles
        save_config(c)
        reload_config()
    audit('user_promote', detail=f'Promoted {u} to cc_admin')
    flash(t('flash promoted cc admin').replace('{u}', u), 'success')
    return redirect(url_for('admin'))

@app.route('/admin/move_analyst', methods=['POST'])
@admin_required
def admin_move_analyst():
    u       = request.form.get('username', '').strip()
    new_cca = request.form.get('new_cc_admin', '').strip()
    with _CONFIG_LOCK:
        c = get_config()
        if u not in c.get('users', {}):
            flash(t('flash user not found').replace('{u}', u), 'error')
            return redirect(url_for('admin'))
        managed_by = c.get('managed_by', {})
        if new_cca:
            if new_cca in c.get('users', {}) and c.get('roles', {}).get(new_cca) == 'cc_admin':
                managed_by[u] = new_cca
            else:
                flash(t('flash user not found').replace('{u}', new_cca), 'error')
                return redirect(url_for('admin'))
        else:
            managed_by.pop(u, None)
        c['managed_by'] = managed_by
        save_config(c)
        reload_config()
    audit('analyst_move', detail=f'Moved analyst {u} to {new_cca or "unassigned"}')
    flash(t('flash analyst moved').replace('{u}', u).replace('{dest}', new_cca or t('unassigned')), 'success')
    return redirect(url_for('admin'))

# ── API Status Page ────────────────────────────────────────────────────────────
@app.route('/status-page')
@login_required
def api_status_page():
    c = get_config()
    services = []

    # 1. IDS Model
    services.append({
        'name': 'IDS ML Model',
        'icon': 'cpu',
        'status': 'online' if model is not None else 'offline',
        'detail': t('XGBoost acc label') if model is not None else (model_error or t('svc not loaded')),
        'note': t('svc model note'),
    })

    # 2. AbuseIPDB
    abuse_key = c.get('abuseipdb_key', '')
    if abuse_key:
        try:
            r = req_lib.get('https://api.abuseipdb.com/api/v2/check',
                            headers={'Key': abuse_key, 'Accept': 'application/json'},
                            params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 90},
                            timeout=5)
            if r.status_code == 200:
                services.append({'name': 'AbuseIPDB', 'icon': 'shield', 'status': 'online',
                                  'detail': t('svc connected ip'),
                                  'note': f'Key: {abuse_key[:8]}…'})
            elif r.status_code == 401:
                services.append({'name': 'AbuseIPDB', 'icon': 'shield', 'status': 'error',
                                  'detail': t('svc invalid key'),
                                  'note': f'Key: {abuse_key[:8]}…'})
            else:
                services.append({'name': 'AbuseIPDB', 'icon': 'shield', 'status': 'warning',
                                  'detail': f'HTTP {r.status_code}',
                                  'note': f'Key: {abuse_key[:8]}…'})
        except Exception as e:
            services.append({'name': 'AbuseIPDB', 'icon': 'shield', 'status': 'error',
                              'detail': f'{t("svc connection failed")}: {e}', 'note': t('svc unreachable')})
    else:
        services.append({'name': 'AbuseIPDB', 'icon': 'shield', 'status': 'warning',
                          'detail': t('svc api key not configured'),
                          'note': t('svc configure settings')})

    # 3. SMTP Email Alerts
    smtp_host = c.get('smtp_host', '')
    smtp_user = c.get('smtp_user', '')
    smtp_to   = c.get('smtp_to', '')
    if smtp_host and smtp_user and smtp_to:
        try:
            with smtplib.SMTP(smtp_host, int(c.get('smtp_port', 587)), timeout=5) as srv:
                srv.ehlo()
                srv.starttls()
                srv.ehlo()
            services.append({'name': 'SMTP Email Alerts', 'icon': 'mail', 'status': 'online',
                              'detail': t('svc smtp connected').replace('{host}', smtp_host).replace('{port}', str(c.get('smtp_port', 587))),
                              'note': t('svc smtp alert to').replace('{email}', smtp_to)})
        except Exception as e:
            services.append({'name': 'SMTP Email Alerts', 'icon': 'mail', 'status': 'error',
                              'detail': f'{t("svc connection failed")}: {e}',
                              'note': f'{t("svc smtp host")}: {smtp_host}'})
    else:
        services.append({'name': 'SMTP Email Alerts', 'icon': 'mail', 'status': 'warning',
                          'detail': t('svc not configured'),
                          'note': t('svc configure settings')})

    # 4. Webhook
    webhook_url = c.get('webhook_url', '')
    if webhook_url:
        try:
            r = req_lib.head(webhook_url, timeout=5)
            services.append({'name': 'Webhook', 'icon': 'zap', 'status': 'online',
                              'detail': f'{t("svc webhook reachable")} · HTTP {r.status_code}',
                              'note': webhook_url[:50] + ('…' if len(webhook_url) > 50 else '')})
        except Exception as e:
            services.append({'name': 'Webhook', 'icon': 'zap', 'status': 'error',
                              'detail': f'{t("svc connection failed")}: {e}',
                              'note': webhook_url[:50]})
    else:
        services.append({'name': 'Webhook', 'icon': 'zap', 'status': 'warning',
                          'detail': t('svc not configured'),
                          'note': t('svc configure settings')})

    # 5. Storage
    try:
        import shutil
        total, used, free = shutil.disk_usage(str(BASE_DIR))
        pct = round(used / total * 100, 1)
        status = 'online' if pct < 85 else ('warning' if pct < 95 else 'error')
        scan_count = len(list(FLOWS_DIR.glob('scan_*.csv'))) if FLOWS_DIR.exists() else 0
        services.append({'name': 'Storage', 'icon': 'database', 'status': status,
                          'detail': f'{pct}% {t("svc storage used")} · {free / (1024**3):.1f} GB {t("svc storage free")}',
                          'note': f'{scan_count} {t("svc storage scan files")}'})
    except Exception as e:
        services.append({'name': 'Storage', 'icon': 'database', 'status': 'warning',
                          'detail': f'{t("svc could not read")}: {e}', 'note': ''})

    online  = sum(1 for s in services if s['status'] == 'online')
    warning = sum(1 for s in services if s['status'] == 'warning')
    error   = sum(1 for s in services if s['status'] == 'error')

    return render_template('api_status.html', services=services,
                           online=online, warning=warning, error=error,
                           checked_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

# ── API ───────────────────────────────────────────────────────────────────────
@app.route('/api/status')
@login_required
def api_status():
    return jsonify(status='online', model_loaded=model is not None,
                   model_error='Model failed to load — check server logs.' if model_error else None,
                   timestamp=datetime.now().isoformat())

@app.route('/api/predict', methods=['POST'])
def api_predict():
    key = request.headers.get('X-API-Key','')
    if not key:
        return jsonify(error='Unauthorized'), 401
    users = get_users()
    hashed_key = hashlib.sha256(key.encode()).hexdigest()
    if not any(_secrets.compare_digest(hashed_key, h) for h in users.values()):
        return jsonify(error='Unauthorized'), 401
    with _MODEL_LOCK:
        _m, _pp, _fn, _le = model, preprocessor, feature_names, label_encoder
    if _m is None or _pp is None or _fn is None or _le is None:
        return jsonify(error='Model not loaded — check server logs'), 503
    f = request.files.get('file')
    if not f: return jsonify(error='No file'), 400
    try:
        df      = pd.read_csv(f, nrows=500_000)
        df.columns = df.columns.str.strip()
        df.replace([np.inf,-np.inf], np.nan, inplace=True)
        X = pd.DataFrame(0.0, index=df.index, columns=_fn)
        for col in _fn:
            if col in df.columns: X[col] = df[col]
        X = X.fillna(X.median(numeric_only=True)).fillna(0.0)
        X_s   = _pp.transform(X)
        preds = _m.predict(X_s)
        probs = _m.predict_proba(X_s)
        lbls  = [clean_label(l) for l in _le[preds]]
        confs = probs[np.arange(len(preds)), preds] * 100
        results = []
        for i,(label,conf) in enumerate(zip(lbls,confs)):
            sev,color,rank = get_severity(label)
            results.append({'flow_id':i+1,'label':label,'confidence':round(float(conf),2),
                            'severity':sev,'color':color,'is_malicious':label!='BENIGN'})
        malicious = sum(1 for r in results if r['is_malicious'])
        return jsonify(total=len(results), malicious=malicious,
                       benign=len(results)-malicious, results=results)
    except Exception as e:
        app.logger.exception('Internal error in %s', request.path)
        return jsonify(error='An internal error occurred'), 500

# ── Notifications ─────────────────────────────────────────────────────────────
@app.route('/notifications')
@login_required
def notifications():
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    with _NOTIF_LOCK:
        notifs = load_notifications()
    notifs = [n for n in notifs if not n.get('target_roles') or role in n['target_roles']]
    return render_template('notifications.html', notifications=notifs)

@app.route('/api/notifications/mark_read', methods=['POST'])
@login_required
def api_notifications_mark_read():
    me   = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    data   = request.get_json(force=True) or {}
    with _NOTIF_LOCK:
        notifs = load_notifications()
        if data.get('all'):
            for n in notifs:
                if not n.get('target_roles') or role in n['target_roles']:
                    n['read'] = True
        else:
            nid = data.get('id')
            for n in notifs:
                if n.get('id') == nid and (not n.get('target_roles') or role in n['target_roles']):
                    n['read'] = True
        _safe_write(NOTIFICATIONS_PATH, notifs)
    return jsonify(ok=True)

@app.route('/api/notifications/delete', methods=['POST'])
@login_required
def api_notifications_delete():
    me   = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    data   = request.get_json(force=True) or {}
    nid    = data.get('id')
    with _NOTIF_LOCK:
        notifs = load_notifications()
        notifs = [n for n in notifs if not (
            n.get('id') == nid and (not n.get('target_roles') or role in n['target_roles'])
        )]
        _safe_write(NOTIFICATIONS_PATH, notifs)
    return jsonify(ok=True)

# ── Flow Triage ────────────────────────────────────────────────────────────────
@app.route('/api/triage', methods=['POST'])
@login_required
def api_triage():
    data    = request.get_json(force=True) or {}
    scan_id = data.get('scan_id','')
    flow_id = str(data.get('flow_id',''))
    status  = data.get('status','')
    if status not in ('investigated', 'false_positive', 'confirmed'):
        return jsonify(error=t('api invalid status')), 400
    scan_entry, _ = load_results(scan_id)
    if scan_entry and scan_entry.get('user') not in (None, '', session.get('user','')) and session.get('role','analyst') not in ('admin','cc_admin'):
        return jsonify(error=t('api access denied')), 403
    with _TRIAGE_LOCK:
        triage = load_triage()
        if scan_id not in triage:
            triage[scan_id] = {}
        triage[scan_id][flow_id] = status
        save_triage(triage)
    audit('triage', detail=f'Scan {scan_id} flow {flow_id} → {status}')
    # FP feedback
    if status == 'false_positive':
        try:
            _, rows = load_results(scan_id)
            row = next((r for r in rows if str(r.get('flow_id','')) == flow_id), {})
            append_fp_feedback(scan_id, flow_id,
                               row.get('src_ip','N/A'),
                               row.get('label','Unknown'),
                               session.get('user',''))
        except Exception:
            pass
    return jsonify(ok=True)

@app.route('/api/triage/bulk', methods=['POST'])
@login_required
def api_triage_bulk():
    data     = request.get_json(force=True) or {}
    scan_id  = data.get('scan_id','')
    flow_ids = data.get('flow_ids', [])
    status   = data.get('status','')
    case_id  = data.get('case_id','')
    if status not in ('investigated', 'false_positive', 'confirmed'):
        return jsonify(error=t('api invalid status')), 400
    if not flow_ids:
        return jsonify(error=t('api no flow ids')), 400
    if len(flow_ids) > 5000:
        return jsonify(error=t('api too many flow ids')), 400
    try:
        flow_ids = [int(fid) for fid in flow_ids]
    except (ValueError, TypeError):
        return jsonify(error=t('api flow ids integers')), 400
    scan_entry, rows = load_results(scan_id)
    if scan_entry and scan_entry.get('user') not in (None, '', session.get('user','')) and session.get('role','analyst') not in ('admin','cc_admin'):
        return jsonify(error=t('api access denied')), 403
    rows_by_id = {str(r.get('flow_id','')): r for r in rows}
    with _TRIAGE_LOCK:
        triage = load_triage()
        if scan_id not in triage:
            triage[scan_id] = {}
        for fid in flow_ids:
            triage[scan_id][str(fid)] = status
        save_triage(triage)
    # FP feedback appended outside the lock (append_fp_feedback uses its own lock)
    if status == 'false_positive':
        for fid in flow_ids:
            try:
                row = rows_by_id.get(str(fid), {})
                append_fp_feedback(scan_id, str(fid),
                                   row.get('src_ip','N/A'),
                                   row.get('label','Unknown'),
                                   session.get('user',''))
            except Exception:
                pass
    audit('triage_bulk', detail=f'Scan {scan_id} bulk {len(flow_ids)} flows → {status}')
    # Optionally add to case — verify user has access to the case first
    if case_id and re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        me   = session.get('user', '')
        role = session.get('role', 'analyst')
        with _CASES_LOCK:
            all_cases = load_cases()
            for c in all_cases:
                if c['id'] == case_id:
                    allowed = (role in ('admin', 'cc_admin')
                               or c.get('analyst') == me
                               or me in get_assignees(c))
                    if allowed and scan_id not in c.get('scan_ids', []):
                        c.setdefault('scan_ids', []).append(scan_id)
                    break
            save_cases(all_cases)
    return jsonify(ok=True, count=len(flow_ids))

# ── Audit Log ──────────────────────────────────────────────────────────────────
@app.route('/audit')
@admin_required
def audit_log():
    log = []
    with _AUDIT_LOCK:
        if AUDIT_PATH.exists():
            try:
                with open(AUDIT_PATH) as f:
                    log = json.load(f)
            except (json.JSONDecodeError, OSError):
                log = []
    log_reversed = list(reversed(log))
    return render_template('audit_log.html', log=log_reversed)

# ── Scan Tagging ───────────────────────────────────────────────────────────────
@app.route('/api/tag', methods=['POST'])
@login_required
def api_tag():
    data    = request.get_json(force=True) or {}
    scan_id = data.get('scan_id','')
    tag     = data.get('tag','').strip()
    action  = data.get('action','add')
    if not scan_id or not tag:
        return jsonify(error='scan_id and tag required'), 400
    if len(tag) > 64:
        return jsonify(error='Tag must be 64 characters or fewer'), 400
    current_user = session.get('user', '')
    current_role = session.get('role', 'analyst')
    with _HISTORY_LOCK:
        h = load_history()
        for entry in h:
            if entry.get('scan_id') == scan_id:
                # Only allow tagging own scans unless admin/cc_admin
                if (entry.get('user') not in (None, '', current_user)
                        and current_role not in ('admin', 'cc_admin')):
                    return jsonify(error='Access denied'), 403
                tags = entry.get('tags', [])
                if action == 'add' and tag not in tags:
                    if len(tags) >= 50:
                        return jsonify(error='Maximum 50 tags per scan'), 400
                    tags.append(tag)
                elif action == 'remove' and tag in tags:
                    tags.remove(tag)
                entry['tags'] = tags
                break
        _safe_write(HISTORY, h[:500])
    return jsonify(ok=True)

# ── Whois Lookup ───────────────────────────────────────────────────────────────
@app.route('/api/whois/<ip>')
@login_required
def api_whois(ip):
    ip = ip.strip()
    if not ip or ip == 'nan':
        return jsonify(ip=ip, private=True, note='No IP address.')
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(ip=ip, error='Invalid IP address'), 400
    if is_private_ip(ip):
        return jsonify(ip=ip, private=True, note='Private/reserved IP — no public WHOIS data.')
    import socket as _socket
    result = {'ip': ip, 'hostname': '', 'org': '', 'city': '', 'country': '', 'error': ''}
    try:
        hostname, _, _ = _socket.gethostbyaddr(ip)
        result['hostname'] = hostname
    except Exception:
        result['hostname'] = ip
    # Check cache first
    ip_cache = load_ip_cache()
    cached = ip_cache.get(ip, {})
    if cached.get('org') or cached.get('abuse_score') is not None:
        # Return from cache if present
        result.update(cached)
        return jsonify(result)

    try:
        r = req_lib.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get('bogon'):
                return jsonify(ip=ip, private=True, note='Bogon/reserved IP — no public WHOIS data.')
            result['org']     = d.get('org', '')
            result['city']    = d.get('city', '')
            result['country'] = d.get('country', '')
    except Exception:
        pass

    # AbuseIPDB enrichment
    abuse_key = cfg('abuseipdb_key', '')
    if abuse_key:
        try:
            ar = req_lib.get('https://api.abuseipdb.com/api/v2/check',
                             headers={'Key': abuse_key, 'Accept': 'application/json'},
                             params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''},
                             timeout=6)
            if ar.status_code == 200:
                ad = ar.json().get('data', {})
                result['abuse_score']   = ad.get('abuseConfidenceScore', 0)
                result['abuse_reports'] = ad.get('totalReports', 0)
                result['abuse_country'] = ad.get('countryCode', '')
        except Exception:
            pass

    # Update cache atomically (re-read to avoid losing concurrent updates)
    try:
        with _IP_CACHE_LOCK:
            fresh_cache = load_ip_cache()
            fresh_cache[ip] = {k: v for k, v in result.items() if k != 'ip'}
            save_ip_cache(fresh_cache)
    except Exception:
        pass

    return jsonify(result)

# ── Dashboard SSE ──────────────────────────────────────────────────────────────
@app.route('/api/dashboard/stream')
@login_required
def dashboard_stream():
    me   = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    def generate():
        try:
            while True:
                h = load_user_history()
                total_scans   = len(h)
                total_flows   = sum(x.get('total_flows',0) for x in h)
                total_threats = sum(x.get('malicious_flows',0) for x in h)
                unread        = get_unread_count(role)
                payload = json.dumps({
                    'total_scans':   total_scans,
                    'total_flows':   total_flows,
                    'total_threats': total_threats,
                    'unread_count':  unread,
                })
                yield f"data: {payload}\n\n"
                time.sleep(30)
        except GeneratorExit:
            return
    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/cases/new', methods=['POST'])
@login_required
def cases_new():
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    title       = request.form.get('title','').strip()[:256]
    description = request.form.get('description','').strip()[:2000]
    scan_id     = request.form.get('scan_id','').strip()[:64]
    # Validate that the analyst owns this scan (admins/cc_admins may link any scan)
    if scan_id:
        _scan_entry = next((x for x in load_history() if x.get('scan_id') == scan_id), None)
        if _scan_entry is None:
            flash(t('flash scan not found'), 'error')
            return redirect(url_for('cases'))
        _scan_owner = _scan_entry.get('user', '')
        if role not in ('admin', 'cc_admin') and _scan_owner not in ('', None, me):
            flash(t('flash access denied'), 'error')
            return redirect(url_for('cases'))
    priority    = request.form.get('priority','Medium').strip()
    if priority not in ('Low', 'Medium', 'High', 'Critical'):
        priority = 'Medium'
    assigned_to = [u[:32] for u in request.form.getlist('assigned_to') if u.strip()][:20]
    try:
        sla_hours = float(request.form.get('sla_hours', 24))
        sla_hours = max(1.0, sla_hours)
    except (ValueError, TypeError):
        sla_hours = 24
    if not title:
        flash(t('flash title required'), 'error')
        return redirect(url_for('cases'))
    new_case = {
        'id':          str(uuid.uuid4())[:8],
        'title':       title,
        'description': description,
        'scan_ids':    [scan_id] if scan_id else [],
        'status':      'open',
        'priority':    priority,
        'assigned_to': assigned_to,
        'analyst':     me,
        'created':     datetime.now().isoformat(),
        'notes':       [],
        'sla_hours':   sla_hours,
        'attachments': [],
        'seen_by':     [me],
    }
    # Handle file attachments (admin only) — done before acquiring cases lock (file I/O)
    if role == 'admin':
        _NEW_ATTACH_ALLOWED = {
            'pdf','txt','log','csv','json','png','jpg','jpeg','gif','bmp',
            'doc','docx','xls','xlsx','ppt','pptx','zip','pcap','pcapng'
        }
        files = request.files.getlist('attachments')[:10]
        for f in files:
            if f and f.filename:
                filename = secure_filename(f.filename)
                if not filename:
                    continue
                ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                if ext not in _NEW_ATTACH_ALLOWED:
                    flash(t('flash file type not allowed').replace('{ext}', ext), 'error')
                    continue
                case_dir = CASE_ATTACH_DIR / new_case['id']
                case_dir.mkdir(parents=True, exist_ok=True)
                try:
                    f.save(str(case_dir / filename))
                except OSError:
                    flash(t('flash file save error'), 'error')
                    continue
                if filename not in new_case['attachments']:
                    new_case['attachments'].append(filename)
    with _CASES_LOCK:
        all_cases = load_cases()
        all_cases.insert(0, new_case)
        save_cases(all_cases)
    audit('case_create', detail=f'Case "{title}" created')
    save_notification({
        'id':           f'case_new_{new_case["id"]}',
        'timestamp':    datetime.now().isoformat(),
        'type':         'info',
        'title':        f'New case: {title}',
        'message':      f'Case "{title}" (ID: {new_case["id"]}) was created by {me}.',
        'read':         False,
        'case_id':      new_case['id'],
        'target_roles': ['admin', 'cc_admin'],
    })
    flash(t('flash case created').replace('{title}', title), 'success')
    return redirect(url_for('case_detail', case_id=new_case['id']))

@app.route('/cases/<case_id>')
@login_required
def case_detail(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    roles = get_roles()
    role = roles.get(me, 'analyst')
    is_admin = role == 'admin'
    is_cc_admin_user = role == 'cc_admin'
    is_analyst = role == 'analyst'
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        if not is_admin and not is_cc_admin_user and case.get('analyst') != me and me not in get_assignees(case):
            flash(t('flash access denied'), 'error')
            return redirect(url_for('cases'))
        if me not in case.get('seen_by', []):
            case.setdefault('seen_by', []).append(me)
            save_cases(all_cases)
    # Analysts can only see linked scans they own; admins/cc_admins see all
    _history_for_case = load_history() if is_admin or is_cc_admin_user else load_user_history()
    linked_scans = [h for h in _history_for_case if h.get('scan_id') in case.get('scan_ids', [])]
    config = get_config()
    available_assignees = _available_assignees_for(me, roles, config)
    can_assign = is_admin or is_cc_admin_user
    managed_analysts = {u for u, mgr in config.get('managed_by', {}).items() if mgr == me} if is_cc_admin_user else set()
    attachments = case.get('attachments', [])
    def get_user_role(u):
        return roles.get(u, 'analyst')
    return render_template('case_detail.html', case=case, linked_scans=linked_scans,
                           is_admin=is_admin, is_cc_admin=is_cc_admin_user,
                           is_analyst=is_analyst,
                           managed_analysts=managed_analysts,
                           can_assign=can_assign,
                           available_assignees=available_assignees,
                           attachments=attachments,
                           get_assignees=get_assignees,
                           get_user_role=get_user_role,
                           current_user=me)

@app.route('/cases/<case_id>/note', methods=['POST'])
@login_required
def case_add_note(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    is_admin = role == 'admin'
    is_cc_admin = role == 'cc_admin'
    text = request.form.get('text', '').strip()[:4000]
    f = request.files.get('attachment')
    if not text and not (f and f.filename):
        return redirect(url_for('case_detail', case_id=case_id))
    # Authorization check BEFORE saving any file to disk (prevents orphaned uploads)
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash access denied'), 'error')
            return redirect(url_for('cases'))
        if not is_admin and not is_cc_admin and case.get('analyst') != me and me not in get_assignees(case):
            flash(t('flash access denied'), 'error')
            return redirect(url_for('cases'))
        existing_notes = case.setdefault('notes', [])
        if len(existing_notes) >= 500:
            flash(t('flash notes limit reached'), 'error')
            return redirect(url_for('case_detail', case_id=case_id))

    # Auth passed — now save the attachment (outside lock to avoid holding it during I/O)
    import time as _time
    note = {
        'ts':   datetime.now().isoformat(),
        'user': me,
        'text': text,
    }
    if f and f.filename:
        _NOTE_ATTACH_ALLOWED = {
            'pdf','txt','log','csv','json','png','jpg','jpeg','gif','bmp',
            'doc','docx','xls','xlsx','ppt','pptx','zip','pcap','pcapng'
        }
        _safe_fname = secure_filename(f.filename)
        if not _safe_fname:
            flash(t('flash file type not allowed').replace('{ext}', ''), 'error')
        elif (_ext := _safe_fname.rsplit('.', 1)[-1].lower() if '.' in _safe_fname else '') not in _NOTE_ATTACH_ALLOWED:
            flash(t('flash file type not allowed').replace('{ext}', _ext), 'error')
        else:
            fname = f'{int(_time.time())}_{uuid.uuid4().hex[:8]}_{_safe_fname}'
            note_dir = CASE_ATTACH_DIR / case_id / 'comments'
            note_dir.mkdir(parents=True, exist_ok=True)
            try:
                f.save(str(note_dir / fname))
                note['attachment'] = fname
            except OSError:
                flash(t('flash file save error'), 'error')

    # Re-acquire lock to append the note (case may have been updated between locks)
    with _CASES_LOCK:
        all_cases = load_cases()
        case_found = False
        for case in all_cases:
            if case['id'] == case_id:
                case_found = True
                # Re-check closed status (may have changed between lock releases)
                if case.get('status') == 'closed':
                    flash(t('flash access denied'), 'error')
                    return redirect(url_for('case_detail', case_id=case_id))
                existing_notes = case.setdefault('notes', [])
                if len(existing_notes) < 500:
                    existing_notes.append(note)
                break
        if not case_found:
            flash(t('flash access denied'), 'error')
            return redirect(url_for('cases'))
        save_cases(all_cases)
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/close', methods=['POST'])
@admin_required
def case_close(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        if case.get('status') == 'closed':
            flash(t('flash access denied'), 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        case['status'] = 'closed'
        case['closed_at'] = datetime.now().isoformat()
        save_cases(all_cases)
    audit('case_close', detail=f'Case {case_id} permanently closed')
    flash(t('flash case closed'), 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/analyst_close', methods=['POST'])
@login_required
def case_analyst_close(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    if role != 'analyst':
        flash(t('flash access denied'), 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        if case.get('analyst') != me and me not in get_assignees(case):
            flash(t('flash access denied'), 'error')
            return redirect(url_for('cases'))
        if case.get('status') != 'open':
            flash(t('flash access denied'), 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        case['status'] = 'pending_cc_review'
        case['closed_by_analyst'] = me
        case['analyst_closed_at'] = datetime.now().isoformat()
        save_cases(all_cases)
    audit('case_analyst_close', detail=f'Case {case_id} finished by analyst {me}')
    save_notification({
        'id':           f'case_analyst_close_{case_id}_{int(datetime.now().timestamp())}',
        'timestamp':    datetime.now().isoformat(),
        'type':         'medium',
        'title':        f'Case closed by analyst: {case.get("title", case_id)}',
        'message':      f'Analyst {me} has finished and closed case "{case.get("title", case_id)}". Please review and close.',
        'read':         False,
        'case_id':      case_id,
        'target_roles': ['cc_admin'],
    })
    flash(t('flash case analyst close'), 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/cc_close', methods=['POST'])
@cc_admin_required
def case_cc_close(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        if case.get('status') != 'pending_cc_review':
            flash(t('flash access denied'), 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        case['status'] = 'pending_admin_close'
        case['closed_by_cc_admin'] = me
        case['cc_closed_at'] = datetime.now().isoformat()
        save_cases(all_cases)
    audit('case_cc_close', detail=f'Case {case_id} reviewed and closed by CC Admin {me}')
    save_notification({
        'id':           f'case_cc_close_{case_id}_{int(datetime.now().timestamp())}',
        'timestamp':    datetime.now().isoformat(),
        'type':         'high',
        'title':        f'Case awaiting permanent closure: {case.get("title", case_id)}',
        'message':      f'CC Admin {me} has reviewed and closed case "{case.get("title", case_id)}". Permanent closure required.',
        'read':         False,
        'case_id':      case_id,
        'target_roles': ['admin'],
    })
    flash(t('flash case cc close'), 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/return_to_analyst', methods=['POST'])
@login_required
def case_return_to_analyst(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    if role not in ('cc_admin', 'admin'):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        if case.get('status') != 'pending_cc_review':
            flash(t('flash access denied'), 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        case['status'] = 'open'
        case['returned_by'] = me
        case['returned_at'] = datetime.now().isoformat()
        # Return to assigned analysts AND the case creator
        assignees = get_assignees(case)
        creator = case.get('analyst', '')
        returned_targets = list(set(assignees + ([creator] if creator else [])))
        case['returned_to'] = returned_targets
        save_cases(all_cases)
    audit('case_return_analyst', detail=f'Case {case_id} returned to analyst by {me}')
    save_notification({
        'id':           f'case_return_analyst_{case_id}_{int(datetime.now().timestamp())}',
        'timestamp':    datetime.now().isoformat(),
        'type':         'medium',
        'title':        f'Case returned for further work: {case.get("title", case_id)}',
        'message':      f'Case "{case.get("title", case_id)}" was returned to you by {me}. Please continue working on it.',
        'read':         False,
        'case_id':      case_id,
        'target_roles': ['analyst'],
    })
    flash(t('flash case returned analyst'), 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/return_to_cc_admin', methods=['POST'])
@admin_required
def case_return_to_cc_admin(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        if case.get('status') != 'pending_admin_close':
            flash(t('flash access denied'), 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        case['status'] = 'pending_cc_review'
        case['returned_by_admin'] = me
        case['returned_by_admin_at'] = datetime.now().isoformat()
        case['returned_to_cc'] = case.get('closed_by_cc_admin', '')
        save_cases(all_cases)
    audit('case_return_cc', detail=f'Case {case_id} returned to CC Admin by admin {me}')
    save_notification({
        'id':           f'case_return_cc_{case_id}_{int(datetime.now().timestamp())}',
        'timestamp':    datetime.now().isoformat(),
        'type':         'high',
        'title':        f'Case returned for re-review: {case.get("title", case_id)}',
        'message':      f'Admin {me} has returned case "{case.get("title", case_id)}" to CC Admin for re-review.',
        'read':         False,
        'case_id':      case_id,
        'target_roles': ['cc_admin'],
    })
    flash(t('flash case returned cc'), 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/comment/<int:comment_idx>/delete', methods=['POST'])
@login_required
def case_delete_comment(case_id, comment_idx):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    if role not in ('admin', 'cc_admin'):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        notes = case.get('notes', [])
        if 0 <= comment_idx < len(notes):
            del notes[comment_idx]
            save_cases(all_cases)
    audit('case_comment_delete', detail=f'Comment #{comment_idx} deleted from case {case_id} by {me}')
    flash(t('flash comment deleted'), 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/comment_attachment/<filename>')
@login_required
def case_comment_attachment(case_id, filename):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    is_admin = role == 'admin'
    is_cc_admin = role == 'cc_admin'
    with _CASES_LOCK:
        all_cases = load_cases()
    case = next((c for c in all_cases if c['id'] == case_id), None)
    if not case or (not is_admin and not is_cc_admin and case.get('analyst') != me and me not in get_assignees(case)):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    safe = secure_filename(filename)
    # Only serve files that are recorded in a note's attachment field
    note_attachments = {n.get('attachment') for n in case.get('notes', []) if n.get('attachment')}
    if safe not in note_attachments:
        flash(t('flash access denied'), 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    return send_from_directory(str(CASE_ATTACH_DIR / case_id / 'comments'), safe)

@app.route('/cases/<case_id>/attach', methods=['POST'])
@admin_required
def case_attach(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    _ATTACH_ALLOWED = {
        'pdf','txt','log','csv','json','png','jpg','jpeg','gif','bmp',
        'doc','docx','xls','xlsx','ppt','pptx','zip','pcap','pcapng'
    }
    # Verify case exists and is not closed BEFORE saving files (prevents orphaned uploads)
    with _CASES_LOCK:
        _pre_cases = load_cases()
        _pre_case = next((c for c in _pre_cases if c['id'] == case_id), None)
    if not _pre_case:
        flash(t('flash case not found'), 'error')
        return redirect(url_for('cases'))
    if _pre_case.get('status') == 'closed':
        flash(t('flash access denied'), 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    # Save files to disk before re-acquiring the cases lock (avoids lock-during-I/O)
    files = request.files.getlist('attachments')[:10]
    case_dir = CASE_ATTACH_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    saved_files = []
    for f in files:
        if f and f.filename:
            filename = secure_filename(f.filename)
            if not filename:
                continue
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if ext not in _ATTACH_ALLOWED:
                flash(t('flash file type not allowed').replace('{ext}', ext), 'error')
                continue
            try:
                f.save(str(case_dir / filename))
                saved_files.append(filename)
            except OSError:
                flash(t('flash file save error'), 'error')
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        # Re-check closed status under lock (may have changed during file I/O)
        if case.get('status') == 'closed':
            flash(t('flash access denied'), 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        atts = case.setdefault('attachments', [])
        for filename in saved_files:
            if filename not in atts:
                atts.append(filename)
        save_cases(all_cases)
    audit('case_attach', detail=f'Attachment added to case {case_id}')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/attachment/<path:filename>')
@login_required
def case_attachment(case_id, filename):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    is_admin = role == 'admin'
    is_cc_admin = role == 'cc_admin'
    with _CASES_LOCK:
        all_cases = load_cases()
    case = next((c for c in all_cases if c['id'] == case_id), None)
    if not case or (not is_admin and not is_cc_admin and case.get('analyst') != me and me not in get_assignees(case)):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    safe = secure_filename(filename)
    # Only serve files that are actually recorded in the case attachments list
    if safe not in case.get('attachments', []):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    return send_from_directory(str(CASE_ATTACH_DIR / case_id), safe)

@app.route('/cases/<case_id>/assign', methods=['POST'])
@login_required
def case_assign(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    roles = get_roles()
    role = roles.get(me, 'analyst')
    is_admin = role == 'admin'
    is_cc_admin_user = role == 'cc_admin'
    can_assign = is_admin or is_cc_admin_user
    with _CASES_LOCK:
        all_cases = load_cases()
        case = next((c for c in all_cases if c['id'] == case_id), None)
        if not case:
            flash(t('flash case not found'), 'error')
            return redirect(url_for('cases'))
        if not is_admin and not is_cc_admin_user and case.get('analyst') != me and me not in get_assignees(case):
            flash(t('flash access denied'), 'error')
            return redirect(url_for('cases'))
        if can_assign:
            new_assignees = [u[:32] for u in request.form.getlist('assigned_to') if u.strip()][:20]
            if is_cc_admin_user:
                config = get_config()
                allowed = set(_available_assignees_for(me, roles, config))
                new_assignees = [u for u in new_assignees if u in allowed]
            else:
                # Admin: validate assignees exist in the system
                valid_users = set(get_users().keys())
                new_assignees = [u for u in new_assignees if u in valid_users]
            case['assigned_to'] = new_assignees
            case['assigned_by'] = me
            if is_admin:
                priority = request.form.get('priority', '').strip()
                if priority in ('Low', 'Medium', 'High', 'Critical'):
                    case['priority'] = priority
        save_cases(all_cases)
    audit('case_assign', detail=f'Case {case_id} assigned/priority updated')
    flash(t('flash case updated'), 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/cases/<case_id>/export/pdf')
@login_required
def case_export_pdf(case_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', case_id):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    me = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    is_admin = role == 'admin'
    is_cc_admin = role == 'cc_admin'
    with _CASES_LOCK:
        all_cases = load_cases()
    case = next((c for c in all_cases if c['id'] == case_id), None)
    if not case:
        flash(t('flash case not found'), 'error')
        return redirect(url_for('cases'))
    if not is_admin and not is_cc_admin and case.get('analyst') != me and me not in get_assignees(case):
        flash(t('flash access denied'), 'error')
        return redirect(url_for('cases'))
    # Analysts can only see linked scans they own
    _history_for_pdf = load_history() if is_admin or is_cc_admin else load_user_history()
    linked_scans = [h for h in _history_for_pdf if h.get('scan_id') in case.get('scan_ids', [])]
    try:
        from fpdf import FPDF
    except ImportError:
        flash(t('flash fpdf2 missing'), 'error')
        return redirect(url_for('case_detail', case_id=case_id))

    def _safe(s):
        v = str(s).replace('\u2014','-').replace('\u2013','-').replace('\u2019',"'").replace('\u2018',"'").replace('\ufffd','?')
        return v.encode('latin-1', errors='replace').decode('latin-1')
    # ── Arabic support ─────────────────────────────────────────────────────────
    lang = session.get('lang', cfg('language', 'en'))
    is_rtl = lang == 'ar'
    _arabic_ok = False; _arabic_font = None; _arabic_font_bold = None
    if is_rtl:
        try:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Regular.ttf',
                        BASE_DIR / 'static/fonts/Amiri-Regular.ttf',
                        Path('C:/Windows/Fonts/Arial.ttf')]:
                if _fp.exists(): _arabic_font = str(_fp); _arabic_ok = True; break
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Bold.ttf',
                        BASE_DIR / 'static/fonts/NotoNaskhArabic-SemiBold.ttf']:
                if _fp.exists(): _arabic_font_bold = str(_fp); break
        except ImportError:
            pass

    def _txt(s):
        v = str(s)
        if is_rtl and _arabic_ok:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            return bidi_display(arabic_reshaper.reshape(v))
        return _safe(v)

    def _fit(text, w):
        maxc = max(1, int(w / 1.9))
        s = _txt(str(text)) if (is_rtl and _arabic_ok) else _safe(str(text))
        return (s[:maxc-2]+'..') if len(s) > maxc else s

    _CS = {
        'en': {
            'case subtitle': 'Incident Case Report',
            'Case ID': 'Case ID', 'Status': 'Status', 'Priority': 'Priority',
            'Analyst': 'Analyst', 'Assigned To': 'Assigned To',
            'Created': 'Created', 'Generated': 'Generated',
            's1': '1. Case Details', 's2': '2. Linked Scans',
            's2 desc': '{n} scan(s) associated with this case.',
            's3': '3. Case Timeline / Comments',
            'Scan ID': 'Scan ID', 'Date': 'Date', 'File': 'File',
            'Flows': 'Flows', 'Threats': 'Threats',
            'csv ref': 'Full data available in companion file: {filename}',
        },
        'ar': {
            'case subtitle': '\u062a\u0642\u0631\u064a\u0631 \u0627\u0644\u0642\u0636\u064a\u0629 \u0627\u0644\u0623\u0645\u0646\u064a\u0629',
            'Case ID': '\u0645\u0639\u0631\u0641 \u0627\u0644\u0642\u0636\u064a\u0629', 'Status': '\u0627\u0644\u062d\u0627\u0644\u0629',
            'Priority': '\u0627\u0644\u0623\u0648\u0644\u0648\u064a\u0629', 'Analyst': '\u0627\u0644\u0645\u062d\u0644\u0644',
            'Assigned To': '\u0645\u064f\u0639\u064a\u064e\u0651\u0646 \u0625\u0644\u0649', 'Created': '\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u0625\u0646\u0634\u0627\u0621',
            'Generated': '\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u062a\u0642\u0631\u064a\u0631',
            's1': '1. \u062a\u0641\u0627\u0635\u064a\u0644 \u0627\u0644\u0642\u0636\u064a\u0629',
            's2': '2. \u0627\u0644\u0641\u062d\u0648\u0635\u0627\u062a \u0627\u0644\u0645\u0631\u062a\u0628\u0637\u0629',
            's2 desc': '{n} \u0641\u062d\u0635 \u0645\u0631\u062a\u0628\u0637 \u0628\u0647\u0630\u0647 \u0627\u0644\u0642\u0636\u064a\u0629.',
            's3': '3. \u0627\u0644\u062c\u062f\u0648\u0644 \u0627\u0644\u0632\u0645\u0646\u064a / \u0627\u0644\u062a\u0639\u0644\u064a\u0642\u0627\u062a',
            'Scan ID': '\u0645\u0639\u0631\u0641 \u0627\u0644\u0641\u062d\u0635', 'Date': '\u0627\u0644\u062a\u0627\u0631\u064a\u062e',
            'File': '\u0627\u0644\u0645\u0644\u0641', 'Flows': '\u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a',
            'Threats': '\u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a',
            'csv ref': '\u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0643\u0627\u0645\u0644\u0629 \u0645\u062a\u0627\u062d\u0629 \u0641\u064a \u0627\u0644\u0645\u0644\u0641 \u0627\u0644\u0645\u0631\u0641\u0642: {filename}',
        }
    }
    def cs(key, **kwargs):
        s = _CS.get(lang, _CS['en']).get(key, _CS['en'].get(key, key))
        return s.format(**kwargs) if kwargs else s

    # ── Light color palette ────────────────────────────────────────────────────
    C_BG=(255,255,255); C_NAVY=(20,50,110); C_ACCENT=(60,120,200)
    C_TXT=(25,35,55); C_MUTED=(100,110,130); C_TH_BG=(210,225,248)
    C_TH_TXT=(15,40,100); C_ROW_ALT=(245,248,254); C_BORDER=(180,195,220); C_FOOTER=(150,160,180)
    PRIORITY_COLOR={'Critical':(170,0,15),'High':(160,70,0),'Medium':(120,90,0),'Low':(0,100,40)}
    STATUS_COLOR={'open':(170,0,15),'in_progress':(120,90,0),'resolved':(0,100,40),'closed':(80,85,100)}
    L_MARGIN=15; R_MARGIN=15; T_MARGIN=20; CONTENT_W=180

    class CasePDF(FPDF):
        def header(self):
            self.set_fill_color(*C_BG); self.rect(0,0,210,297,'F')
            if self.page_no()>1:
                self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
                self.line(L_MARGIN,12,210-R_MARGIN,12)
                self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
                self.set_xy(L_MARGIN,14); self.cell(CONTENT_W,5,_safe(f'BASTION IDS  |  Case {case_id}  |  CONFIDENTIAL'),align='R'); self.ln(4)
        def footer(self):
            if self.page_no() == 1: return
            self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
            self.line(L_MARGIN,284,210-R_MARGIN,284)
            self.set_y(-13); self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
            self.cell(0,5,_safe(f'Generated {datetime.now().strftime("%Y-%m-%d %H:%M")}  |  Page {self.page_no()}  |  BASTION IDS Incident Case Report'),align='C')

    pdf=CasePDF(); pdf.set_margins(L_MARGIN,T_MARGIN,R_MARGIN); pdf.set_auto_page_break(auto=True,margin=22)
    if is_rtl and _arabic_ok:
        pdf.add_font('Arabic', '', _arabic_font)
        if _arabic_font_bold: pdf.add_font('ArabicB', '', _arabic_font_bold)

    def _font(style='',size=10):
        if is_rtl and _arabic_ok:
            if style == 'B' and _arabic_font_bold: pdf.set_font('ArabicB','',size)
            else: pdf.set_font('Arabic','',size)
        else: pdf.set_font('Helvetica',style,size)

    def section(title,desc=None):
        _a = 'R' if is_rtl else 'L'
        pdf.ln(5); _font('B',13); pdf.set_text_color(*C_NAVY)
        pdf.set_x(L_MARGIN); pdf.cell(CONTENT_W,9,_txt(title),align=_a,new_x='LMARGIN',new_y='NEXT')
        if desc:
            _font('I',9); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.multi_cell(CONTENT_W,5,_txt(desc),align=_a,new_x='LMARGIN',new_y='NEXT')
        pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.5)
        pdf.line(L_MARGIN,pdf.get_y(),L_MARGIN+CONTENT_W,pdf.get_y()); pdf.ln(3)

    def kv(label,value,color=None):
        if is_rtl:
            _font('',10); pdf.set_text_color(*(color if color else C_TXT))
            pdf.set_x(L_MARGIN); pdf.cell(60,7,_txt(str(value)),align='L',new_x='RIGHT',new_y='LAST')
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.cell(CONTENT_W-60,7,_txt(label+':'),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.cell(65,7,_txt(label+':'),new_x='RIGHT',new_y='LAST')
            _font('',10); pdf.set_text_color(*(color if color else C_TXT))
            pdf.cell(0,7,_txt(str(value)),new_x='LMARGIN',new_y='NEXT')

    def th(*cols_widths):
        _a = 'R' if is_rtl else 'L'
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*C_TH_BG); pdf.set_text_color(*C_TH_TXT)
        pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('B',9)
        for col,w in cols_widths: pdf.cell(w,7,_fit(col,w),border=1,fill=True,align=_a)
        pdf.ln()

    def tr(*vals_widths,alt=False):
        _a = 'R' if is_rtl else 'L'
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*(C_ROW_ALT if alt else (255,255,255)))
        pdf.set_text_color(*C_TXT); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('',9)
        for val,w in vals_widths: pdf.cell(w,6,_fit(val,w),border=1,fill=True,align=_a)
        pdf.ln()

    def csv_ref(filename):
        _a = 'R' if is_rtl else 'L'
        pdf.ln(2); pdf.set_fill_color(235,243,255); pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.3)
        pdf.set_x(L_MARGIN); pdf.rect(L_MARGIN,pdf.get_y(),CONTENT_W,8,'FD')
        _font('I',8); pdf.set_text_color(*C_NAVY); pdf.set_x(L_MARGIN+2)
        pdf.cell(CONTENT_W-4,8,_txt(cs('csv ref', filename=filename)),align=_a,new_x='LMARGIN',new_y='NEXT'); pdf.ln(2)

    # ── Cover ──────────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(*C_NAVY); pdf.rect(0,0,210,60,'F')
    pdf.set_y(18); _font('B',34); pdf.set_text_color(255,255,255)
    pdf.cell(0,16,'BASTION IDS',align='C',new_x='LMARGIN',new_y='NEXT')
    _font('',14); pdf.set_text_color(200,215,245)
    pdf.cell(0,8,_txt(cs('case subtitle')),align='C',new_x='LMARGIN',new_y='NEXT')
    pdf.ln(14)
    _font('B',14); pdf.set_text_color(*C_NAVY)
    pdf.set_x(L_MARGIN); pdf.multi_cell(CONTENT_W,8,_txt(case.get('title','')),align='C',new_x='LMARGIN',new_y='NEXT')
    pdf.ln(4)
    meta_y=pdf.get_y()
    pdf.set_fill_color(245,248,254); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.4)
    pdf.rect(L_MARGIN,meta_y,CONTENT_W,58,'FD'); pdf.set_y(meta_y+5)
    assignees_str=', '.join(get_assignees(case)) or 'Unassigned'
    priority=case.get('priority',''); status=case.get('status','')
    for label,val in [(cs('Case ID'),case_id),(cs('Status'),status.upper()),(cs('Priority'),priority),
                      (cs('Analyst'),case.get('analyst','')),( cs('Assigned To'),assignees_str),
                      (cs('Created'),case.get('created','')[:16].replace('T',' ')),
                      (cs('Generated'),datetime.now().strftime('%Y-%m-%d %H:%M'))]:
        clr=(PRIORITY_COLOR.get(priority,C_TXT) if label==cs('Priority')
             else STATUS_COLOR.get(status,C_TXT) if label==cs('Status') else C_TXT)
        if is_rtl:
            _font('',10); pdf.set_text_color(*clr)
            pdf.set_x(L_MARGIN+5); pdf.cell(60,7,_txt(str(val)),align='L',new_x='RIGHT',new_y='LAST')
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.cell(CONTENT_W-65,7,_txt(label+':'),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN+5); pdf.cell(60,7,_txt(label+':'),align='L',new_x='RIGHT',new_y='LAST')
            _font('',10); pdf.set_text_color(*clr); pdf.cell(0,7,_txt(str(val)),new_x='LMARGIN',new_y='NEXT')

    # ── Page 2: Details ────────────────────────────────────────────────────────
    pdf.add_page()
    section(cs('s1'))
    if case.get('description'):
        _font('',10); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN)
        pdf.multi_cell(CONTENT_W,5,_txt(case['description']),align='R' if is_rtl else 'L',new_x='LMARGIN',new_y='NEXT'); pdf.ln(3)

    csv_fname = f'bastion_case_{case_id}.csv'
    if linked_scans:
        section(cs('s2'), cs('s2 desc', n=len(linked_scans)))
        SHOW=10
        th((cs('Scan ID'),38),(cs('Date'),24),(cs('File'),68),(cs('Flows'),25),(cs('Threats'),25))
        for i,h in enumerate(linked_scans[:SHOW]):
            tr((h.get('scan_id','')[:16],38),(h.get('timestamp','')[:10],24),(h.get('filename',''),68),
               (f"{h.get('total_flows',0):,}",25),(str(h.get('malicious_flows',0)),25),alt=(i%2==1))
        if len(linked_scans)>SHOW: csv_ref(csv_fname)

    if case.get('notes'):
        section(cs('s3'))
        for note in case['notes']:
            ts=note.get('ts','')[:16].replace('T',' '); user=note.get('user','')
            pdf.set_fill_color(235,243,255); pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.2)
            pdf.set_x(L_MARGIN); pdf.rect(L_MARGIN,pdf.get_y(),CONTENT_W,6,'FD')
            _font('B',9); pdf.set_text_color(*C_NAVY); pdf.set_x(L_MARGIN+2)
            pdf.cell(CONTENT_W-4,6,_txt(f'[{ts}]  {user}'),new_x='LMARGIN',new_y='NEXT')
            _font('',9); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN+4)
            pdf.multi_cell(CONTENT_W-8,5,_txt(note.get('text','')),new_x='LMARGIN',new_y='NEXT'); pdf.ln(2)

    # ── Companion CSV ──────────────────────────────────────────────────────────
    csv_buf=io.StringIO(); writer=csv.writer(csv_buf)
    writer.writerow(['=== LINKED SCANS FULL DETAILS ==='])
    writer.writerow(['Scan ID','Timestamp','Filename','Total Flows','Malicious Flows','Benign Flows','Detection Rate','Avg Confidence'])
    for h in linked_scans:
        tf=h.get('total_flows',0); mal=h.get('malicious_flows',0)
        rate=f"{round(mal/tf*100,1)}%" if tf else '0%'
        writer.writerow([h.get('scan_id',''),h.get('timestamp',''),_csv_safe(h.get('filename','')),
                         tf,mal,h.get('benign_flows',0),rate,h.get('avg_confidence',0)])
    writer.writerow([])
    writer.writerow(['=== CASE TIMELINE ==='])
    writer.writerow(['Timestamp','User','Comment'])
    for note in case.get('notes',[]):
        writer.writerow([note.get('ts',''),_csv_safe(note.get('user','')),_csv_safe(note.get('text',''))])

    pdf_fname=f'bastion_case_{case_id}.pdf'; zip_fname=f'bastion_case_{case_id}.zip'
    zip_buf=io.BytesIO()
    with zipfile.ZipFile(zip_buf,'w',zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(pdf_fname, bytes(pdf.output()))
        zf.writestr(csv_fname, csv_buf.getvalue())
    zip_buf.seek(0)
    return send_file(zip_buf, as_attachment=True,
                     download_name=_safe(zip_fname),
                     mimetype='application/zip')

# ── Activity Log ───────────────────────────────────────────────────────────────
@app.route('/activity')
@login_required
def activity_log():
    me = session.get('user', '')
    roles = get_roles()
    role = roles.get(me, 'analyst')
    log = []
    with _AUDIT_LOCK:
        if AUDIT_PATH.exists():
            try:
                with open(AUDIT_PATH) as f:
                    log = json.load(f)
            except (json.JSONDecodeError, OSError):
                log = []
    log.reverse()
    # Filter by role: analysts see only their own activity
    if role == 'analyst':
        log = [e for e in log if e.get('user') == me]
    elif role == 'cc_admin':
        config = get_config()
        managed = {u for u, mgr in config.get('managed_by', {}).items() if mgr == me}
        managed.add(me)
        log = [e for e in log if e.get('user') in managed]
    triage_kw = {'triage', 'triage_bulk', 'auto_triage'}
    stats = {
        'scan_count':    sum(1 for e in log if e.get('action') == 'scan_complete'),
        'login_count':   sum(1 for e in log if e.get('action') in ('login','logout')),
        'triage_count':  sum(1 for e in log if e.get('action') in triage_kw),
        'alert_count':   sum(1 for e in log if 'alert' in (e.get('action') or '')),
        'total':         len(log),
    }
    return render_template('activity.html', log=log, stats=stats)

# ── Global Correlation ─────────────────────────────────────────────────────────
@app.route('/analysis/correlation')
@login_required
def global_correlation():
    history = load_user_history()
    grouped = {}
    for scan_entry in history:
        scan_id = scan_entry.get('scan_id','')
        fp = Path(scan_entry.get('flows_file') or '')
        if not fp.exists(): continue
        try:
            df = pd.read_csv(fp)
            df.columns = df.columns.str.strip()
            label_col = next((c for c in df.columns if c.lower()=='label'), None)
            if not label_col: continue
            meta = find_meta_cols(df)
            src_col = meta.get('src_ip')
            mal = df[df[label_col].astype(str).str.upper()!='BENIGN'].copy()
            if mal.empty: continue
            src_series = mal[src_col].astype(str) if src_col and src_col in mal.columns else pd.Series(['N/A']*len(mal))
            for (src,label),grp in mal.groupby([src_series,label_col]):
                src=str(src); label=str(label)
                if src not in grouped:
                    grouped[src]={'src_ip':src,'attack_types':set(),'flow_count':0,'scan_ids':set(),'max_severity_rank':0,'max_severity':'SAFE'}
                grouped[src]['attack_types'].add(label)
                grouped[src]['flow_count']+=len(grp)
                grouped[src]['scan_ids'].add(scan_id)
                sev,_,rank=get_severity(label)
                if rank>grouped[src]['max_severity_rank']:
                    grouped[src]['max_severity_rank']=rank; grouped[src]['max_severity']=sev
        except Exception:
            app.logger.exception('Error processing scan data in correlation')
    corr_list=[]
    for ip,g in grouped.items():
        corr_list.append({'src_ip':ip,'attack_types':list(g['attack_types']),'flow_count':g['flow_count'],'scan_count':len(g['scan_ids']),'max_severity':g['max_severity'],'threat_score':g['flow_count']*g['max_severity_rank']})
    corr_list.sort(key=lambda x:x['threat_score'],reverse=True)
    return render_template('global_correlation.html', correlations=corr_list[:200])

# ── Dashboard Map ──────────────────────────────────────────────────────────────
@app.route('/dashboard/map')
@login_required
def dashboard_map():
    return render_template('dashboard_map.html')

@app.route('/api/dashboard/geo')
@login_required
def api_dashboard_geo():
    history = load_user_history()
    ip_info = {}   # all IPs (public + private)
    for scan_entry in history[:20]:
        fp = Path(scan_entry.get('flows_file') or '')
        if not fp.exists(): continue
        try:
            df = pd.read_csv(fp, usecols=lambda c: c.strip().lower() in {'src_ip','source ip','srcip','dst_ip','destination ip','dstip','label'})
            df.columns = df.columns.str.strip()
            label_col = next((c for c in df.columns if c.lower() == 'label'), None)
            ip_cols = [c for c in df.columns if c.lower() in ('src_ip','source ip','srcip','dst_ip','destination ip','dstip')]
            mal_mask = df[label_col].astype(str).str.upper() != 'BENIGN' if label_col else pd.Series(False, index=df.index)
            # collect per-IP attack labels
            labels_for_ip = {}
            if label_col:
                mal_df = df[mal_mask]
                for col in ip_cols:
                    for ip, grp in mal_df.groupby(mal_df[col].astype(str).str.strip()):
                        if ip and ip not in ('N/A', 'nan', 'none', 'None', 'NaN'):
                            if ip not in labels_for_ip: labels_for_ip[ip] = set()
                            labels_for_ip[ip].update(grp[label_col].astype(str).str.strip().tolist())
            for col in ip_cols:
                for is_mal, grp in df.groupby(mal_mask):
                    for ip, cnt in grp[col].dropna().astype(str).str.strip().value_counts().items():
                        if ip and ip not in ('N/A', 'nan', 'none', 'None', 'NaN'):
                            if ip not in ip_info:
                                ip_info[ip] = {'count':0,'is_malicious':False,'is_private':is_private_ip(ip),'labels':set()}
                            ip_info[ip]['count'] += int(cnt)
                            if is_mal:
                                ip_info[ip]['is_malicious'] = True
                                ip_info[ip]['labels'].update(labels_for_ip.get(ip,set()))
        except Exception:
            app.logger.exception('Error processing scan data in dashboard geo')

    # build table data (all IPs, sorted by count)
    table_rows = sorted(
        [{'ip':ip,'count':d['count'],'is_malicious':d['is_malicious'],
          'is_private':d['is_private'],
          'labels':list(d['labels'])[:3]}
         for ip,d in ip_info.items()],
        key=lambda x: x['count'], reverse=True
    )[:200]

    # geo-locate public IPs only
    pub_ips = [ip for ip,d in ip_info.items() if not d['is_private']][:100]
    geo_results = []
    if pub_ips:
        try:
            resp = req_lib.post('http://ip-api.com/batch',
                json=[{'query':ip,'fields':'status,country,lat,lon,query'} for ip in pub_ips],
                timeout=15)
            for item in resp.json():
                if item.get('status') == 'success':
                    ip = item['query']
                    geo_results.append({
                        'ip':ip,'lat':item.get('lat',0),'lon':item.get('lon',0),
                        'country':item.get('country','Unknown'),
                        'count':ip_info.get(ip,{}).get('count',0),
                        'is_malicious':ip_info.get(ip,{}).get('is_malicious',False)
                    })
        except Exception:
            app.logger.exception('Error geo-locating IPs via ip-api.com batch')

    return jsonify({'geo': geo_results, 'table': table_rows})

@app.route('/api/trend')
@login_required
def api_trend():
    period = request.args.get('period','week')
    if period not in ('week', 'month'):
        period = 'week'
    history = load_user_history()
    now = datetime.now()
    buckets = {}
    for h in history:
        try:
            ts = datetime.fromisoformat(h.get('timestamp',''))
        except Exception: continue
        if period == 'week':
            delta = (now - ts).days
            if delta > 7: continue
            key = ts.strftime('%a')
        else:
            delta = (now - ts).days
            if delta > 30: continue
            key = ts.strftime('%b %d')
        if key not in buckets: buckets[key] = {'threats':0,'scans':0}
        buckets[key]['threats'] += h.get('malicious_flows',0) or 0
        buckets[key]['scans']   += 1
    result = [{'date': k, 'threats': v['threats'], 'scans': v['scans']} for k, v in buckets.items()]
    # Sort chronologically so the frontend chart renders in correct order
    if period == 'week':
        _day_order = {'Mon':0,'Tue':1,'Wed':2,'Thu':3,'Fri':4,'Sat':5,'Sun':6}
        result.sort(key=lambda x: _day_order.get(x['date'], 99))
    else:
        try:
            result.sort(key=lambda x: datetime.strptime(x['date'], '%b %d').replace(year=now.year))
        except (ValueError, TypeError):
            pass
    return jsonify(result)

@app.route('/api/dashboard/live')
@login_required
def api_dashboard_live():
    me   = session.get('user', '')
    role = get_roles().get(me, 'analyst')
    def generate():
        try:
            while True:
                try:
                    h = load_user_history()
                    payload = json.dumps({'total_scans':len(h),'total_flows':sum(x.get('total_flows',0) or 0 for x in h),'total_threats':sum(x.get('malicious_flows',0) or 0 for x in h),'unread_count':get_unread_count(role)})
                    yield f"data: {payload}\n\n"
                except Exception:
                    yield 'data: {"total_scans":0,"total_flows":0,"total_threats":0,"unread_count":0}\n\n'
                time.sleep(5)
        except GeneratorExit:
            pass
    return Response(stream_with_context(generate()), mimetype='text/event-stream', headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

# ── Threat Feed API ─────────────────────────────────────────────────────────────
@app.route('/api/threat/feed')
@login_required
def api_threat_feed():
    """Return latest threat detections for the live ticker."""
    history = load_user_history()
    feed = []
    for h in history[:20]:  # last 20 scans
        ts_raw = h.get('timestamp', '')
        try:
            ts_obj = datetime.fromisoformat(ts_raw)
            ts_str = ts_obj.strftime('%H:%M')
        except Exception:
            ts_str = ts_raw[:16].replace('T', ' ')
        sev_bd = h.get('severity_breakdown', {})
        top_sev = 'SAFE'
        if sev_bd.get('CRITICAL', 0) > 0:
            top_sev = 'CRITICAL'
        elif sev_bd.get('HIGH', 0) > 0:
            top_sev = 'HIGH'
        elif sev_bd.get('MEDIUM', 0) > 0:
            top_sev = 'MEDIUM'
        threats = h.get('malicious_flows', 0) or 0
        if threats == 0:
            continue
        threat_bd = h.get('threat_breakdown', {})
        # Filter out Benign from threat breakdown
        real_threats = {k: v for k, v in threat_bd.items() if 'benign' not in k.lower()}
        if not real_threats:
            continue
        top_attack = max(real_threats, key=lambda k: real_threats[k])
        src_ip = h.get('top_src_ip', h.get('filename', 'Unknown'))
        feed.append({
            'time': ts_str,
            'src': src_ip[:15] if len(src_ip) > 15 else src_ip,
            'attack': top_attack,
            'severity': top_sev,
            'count': threats,
        })
    return jsonify(feed[:15])

# ── Attack Map API ──────────────────────────────────────────────────────────────
@app.route('/api/attack/map')
@login_required
def api_attack_map():
    """Return country → count by geo-locating public IPs from scan flows."""
    country_counts = {}
    cache = load_ip_cache()

    # 1. Pull countries already cached from AbuseIPDB / ipinfo / whois lookups
    for key, val in cache.items():
        if key.startswith('vt_') or key.startswith('shodan_'):
            continue
        country = val.get('country', '') or val.get('countryCode', '')
        if country and country not in ('', 'N/A', 'Unknown', 'Private'):
            country_counts[country] = country_counts.get(country, 0) + max(1, val.get('totalReports', 1))

    # 2. Collect unique public IPs from recent flow CSVs (up to 5 scans)
    history = load_user_history()
    public_ips = set()
    for h in history[:5]:
        flows_path = Path(h.get('flows_file') or '')
        if not flows_path.exists():
            continue
        try:
            df = pd.read_csv(flows_path, usecols=lambda c: c in ('src_ip','dst_ip'), nrows=5000)
            for col in ('src_ip', 'dst_ip'):
                if col in df.columns:
                    for ip in df[col].dropna().unique():
                        try:
                            if not is_private_ip(str(ip)):
                                public_ips.add(str(ip))
                        except Exception:
                            pass
        except Exception:
            pass

    # 3. Geo-locate uncached public IPs via ipinfo.io (free, no key needed)
    now = datetime.now()
    new_cache_entries = {}   # collect new lookups; save atomically at the end
    for ip in list(public_ips)[:30]:  # limit to 30 lookups per request
        if ip in cache:
            cached = cache[ip]
            try:
                cached_at = datetime.fromisoformat(cached.get('cached_at', '2000-01-01'))
            except (ValueError, TypeError):
                cached_at = datetime(2000, 1, 1)
            if now - cached_at < timedelta(hours=24):
                country = cached.get('country', '')
                if country and country not in ('', 'N/A', 'Unknown', 'Private'):
                    country_counts[country] = country_counts.get(country, 0) + 1
                continue
        try:
            r = req_lib.get(f'https://ipinfo.io/{ip}/json', timeout=3)
            if r.status_code == 200:
                d = r.json()
                if d.get('bogon'):
                    continue
                country = d.get('country', '')
                if country:
                    country_counts[country] = country_counts.get(country, 0) + 1
                    new_cache_entries[ip] = {
                        'ip': ip, 'country': country,
                        'org': d.get('org', ''), 'city': d.get('city', ''),
                        'cached_at': now.isoformat()
                    }
        except Exception:
            pass

    if new_cache_entries:
        with _IP_CACHE_LOCK:
            fresh_cache = load_ip_cache()
            fresh_cache.update(new_cache_entries)
            save_ip_cache(fresh_cache)

    return jsonify(country_counts)

# ── Heatmap API ─────────────────────────────────────────────────────────────────
@app.route('/api/heatmap')
@login_required
def api_heatmap():
    """Return 7×24 grid of attack frequency by day-of-week × hour."""
    history = load_user_history()
    # grid[day][hour] where day 0=Mon, 6=Sun
    grid = [[0] * 24 for _ in range(7)]
    for h in history:
        ts_raw = h.get('timestamp', '')
        try:
            ts_obj = datetime.fromisoformat(ts_raw)
        except Exception:
            continue
        day = ts_obj.weekday()   # 0=Mon … 6=Sun
        hour = ts_obj.hour
        threats = h.get('malicious_flows', 0) or 0
        grid[day][hour] += threats
    return jsonify(grid)

# ── Dashboard PDF Export ───────────────────────────────────────────────────────
@app.route('/dashboard/export/pdf')
@login_required
def dashboard_export_pdf():
    history = load_user_history()
    total_scans   = len(history)
    total_flows   = sum(h.get('total_flows',0) or 0 for h in history)
    total_threats = sum(h.get('malicious_flows',0) or 0 for h in history)
    detect_rate   = round(total_threats / total_flows * 100, 1) if total_flows else 0
    threat_counts = {}
    sev_totals = {'SAFE':0,'MEDIUM':0,'HIGH':0,'CRITICAL':0,'UNKNOWN':0}
    for h in history:
        for tk,c in h.get('threat_breakdown',{}).items(): threat_counts[tk]=threat_counts.get(tk,0)+c
        for sv,c in h.get('severity_breakdown',{}).items():
            if sv in sev_totals: sev_totals[sv]+=c
    try:
        from fpdf import FPDF
    except ImportError:
        flash(t('flash fpdf2 missing'), 'error'); return redirect(url_for('dashboard'))

    def _safe(s):
        v=str(s).replace('\u2014','-').replace('\u2013','-').replace('\u2019',"'").replace('\u2018',"'").replace('\ufffd','?')
        return v.encode('latin-1',errors='replace').decode('latin-1')

    # ── Arabic support ─────────────────────────────────────────────────────────
    lang = session.get('lang', cfg('language', 'en'))
    is_rtl = lang == 'ar'
    _arabic_ok = False; _arabic_font = None; _arabic_font_bold = None
    if is_rtl:
        try:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Regular.ttf',
                        BASE_DIR / 'static/fonts/Amiri-Regular.ttf',
                        Path('C:/Windows/Fonts/Arial.ttf')]:
                if _fp.exists(): _arabic_font = str(_fp); _arabic_ok = True; break
            for _fp in [BASE_DIR / 'static/fonts/NotoNaskhArabic-Bold.ttf',
                        BASE_DIR / 'static/fonts/NotoNaskhArabic-SemiBold.ttf']:
                if _fp.exists(): _arabic_font_bold = str(_fp); break
        except ImportError:
            pass

    def _txt(s):
        v = str(s)
        if is_rtl and _arabic_ok:
            import arabic_reshaper
            from bidi.algorithm import get_display as bidi_display
            return bidi_display(arabic_reshaper.reshape(v))
        return _safe(v)

    def _fit(text,w):
        maxc=max(1,int(w/1.9))
        s = _txt(str(text)) if (is_rtl and _arabic_ok) else _safe(str(text))
        return (s[:maxc-2]+'..') if len(s)>maxc else s

    _DS = {
        'en': {
            'dash sub1': 'Security Operations Center',
            'dash sub2': 'Dashboard Summary Report',
            'Total Scans': 'Total Scans', 'Total Flows': 'Total Flows',
            'Threats': 'Threats', 'Detection Rate': 'Detection Rate',
            'tile sub scans': 'CSV files analyzed', 'tile sub flows': 'Network connections',
            'tile sub threats': 'Malicious flows', 'tile sub rate': '% malicious',
            'Analyst': 'Analyst', 'Generated': 'Generated',
            's1 title': 'Section 1 \u2014 Overall Statistics',
            's1 desc': 'Aggregated metrics across all scans.',
            'Total Scans kv': 'Total Scans', 'Total Flows Analyzed': 'Total Flows Analyzed',
            'Total Malicious Flows': 'Total Malicious Flows', 'Total Benign Flows': 'Total Benign Flows',
            'Detection Rate kv': 'Detection Rate', 'Unique Attack Types': 'Unique Attack Types',
            'Traffic Severity Breakdown': 'Traffic Severity Breakdown',
            'Severity': 'Severity', 'Flow Count': 'Flow Count',
            'Percentage': 'Percentage', 'Meaning': 'Meaning',
            'Attack Type Breakdown': 'Attack Type Breakdown',
            'atk bd desc': 'Top 10 attack categories. Full breakdown in companion CSV.',
            'Attack Type': 'Attack Type', '% Threats': '% Threats',
            'Description': 'Description',
            's2 title': 'Section 2 \u2014 Scan History',
            's2 desc': '{n} total scans. Showing first 15. Full history in companion CSV.',
            'Date': 'Date', 'Scan ID': 'Scan ID', 'File': 'File',
            'Flows': 'Flows', 'Rate': 'Rate',
            's3 title': 'Section 3 \u2014 Security Recommendations',
            's3 desc': 'Actionable guidance based on detected threats.',
            'csv ref': 'Full data available in companion file: {filename}',
            'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'SAFE': 'SAFE', 'UNKNOWN': 'UNKNOWN',
            'sev_exp_CRITICAL': 'Confirmed attack requiring immediate action.',
            'sev_exp_HIGH': 'Active attack, urgent investigation needed.',
            'sev_exp_MEDIUM': 'Suspicious activity to investigate.',
            'sev_exp_SAFE': 'Normal benign traffic.',
            'sev_exp_UNKNOWN': 'Unclassified, manual review needed.',
            'rec_crit_title': 'Address Critical Threats',
            'rec_crit_body': '{n:,} critical flows. Block attacker IPs immediately and escalate to incident response.',
            'rec_high_title': 'Investigate High-Severity Attacks',
            'rec_high_body': '{n:,} high-severity flows. Review attacker IPs and apply firewall rules urgently.',
            'rec_bot_title': 'Botnet Activity Detected',
            'rec_bot_body': '{n:,} bot flows. Isolate suspected hosts, run malware scans, and check for C2 beaconing.',
            'rec_brute_title': 'Brute Force Attacks Active',
            'rec_brute_body': 'Enable account lockout policies. Add rate limiting on SSH, FTP, and web login endpoints. Deploy fail2ban.',
            'rec_dos_title': 'DoS/DDoS Traffic Detected',
            'rec_dos_body': 'Enable DDoS mitigation at the network edge. Apply connection rate limits. Contact ISP for upstream filtering if severe.',
            'rec_sqli_title': 'SQL Injection Attempts Detected',
            'rec_sqli_body': 'Use parameterized queries in all database code. Deploy a WAF. Audit web application code for injection vulnerabilities.',
            'rec_xss_title': 'XSS Attacks Detected',
            'rec_xss_body': 'Sanitize and encode all user-supplied HTML output. Implement a strict Content Security Policy header.',
            'rec_safe_title': 'No Critical Threats',
            'rec_safe_body': 'No critical threats detected in current scan history. Continue regular monitoring.',
        },
        'ar': {
            'dash sub1': '\u0645\u0631\u0643\u0632 \u0627\u0644\u0639\u0645\u0644\u064a\u0627\u062a \u0627\u0644\u0623\u0645\u0646\u064a\u0629',
            'dash sub2': '\u062a\u0642\u0631\u064a\u0631 \u0645\u0644\u062e\u0635 \u0644\u0648\u062d\u0629 \u0627\u0644\u062a\u062d\u0643\u0645',
            'Total Scans': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u0641\u062d\u0648\u0635\u0627\u062a',
            'Total Flows': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a',
            'Threats': '\u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a',
            'Detection Rate': '\u0645\u0639\u062f\u0644 \u0627\u0644\u0643\u0634\u0641',
            'tile sub scans': '\u0645\u0644\u0641\u0627\u062a CSV \u0645\u062d\u0644\u0644\u0629',
            'tile sub flows': '\u0627\u062a\u0635\u0627\u0644\u0627\u062a \u0627\u0644\u0634\u0628\u0643\u0629',
            'tile sub threats': '\u062a\u062f\u0641\u0642\u0627\u062a \u0636\u0627\u0631\u0629',
            'tile sub rate': '% \u0636\u0627\u0631',
            'Analyst': '\u0627\u0644\u0645\u062d\u0644\u0644', 'Generated': '\u062a\u0627\u0631\u064a\u062e \u0627\u0644\u0625\u0646\u0634\u0627\u0621',
            's1 title': '\u0627\u0644\u0642\u0633\u0645 \u0627\u0644\u0623\u0648\u0644 \u2014 \u0625\u062d\u0635\u0627\u0621\u0627\u062a \u0639\u0627\u0645\u0629',
            's1 desc': '\u0645\u0642\u0627\u064a\u064a\u0633 \u0645\u062c\u0645\u0639\u0629 \u0639\u0628\u0631 \u062c\u0645\u064a\u0639 \u0627\u0644\u0641\u062d\u0648\u0635\u0627\u062a.',
            'Total Scans kv': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u0641\u062d\u0648\u0635\u0627\u062a',
            'Total Flows Analyzed': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u0645\u062d\u0644\u0644\u0629',
            'Total Malicious Flows': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u0636\u0627\u0631\u0629',
            'Total Benign Flows': '\u0625\u062c\u0645\u0627\u0644\u064a \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a \u0627\u0644\u062d\u0645\u064a\u062f\u0629',
            'Detection Rate kv': '\u0645\u0639\u062f\u0644 \u0627\u0644\u0643\u0634\u0641',
            'Unique Attack Types': '\u0623\u0646\u0648\u0627\u0639 \u0627\u0644\u0647\u062c\u0645\u0627\u062a \u0627\u0644\u0641\u0631\u064a\u062f\u0629',
            'Traffic Severity Breakdown': '\u062a\u0648\u0632\u064a\u0639 \u062e\u0637\u0648\u0631\u0629 \u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631',
            'Severity': '\u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u062e\u0637\u0648\u0631\u0629',
            'Flow Count': '\u0639\u062f\u062f \u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a',
            'Percentage': '\u0627\u0644\u0646\u0633\u0628\u0629 \u0627\u0644\u0645\u0626\u0648\u064a\u0629',
            'Meaning': '\u0627\u0644\u0645\u0639\u0646\u0649',
            'Attack Type Breakdown': '\u062a\u0641\u0635\u064a\u0644 \u0623\u0646\u0648\u0627\u0639 \u0627\u0644\u0647\u062c\u0645\u0627\u062a',
            'atk bd desc': '\u0623\u0639\u0644\u0649 10 \u0641\u0626\u0627\u062a \u0647\u062c\u0645\u0627\u062a. \u0627\u0644\u062a\u0641\u0627\u0635\u064a\u0644 \u0641\u064a \u0645\u0644\u0641 CSV \u0627\u0644\u0645\u0631\u0641\u0642.',
            'Attack Type': '\u0646\u0648\u0639 \u0627\u0644\u0647\u062c\u0648\u0645', '% Threats': '% \u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a',
            'Description': '\u0627\u0644\u0648\u0635\u0641',
            's2 title': '\u0627\u0644\u0642\u0633\u0645 \u0627\u0644\u062b\u0627\u0646\u064a \u2014 \u0633\u062c\u0644 \u0627\u0644\u0641\u062d\u0648\u0635\u0627\u062a',
            's2 desc': '{n} \u0625\u062c\u0645\u0627\u0644\u064a \u0641\u062d\u0648\u0635\u0627\u062a. \u0639\u0631\u0636 \u0623\u0648\u0644 15. \u0627\u0644\u0633\u062c\u0644 \u0627\u0644\u0643\u0627\u0645\u0644 \u0641\u064a \u0645\u0644\u0641 CSV \u0627\u0644\u0645\u0631\u0641\u0642.',
            'Date': '\u0627\u0644\u062a\u0627\u0631\u064a\u062e', 'Scan ID': '\u0645\u0639\u0631\u0641 \u0627\u0644\u0641\u062d\u0635',
            'File': '\u0627\u0644\u0645\u0644\u0641', 'Flows': '\u0627\u0644\u062a\u062f\u0641\u0642\u0627\u062a', 'Rate': '\u0627\u0644\u0645\u0639\u062f\u0644',
            's3 title': '\u0627\u0644\u0642\u0633\u0645 \u0627\u0644\u062b\u0627\u0644\u062b \u2014 \u062a\u0648\u0635\u064a\u0627\u062a \u0623\u0645\u0646\u064a\u0629',
            's3 desc': '\u062a\u0648\u062c\u064a\u0647\u0627\u062a \u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u062a\u0646\u0641\u064a\u0630 \u0628\u0646\u0627\u0621\u064b \u0639\u0644\u0649 \u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a \u0627\u0644\u0645\u0643\u062a\u0634\u0641\u0629.',
            'csv ref': '\u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0643\u0627\u0645\u0644\u0629 \u0645\u062a\u0627\u062d\u0629 \u0641\u064a \u0627\u0644\u0645\u0644\u0641 \u0627\u0644\u0645\u0631\u0641\u0642: {filename}',
            'CRITICAL': '\u062d\u0631\u062c', 'HIGH': '\u0639\u0627\u0644\u0650', 'MEDIUM': '\u0645\u062a\u0648\u0633\u0637', 'SAFE': '\u0622\u0645\u0646', 'UNKNOWN': '\u063a\u064a\u0631 \u0645\u0639\u0631\u0648\u0641',
            'sev_exp_CRITICAL': '\u0647\u062c\u0648\u0645 \u0645\u0624\u0643\u062f \u064a\u0633\u062a\u062f\u0639\u064a \u062a\u062f\u062e\u0644\u0627\u064b \u0641\u0648\u0631\u064a\u0627\u064b.',
            'sev_exp_HIGH': '\u0647\u062c\u0648\u0645 \u0646\u0634\u0637\u060c \u064a\u0633\u062a\u0648\u062c\u0628 \u0627\u0644\u062a\u062d\u0642\u064a\u0642 \u0627\u0644\u0639\u0627\u062c\u0644.',
            'sev_exp_MEDIUM': '\u0646\u0634\u0627\u0637 \u0645\u0634\u0628\u0648\u0647 \u064a\u0633\u062a\u062d\u0642 \u0627\u0644\u062a\u062d\u0642\u064a\u0642.',
            'sev_exp_SAFE': '\u062d\u0631\u0643\u0629 \u0645\u0631\u0648\u0631 \u0637\u0628\u064a\u0639\u064a\u0629 \u062d\u0645\u064a\u062f\u0629.',
            'sev_exp_UNKNOWN': '\u063a\u064a\u0631 \u0645\u0635\u0646\u0641\u060c \u064a\u062a\u0637\u0644\u0628 \u0645\u0631\u0627\u062c\u0639\u0629 \u064a\u062f\u0648\u064a\u0629.',
            'rec_crit_title': '\u0645\u0639\u0627\u0644\u062c\u0629 \u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a \u0627\u0644\u062d\u0631\u062c\u0629',
            'rec_crit_body': '{n:,} \u062a\u062f\u0641\u0642 \u062d\u0631\u062c. \u0627\u062d\u062c\u0628 \u0639\u0646\u0627\u0648\u064a\u0646 IP \u0627\u0644\u0645\u0647\u0627\u062c\u0645\u064a\u0646 \u0641\u0648\u0631\u0627\u064b \u0648\u0635\u0639\u0651\u062f \u0627\u0644\u0623\u0645\u0631 \u0644\u0641\u0631\u064a\u0642 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b.',
            'rec_high_title': '\u0627\u0644\u062a\u062d\u0642\u064a\u0642 \u0641\u064a \u0647\u062c\u0645\u0627\u062a \u0639\u0627\u0644\u064a\u0629 \u0627\u0644\u062e\u0637\u0648\u0631\u0629',
            'rec_high_body': '{n:,} \u062a\u062f\u0641\u0642 \u0639\u0627\u0644\u064a \u0627\u0644\u062e\u0637\u0648\u0631\u0629. \u0631\u0627\u062c\u0639 \u0639\u0646\u0627\u0648\u064a\u0646 IP \u0648\u0637\u0628\u0642 \u0642\u0648\u0627\u0639\u062f \u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629 \u0639\u0627\u062c\u0644\u0627\u064b.',
            'rec_bot_title': '\u0646\u0634\u0627\u0637 \u0634\u0628\u0643\u0629 \u0628\u0648\u062a\u0646\u062a \u0645\u0643\u062a\u0634\u0641',
            'rec_bot_body': '{n:,} \u062a\u062f\u0641\u0642 \u0628\u0648\u062a. \u0639\u0632\u0644 \u0627\u0644\u0623\u062c\u0647\u0632\u0629 \u0627\u0644\u0645\u0634\u062a\u0628\u0647 \u0628\u0647\u0627 \u0648\u0641\u062d\u0635\u0647\u0627 \u0628\u062d\u062b\u0627\u064b \u0639\u0646 \u0628\u0631\u0627\u0645\u062c \u062e\u0628\u064a\u062b\u0629 \u0648\u062a\u062d\u0642\u0642 \u0645\u0646 \u062d\u0631\u0643\u0629 C2.',
            'rec_brute_title': '\u0647\u062c\u0645\u0627\u062a \u0627\u0644\u0642\u0648\u0629 \u0627\u0644\u063a\u0627\u0634\u0645\u0629 \u0646\u0634\u0637\u0629',
            'rec_brute_body': '\u0641\u0639\u0651\u0644 \u0633\u064a\u0627\u0633\u0627\u062a \u0642\u0641\u0644 \u0627\u0644\u062d\u0633\u0627\u0628. \u0623\u0636\u0641 \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0645\u0639\u062f\u0644 \u0639\u0644\u0649 SSH \u0648FTP \u0648\u0646\u0642\u0627\u0637 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644. \u0627\u0646\u0634\u0631 fail2ban.',
            'rec_dos_title': '\u062a\u0645 \u0643\u0634\u0641 \u062d\u0631\u0643\u0629 DoS/DDoS',
            'rec_dos_body': '\u0641\u0639\u0651\u0644 \u062a\u062e\u0641\u064a\u0641 DDoS \u0639\u0644\u0649 \u062d\u0627\u0641\u0629 \u0627\u0644\u0634\u0628\u0643\u0629. \u0637\u0628\u0642 \u062d\u062f\u0648\u062f \u0645\u0639\u062f\u0644 \u0627\u0644\u0627\u062a\u0635\u0627\u0644. \u062a\u0648\u0627\u0635\u0644 \u0645\u0639 \u0645\u0632\u0648\u062f \u0627\u0644\u0625\u0646\u062a\u0631\u0646\u062a \u0639\u0646\u062f \u0627\u0644\u062d\u0627\u062c\u0629.',
            'rec_sqli_title': '\u0645\u062d\u0627\u0648\u0644\u0627\u062a \u062d\u0642\u0646 SQL \u0645\u0643\u062a\u0634\u0641\u0629',
            'rec_sqli_body': '\u0627\u0633\u062a\u062e\u062f\u0645 \u0627\u0644\u0627\u0633\u062a\u0639\u0644\u0627\u0645\u0627\u062a \u0627\u0644\u0645\u0639\u0644\u0645\u0629. \u0627\u0646\u0634\u0631 WAF. \u0627\u0641\u062d\u0635 \u0643\u0648\u062f \u062a\u0637\u0628\u064a\u0642 \u0627\u0644\u0648\u064a\u0628 \u0628\u062d\u062b\u0627\u064b \u0639\u0646 \u062b\u063a\u0631\u0627\u062a \u0627\u0644\u062d\u0642\u0646.',
            'rec_xss_title': '\u0647\u062c\u0645\u0627\u062a XSS \u0645\u0643\u062a\u0634\u0641\u0629',
            'rec_xss_body': '\u0639\u0642\u0651\u0645 \u0648\u0631\u0645\u0651\u0632 \u062c\u0645\u064a\u0639 \u0645\u062f\u062e\u0644\u0627\u062a HTML \u0644\u0644\u0645\u0633\u062a\u062e\u062f\u0645. \u0637\u0628\u0642 \u0633\u064a\u0627\u0633\u0629 \u0623\u0645\u0627\u0646 \u0627\u0644\u0645\u062d\u062a\u0648\u0649 (CSP) \u0627\u0644\u0635\u0627\u0631\u0645\u0629.',
            'rec_safe_title': '\u0644\u0627 \u062a\u0647\u062f\u064a\u062f\u0627\u062a \u062d\u0631\u062c\u0629',
            'rec_safe_body': '\u0644\u0645 \u062a\u064f\u0643\u062a\u0634\u0641 \u062a\u0647\u062f\u064a\u062f\u0627\u062a \u062d\u0631\u062c\u0629 \u0641\u064a \u0633\u062c\u0644 \u0627\u0644\u0641\u062d\u0648\u0635\u0627\u062a \u0627\u0644\u062d\u0627\u0644\u064a. \u0648\u0627\u0635\u0644 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629 \u0628\u0627\u0646\u062a\u0638\u0627\u0645.',
        }
    }
    def ds(key, **kwargs):
        s = _DS.get(lang, _DS['en']).get(key, _DS['en'].get(key, key))
        return s.format(**kwargs) if kwargs else s

    ATTACK_EXPLAIN={'PortScan':'Systematic probing of network ports to map open services.','DoS Hulk':'HTTP flood attack overwhelming web servers.','DoS GoldenEye':'Layer-7 DoS exploiting keep-alive connections.','DoS slowloris':'Slow HTTP attack exhausting server connections.','DoS Slowhttptest':'Slow HTTP attack testing server limits.','DDoS':'Distributed flood from multiple coordinated sources.','FTP-Patator':'Automated brute-force against FTP logins.','SSH-Patator':'Automated brute-force against SSH logins.','Bot':'Botnet traffic — compromised host under C2 control.','Heartbleed':'OpenSSL exploit reading sensitive server memory (CVE-2014-0160).','Infiltration':'Confirmed breach of network perimeter.','Web Attack Brute Force':'Automated credential brute-force against web logins.','Web Attack XSS':'Cross-Site Scripting injection attempt.','Web Attack Sql Injection':'SQL injection targeting database queries.'}
    SEV_EXPLAIN = {sev: ds(f'sev_exp_{sev}') for sev in ['CRITICAL','HIGH','MEDIUM','UNKNOWN','SAFE']}

    # ── Light color palette ────────────────────────────────────────────────────
    C_BG=(255,255,255); C_NAVY=(20,50,110); C_ACCENT=(60,120,200)
    C_TXT=(25,35,55); C_MUTED=(100,110,130); C_TH_BG=(210,225,248)
    C_TH_TXT=(15,40,100); C_ROW_ALT=(245,248,254); C_BORDER=(180,195,220); C_FOOTER=(150,160,180)
    SEV_BG={'CRITICAL':(255,232,232),'HIGH':(255,243,222),'MEDIUM':(255,252,218),'SAFE':(228,250,234),'UNKNOWN':(240,242,246)}
    SEV_TXT={'CRITICAL':(170,0,15),'HIGH':(160,70,0),'MEDIUM':(120,90,0),'SAFE':(0,100,40),'UNKNOWN':(80,85,100)}
    SEV_BDR={'CRITICAL':(220,60,60),'HIGH':(220,130,0),'MEDIUM':(200,165,0),'SAFE':(0,160,70),'UNKNOWN':(160,165,180)}
    L_MARGIN=15; R_MARGIN=15; T_MARGIN=20; CONTENT_W=180

    class DashPDF(FPDF):
        def header(self):
            self.set_fill_color(*C_BG); self.rect(0,0,210,297,'F')
            if self.page_no()>1:
                self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
                self.line(L_MARGIN,12,210-R_MARGIN,12)
                self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
                self.set_xy(L_MARGIN,14); self.cell(CONTENT_W,5,_safe('BASTION IDS  |  Dashboard Report  |  CONFIDENTIAL'),align='R'); self.ln(4)
        def footer(self):
            if self.page_no() == 1: return
            self.set_draw_color(*C_ACCENT); self.set_line_width(0.3)
            self.line(L_MARGIN,284,210-R_MARGIN,284)
            self.set_y(-13); self.set_font('Helvetica','I',7); self.set_text_color(*C_FOOTER)
            self.cell(0,5,_safe(f'Generated {datetime.now().strftime("%Y-%m-%d %H:%M")}  |  Page {self.page_no()}  |  BASTION IDS SOC Dashboard'),align='C')

    pdf=DashPDF(); pdf.set_margins(L_MARGIN,T_MARGIN,R_MARGIN); pdf.set_auto_page_break(auto=True,margin=22)
    if is_rtl and _arabic_ok:
        pdf.add_font('Arabic', '', _arabic_font)
        if _arabic_font_bold: pdf.add_font('ArabicB', '', _arabic_font_bold)

    def _font(style='',size=10):
        if is_rtl and _arabic_ok:
            if style == 'B' and _arabic_font_bold: pdf.set_font('ArabicB','',size)
            else: pdf.set_font('Arabic','',size)
        else: pdf.set_font('Helvetica',style,size)

    def section(title,desc=None):
        _a = 'R' if is_rtl else 'L'
        pdf.ln(5); _font('B',13); pdf.set_text_color(*C_NAVY)
        pdf.set_x(L_MARGIN); pdf.cell(CONTENT_W,9,_txt(title),align=_a,new_x='LMARGIN',new_y='NEXT')
        if desc:
            _font('I',9); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.multi_cell(CONTENT_W,5,_txt(desc),align=_a,new_x='LMARGIN',new_y='NEXT')
        pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.5)
        pdf.line(L_MARGIN,pdf.get_y(),L_MARGIN+CONTENT_W,pdf.get_y()); pdf.ln(3)

    def kv(label,value):
        if is_rtl:
            _font('',10); pdf.set_text_color(*C_TXT)
            pdf.set_x(L_MARGIN); pdf.cell(60,7,_txt(str(value)),align='L',new_x='RIGHT',new_y='LAST')
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.cell(CONTENT_W-60,7,_txt(label+':'),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            _font('B',10); pdf.set_text_color(*C_MUTED)
            pdf.set_x(L_MARGIN); pdf.cell(65,7,_txt(label+':'),new_x='RIGHT',new_y='LAST')
            _font('',10); pdf.set_text_color(*C_TXT); pdf.cell(0,7,_txt(str(value)),new_x='LMARGIN',new_y='NEXT')

    def th(*cols_widths):
        _a = 'R' if is_rtl else 'L'
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*C_TH_BG); pdf.set_text_color(*C_TH_TXT)
        pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('B',9)
        for col,w in cols_widths: pdf.cell(w,7,_fit(col,w),border=1,fill=True,align=_a)
        pdf.ln()

    def tr(*vals_widths,alt=False):
        _a = 'R' if is_rtl else 'L'
        pdf.set_x(L_MARGIN); pdf.set_fill_color(*(C_ROW_ALT if alt else (255,255,255)))
        pdf.set_text_color(*C_TXT); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.2); _font('',9)
        for val,w in vals_widths: pdf.cell(w,6,_fit(val,w),border=1,fill=True,align=_a)
        pdf.ln()

    csv_date=datetime.now().strftime('%Y%m%d')
    csv_fname=f'bastion_dashboard_{csv_date}.csv'

    def csv_ref(filename):
        _a = 'R' if is_rtl else 'L'
        pdf.ln(2); pdf.set_fill_color(235,243,255); pdf.set_draw_color(*C_ACCENT); pdf.set_line_width(0.3)
        pdf.set_x(L_MARGIN); pdf.rect(L_MARGIN,pdf.get_y(),CONTENT_W,8,'FD')
        _font('I',8); pdf.set_text_color(*C_NAVY); pdf.set_x(L_MARGIN+2)
        pdf.cell(CONTENT_W-4,8,_txt(ds('csv ref', filename=filename)),align=_a,new_x='LMARGIN',new_y='NEXT'); pdf.ln(2)

    # ── Cover ──────────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(*C_NAVY); pdf.rect(0,0,210,60,'F')
    pdf.set_y(18); _font('B',34); pdf.set_text_color(255,255,255)
    pdf.cell(0,16,'BASTION IDS',align='C',new_x='LMARGIN',new_y='NEXT')
    _font('',13); pdf.set_text_color(200,215,245)
    pdf.cell(0,8,_txt(ds('dash sub1')),align='C',new_x='LMARGIN',new_y='NEXT')
    pdf.cell(0,7,_txt(ds('dash sub2')),align='C',new_x='LMARGIN',new_y='NEXT')
    pdf.ln(16)
    # Stat tiles
    tiles=[(ds('Total Scans'),str(total_scans),ds('tile sub scans')),(ds('Total Flows'),f'{total_flows:,}',ds('tile sub flows')),
           (ds('Threats'),f'{total_threats:,}',ds('tile sub threats')),(ds('Detection Rate'),f'{detect_rate}%',ds('tile sub rate'))]
    tw=CONTENT_W/4; tile_y=pdf.get_y()
    for i,(lbl,val,sub) in enumerate(tiles):
        tx=L_MARGIN+i*tw
        pdf.set_fill_color(245,248,254); pdf.set_draw_color(*C_BORDER); pdf.set_line_width(0.3)
        pdf.rect(tx,tile_y,tw-2,22,'FD')
        _font('B',15); pdf.set_text_color(*C_NAVY)
        pdf.set_xy(tx,tile_y+2); pdf.cell(tw-2,9,_safe(val),align='C')
        _font('',7); pdf.set_text_color(*C_MUTED)
        pdf.set_xy(tx,tile_y+11); pdf.cell(tw-2,5,_txt(lbl),align='C')
        pdf.set_xy(tx,tile_y+16); pdf.cell(tw-2,4,_txt(sub),align='C')
    pdf.set_y(tile_y+26); pdf.ln(4)
    for k,v in [(ds('Analyst'),session.get('user','')),(ds('Generated'),datetime.now().strftime('%Y-%m-%d %H:%M:%S'))]:
        _font('B',10); pdf.set_text_color(*C_MUTED)
        pdf.set_x(L_MARGIN); pdf.cell(60,7,_txt(k+':'),align='R' if is_rtl else 'L',new_x='RIGHT',new_y='LAST')
        _font('',10); pdf.set_text_color(*C_TXT); pdf.cell(0,7,_txt(str(v)),align='R' if is_rtl else 'L',new_x='LMARGIN',new_y='NEXT')

    # ── Section 1: Overall Statistics ─────────────────────────────────────────
    pdf.add_page()
    section(ds('s1 title'), ds('s1 desc'))
    kv(ds('Total Scans kv'),total_scans); kv(ds('Total Flows Analyzed'),f'{total_flows:,}')
    kv(ds('Total Malicious Flows'),f'{total_threats:,}'); kv(ds('Total Benign Flows'),f'{total_flows-total_threats:,}')
    kv(ds('Detection Rate kv'),f'{detect_rate}%'); kv(ds('Unique Attack Types'),str(len(threat_counts)))
    pdf.ln(3)

    # Severity bar visualization
    section(ds('Traffic Severity Breakdown'))
    bar_w=110
    for sev in ['CRITICAL','HIGH','MEDIUM','UNKNOWN','SAFE']:
        cnt=sev_totals.get(sev,0); frac=cnt/total_flows if total_flows else 0
        filled=int(frac*bar_w); pct=f'{frac*100:.1f}%'
        _font('B',9); pdf.set_text_color(*C_MUTED)
        pdf.set_x(L_MARGIN); pdf.cell(32,6,_txt(ds(sev)),new_x='RIGHT',new_y='LAST')
        pdf.set_fill_color(*SEV_TXT.get(sev,(80,85,100)))
        if filled>0: pdf.rect(pdf.get_x(),pdf.get_y()+1,filled,4,'F')
        pdf.set_fill_color(225,230,242)
        if bar_w-filled>0: pdf.rect(pdf.get_x()+filled,pdf.get_y()+1,bar_w-filled,4,'F')
        pdf.set_x(pdf.get_x()+bar_w+3); _font('',9); pdf.set_text_color(*C_TXT)
        pdf.cell(40,6,_safe(f'{cnt:,}  ({pct})'),new_x='LMARGIN',new_y='NEXT')
    pdf.ln(3)
    th((ds('Severity'),45),(ds('Flow Count'),40),(ds('Percentage'),35),(ds('Meaning'),60))
    for i,sev in enumerate(['CRITICAL','HIGH','MEDIUM','UNKNOWN','SAFE']):
        cnt=sev_totals.get(sev,0); pct=f"{round(cnt/total_flows*100,2)}%" if total_flows else '0%'
        tr((ds(sev),45),(f'{cnt:,}',40),(pct,35),(SEV_EXPLAIN.get(sev,''),60),alt=(i%2==1))
    pdf.ln(3)

    if threat_counts:
        section(ds('Attack Type Breakdown'), ds('atk bd desc'))
        sorted_tc=sorted(threat_counts.items(),key=lambda x:x[1],reverse=True)
        th((ds('Attack Type'),75),(ds('Flow Count'),28),(ds('% Threats'),27),(ds('Severity'),25),(ds('Description'),25))
        for i,(lbl,cnt) in enumerate(sorted_tc[:10]):
            sev,_,_=get_severity(lbl); pct=f"{round(cnt/total_threats*100,1)}%" if total_threats else '0%'
            exp=''
            for k,v in ATTACK_EXPLAIN.items():
                if k.lower() in lbl.lower(): exp=v[:22]; break
            tr((lbl,75),(f'{cnt:,}',28),(pct,27),(ds(sev),25),(exp,25),alt=(i%2==1))
        if len(sorted_tc)>10: csv_ref(csv_fname)

    # ── Section 2: Scan History ────────────────────────────────────────────────
    pdf.add_page()
    section(ds('s2 title'), ds('s2 desc', n=len(history)))
    if history:
        th((ds('Date'),25),(ds('Scan ID'),45),(ds('File'),60),(ds('Flows'),20),(ds('Threats'),20),(ds('Rate'),10))
        for i,h in enumerate(history[:15]):
            tf=h.get('total_flows',0) or 0; mal=h.get('malicious_flows',0) or 0
            rate=f"{round(mal/tf*100,1)}%" if tf else '0%'
            tr((h.get('timestamp','')[:10],25),(h.get('scan_id','')[:20],45),(h.get('filename',''),60),
               (f'{tf:,}',20),(str(mal),20),(rate,10),alt=(i%2==1))
        if len(history)>15: csv_ref(csv_fname)

    # ── Section 3: Security Recommendations ───────────────────────────────────
    pdf.add_page()
    section(ds('s3 title'), ds('s3 desc'))
    recs=[]
    if sev_totals.get('CRITICAL',0)>0: recs.append(('CRITICAL',ds('rec_crit_title'),ds('rec_crit_body',n=sev_totals['CRITICAL'])))
    if sev_totals.get('HIGH',0)>0: recs.append(('HIGH',ds('rec_high_title'),ds('rec_high_body',n=sev_totals['HIGH'])))
    if threat_counts.get('Bot',0)>0: recs.append(('CRITICAL',ds('rec_bot_title'),ds('rec_bot_body',n=threat_counts['Bot'])))
    if any('Patator' in k or 'Brute' in k for k in threat_counts): recs.append(('HIGH',ds('rec_brute_title'),ds('rec_brute_body')))
    if any('DoS' in k or 'DDoS' in k for k in threat_counts): recs.append(('HIGH',ds('rec_dos_title'),ds('rec_dos_body')))
    if any('Sql Injection' in k for k in threat_counts): recs.append(('CRITICAL',ds('rec_sqli_title'),ds('rec_sqli_body')))
    if any('XSS' in k for k in threat_counts): recs.append(('HIGH',ds('rec_xss_title'),ds('rec_xss_body')))
    if not recs: recs.append(('SAFE',ds('rec_safe_title'),ds('rec_safe_body')))
    for sev,title,body in recs:
        bg=SEV_BG.get(sev,(240,242,246)); bdr=SEV_BDR.get(sev,(160,165,180)); txt=SEV_TXT.get(sev,(80,85,100))
        rec_y=pdf.get_y()
        pdf.set_fill_color(*txt); pdf.rect(L_MARGIN,rec_y,5,14,'F')
        pdf.set_fill_color(*bg); pdf.set_draw_color(*bdr); pdf.set_line_width(0.3)
        pdf.rect(L_MARGIN+5,rec_y,CONTENT_W-5,14,'FD')
        _font('B',10); pdf.set_text_color(*txt)
        pdf.set_xy(L_MARGIN+8,rec_y+1)
        if is_rtl:
            # severity badge on left, Arabic title on right
            pdf.cell(40,6,_txt(ds(sev)),align='C',new_x='RIGHT',new_y='LAST')
            pdf.cell(CONTENT_W-48,6,_txt(title),align='R',new_x='LMARGIN',new_y='NEXT')
        else:
            pdf.cell(CONTENT_W-10,6,_safe(f'[{sev}]  {title}'),align='L',new_x='LMARGIN',new_y='NEXT')
        _font('',9); pdf.set_text_color(*C_TXT); pdf.set_x(L_MARGIN+8)
        pdf.multi_cell(CONTENT_W-10,5,_txt(body),align='R' if is_rtl else 'L',new_x='LMARGIN',new_y='NEXT'); pdf.ln(3)

    # ── Companion CSV ──────────────────────────────────────────────────────────
    csv_buf=io.StringIO(); writer=csv.writer(csv_buf)
    writer.writerow(['=== FULL ATTACK TYPE BREAKDOWN ==='])
    writer.writerow(['Attack Type','Flow Count','% of Threats','Severity','Description'])
    for lbl,cnt in sorted(threat_counts.items(),key=lambda x:x[1],reverse=True):
        sev,_,_=get_severity(lbl); pct=f"{round(cnt/total_threats*100,1)}%" if total_threats else '0%'
        exp=''
        for k,v in ATTACK_EXPLAIN.items():
            if k.lower() in lbl.lower(): exp=v; break
        writer.writerow([lbl,cnt,pct,sev,exp])
    writer.writerow([])
    writer.writerow(['=== FULL SCAN HISTORY ==='])
    writer.writerow(['Scan ID','Timestamp','Filename','Total Flows','Malicious Flows','Benign Flows','Detection Rate','Avg Confidence'])
    for h in history:
        tf=h.get('total_flows',0) or 0; mal=h.get('malicious_flows',0) or 0
        rate=f"{round(mal/tf*100,1)}%" if tf else '0%'
        writer.writerow([h.get('scan_id',''),h.get('timestamp',''),_csv_safe(h.get('filename','')),
                         tf,mal,h.get('benign_flows',0),rate,h.get('avg_confidence',0)])

    pdf_fname=f'bastion_dashboard_{csv_date}.pdf'; zip_fname=f'bastion_dashboard_{csv_date}.zip'
    zip_buf=io.BytesIO()
    with zipfile.ZipFile(zip_buf,'w',zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(pdf_fname, bytes(pdf.output()))
        zf.writestr(csv_fname, csv_buf.getvalue())
    zip_buf.seek(0)
    return send_file(zip_buf, as_attachment=True,
                     download_name=_safe(zip_fname),
                     mimetype='application/zip')

# ── Scan Enhancements ──────────────────────────────────────────────────────────
def _run_sequential(jobs, scan_user):
    """Run scans one by one: (scan_id, filepath, filename) list."""
    for scan_id, filepath, filename in jobs:
        _run_scan(scan_id, filepath, scan_user)

@app.route('/scan/multi', methods=['POST'])
@login_required
def scan_multi():
    files = request.files.getlist('files')
    if not files: flash(t('flash no file'), 'error'); return redirect(url_for('scan'))
    files = files[:20]  # cap to prevent DoS via hundreds of concurrent scans
    if model is None:
        app.logger.error(f'Multi-scan attempted but model not loaded: {model_error}')
        flash(t('flash model not loaded'), 'error')
        return redirect(url_for('scan'))
    scan_user = session.get('user','system')
    jobs = []
    base_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    for idx, f in enumerate(files):
        fname_lower = (f.filename or '').lower()
        is_pcap = fname_lower.endswith('.pcap') or fname_lower.endswith('.pcapng')
        if not fname_lower.endswith('.csv') and not is_pcap:
            continue
        scan_id  = f'{base_ts}_{idx}'
        filename = secure_filename(f.filename)
        filepath = UPLOAD_DIR / f'upload_{scan_id}.csv'
        if is_pcap:
            pcap_tmp = UPLOAD_DIR / f'upload_{scan_id}.pcap'
            f.save(str(pcap_tmp))
            try:
                if cicflowmeter_available():
                    try:
                        flows_df = pcap_to_flows_cicflowmeter(pcap_tmp)
                    except Exception:
                        flows_df = pcap_to_flows_df(pcap_tmp)
                else:
                    flows_df = pcap_to_flows_df(pcap_tmp)
                flows_df.to_csv(str(filepath), index=False)
                pcap_tmp.unlink(missing_ok=True)
            except Exception:
                pcap_tmp.unlink(missing_ok=True)
                continue
        else:
            f.save(str(filepath))
        state = make_state(scan_id, filename)
        state['is_pcap'] = is_pcap
        state['user']   = scan_user
        state['lang']   = session.get('lang', 'en')
        state['status'] = 'queued'
        state['phase']  = _ph(state, 'queued')
        with SCANS_LOCK: SCANS[scan_id] = state
        jobs.append((scan_id, filepath, filename))
    if not jobs:
        flash(t('flash no valid files'), 'error'); return redirect(url_for('scan'))
    threading.Thread(target=_run_sequential, args=(jobs, scan_user), daemon=True).start()
    scan_ids = ','.join(j[0] for j in jobs)
    return redirect(url_for('scan_queue', scan_ids=scan_ids))

@app.route('/scan/queue')
@login_required
def scan_queue():
    scan_ids = request.args.get('scan_ids', '').split(',')
    _SID_RE = re.compile(r'^[A-Za-z0-9_\-]{1,64}$')
    scan_ids = [s.strip() for s in scan_ids if s.strip() and _SID_RE.match(s.strip())][:20]
    cards = []
    current_user = session.get('user', '')
    current_role = get_roles().get(current_user, 'analyst')
    is_privileged = current_role in ('admin', 'cc_admin')
    for sid in scan_ids:
        state = SCANS.get(sid)
        if state:
            if is_privileged or state.get('user') in (None, '', current_user):
                cards.append({'scan_id': sid, 'filename': state['filename']})
        else:
            h = load_history()
            entry = next((x for x in h if x.get('scan_id') == sid), None)
            if entry and (is_privileged or entry.get('user') in (None, '', current_user)):
                cards.append({'scan_id': sid, 'filename': entry.get('filename', sid)})
    return render_template('scan_queue.html', cards=cards)

@app.route('/rescan/<scan_id>', methods=['POST'])
@login_required
def rescan(scan_id):
    if not re.match(r'^[A-Za-z0-9_\-]{1,64}$', scan_id):
        flash(t('flash access denied'), 'error'); return redirect(url_for('history'))
    h = load_history()
    entry = next((x for x in h if x.get('scan_id')==scan_id), None)
    if not entry: flash(t('flash scan not found'), 'error'); return redirect(url_for('history'))
    current_user = session.get('user', '')
    current_role = get_roles().get(current_user, 'analyst')
    if entry.get('user') not in (None, '', current_user) and current_role not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))
    orig = Path(UPLOAD_DIR / f'upload_{scan_id}.csv')
    if not orig.exists(): flash(t('flash file unavailable'), 'error'); return redirect(url_for('result', scan_id=scan_id))
    _now_rescan = datetime.now()
    new_id = _now_rescan.strftime('%Y%m%d_%H%M%S') + f'_{_now_rescan.microsecond:06d}'
    import shutil
    dest = UPLOAD_DIR / f'upload_{new_id}.csv'
    shutil.copy(str(orig), str(dest))
    scan_user = session.get('user', 'system')
    state = make_state(new_id, entry.get('filename',''))
    state['user'] = scan_user
    state['lang'] = session.get('lang', 'en')
    with SCANS_LOCK: SCANS[new_id] = state
    threading.Thread(target=_run_scan, args=(new_id, dest, scan_user), daemon=True).start()
    return redirect(url_for('scan_live', scan_id=new_id))

# ── Change Password ────────────────────────────────────────────────────────────
@app.route('/settings/change_password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password','')[:256]
        new_pw  = request.form.get('new_password','')[:256]
        confirm = request.form.get('confirm_password','')[:256]
        u = session.get('user','')
        users = get_users()
        if u not in users:
            flash(t('flash wrong password'), 'error')
            return render_template('change_password.html')
        if not _secrets.compare_digest(users.get(u, ''), hashlib.sha256(current.encode()).hexdigest()):
            flash(t('flash wrong password'), 'error')
        elif new_pw != confirm:
            flash(t('flash passwords mismatch'), 'error')
        elif len(new_pw) < 8:
            flash(t('flash password too short'), 'error')
        else:
            with _CONFIG_LOCK:
                cfg_data = get_config()
                cfg_data.setdefault('users',{})[u] = hashlib.sha256(new_pw.encode()).hexdigest()
                save_config(cfg_data)
                reload_config()
            audit('password_change', detail=f'User {u} changed password')
            flash(t('flash password changed'), 'success')
            return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# ── 2FA ────────────────────────────────────────────────────────────────────────
@app.route('/2fa/setup', methods=['GET','POST'])
@login_required
def two_fa_setup():
    u = session.get('user','')
    if not HAS_2FA:
        flash(t('flash 2fa missing'), 'error')
        return redirect(url_for('settings'))
    cfg_data = get_config()
    secret = cfg_data.get('2fa_secrets',{}).get(u)
    if request.method == 'POST':
        action = request.form.get('action','')
        if action == 'disable':
            # Require current TOTP code to disable 2FA -- prevents session-hijack disablement
            disable_code = request.form.get('code', '').strip()[:8]
            if not secret or not HAS_2FA:
                flash(t('flash invalid code'), 'error')
            elif not pyotp.TOTP(secret).verify(disable_code, valid_window=1):
                flash(t('flash invalid code'), 'error')
            else:
                with _CONFIG_LOCK:
                    cfg_data = get_config()
                    secrets = cfg_data.get('2fa_secrets')
                    if isinstance(secrets, dict) and u in secrets:
                        del secrets[u]
                    save_config(cfg_data); reload_config()
                audit('2fa_disabled', detail=f'2FA disabled for {u}')
                flash(t('flash 2fa disabled'), 'success')
                return redirect(url_for('dashboard'))
            return render_template('two_fa_setup.html', secret=None, qr_b64=None, totp_uri='', has_2fa=bool(secret))
        code = request.form.get('code','').strip()[:8]
        # Read secret from session (set on GET) -- not from form field to prevent substitution
        new_secret = session.get('_2fa_setup_secret','')
        if not new_secret:
            flash(t('flash invalid code'), 'error')
        else:
            totp = pyotp.TOTP(new_secret)
            if totp.verify(code, valid_window=1):
                with _CONFIG_LOCK:
                    cfg_data = get_config()
                    cfg_data.setdefault('2fa_secrets',{})[u] = new_secret
                    save_config(cfg_data); reload_config()
                audit('2fa_enabled', detail=f'2FA enabled for {u}')
                session.pop('_2fa_setup_secret', None)
                flash(t('flash 2fa enabled'), 'success')
                session.clear()
                return redirect(url_for('login'))
            else:
                flash(t('flash invalid code'), 'error')
    # Preserve the secret across POST failures so the QR code stays stable
    new_secret = session.get('_2fa_setup_secret') or pyotp.random_base32()
    session['_2fa_setup_secret'] = new_secret
    totp_uri = pyotp.TOTP(new_secret).provisioning_uri(name=u, issuer_name='BASTION IDS')
    try:
        import qrcode as _qr, base64, io as _io
        img = _qr.make(totp_uri)
        buf = _io.BytesIO(); img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
    except Exception: qr_b64 = None
    return render_template('two_fa_setup.html', secret=new_secret, qr_b64=qr_b64, totp_uri=totp_uri, has_2fa=bool(secret))

@app.route('/2fa/verify', methods=['GET','POST'])
def two_fa_verify():
    u = session.get('_2fa_pending_user','')
    if not u: return redirect(url_for('login'))
    if request.method == 'POST':
        if not _check_2fa_rate(u):
            audit_system('2fa_locked', user=u, detail=f'2FA locked out for user {u}')
            flash(t('flash invalid 2fa code'), 'error')
            return render_template('two_fa_verify.html')
        code = request.form.get('code','').strip()[:8]
        cfg_data = get_config()
        secret = cfg_data.get('2fa_secrets',{}).get(u,'')
        if secret and HAS_2FA and pyotp.TOTP(secret).verify(code, valid_window=1):
            # Re-check disabled/deleted status -- admin may have changed it
            # between the password step and the 2FA step.
            if u not in cfg_data.get('users', {}):
                session.clear()
                flash(t('flash session expired'), 'error')
                return redirect(url_for('login'))
            if u in cfg_data.get('disabled_users', []):
                session.clear()
                flash(t('flash account disabled'), 'error')
                return redirect(url_for('login'))
            _clear_2fa_failures(u)
            # Regenerate session to prevent session fixation attacks
            _prev_lang = session.get('lang')
            session.clear()
            session['user'] = u
            roles = get_roles()
            session['role'] = roles.get(u,'analyst')
            session['lang'] = _prev_lang or cfg('language', 'en')
            session['_last_active'] = datetime.now().isoformat()
            # Record last login time
            with _CONFIG_LOCK:
                _login_cfg = get_config()
                _login_cfg.setdefault('user_last_login', {})[u] = datetime.now().isoformat()
                save_config(_login_cfg)
                reload_config()
            audit_system('login', user=u, detail=f'User {u} logged in via 2FA')
            return redirect(url_for('dashboard'))
        _record_2fa_failure(u)
        audit_system('2fa_failed', user=u, detail=f'Failed 2FA attempt for user {u}')
        flash(t('flash invalid 2fa code'), 'error')
    return render_template('two_fa_verify.html')

@app.errorhandler(413)
def too_large(e):
    flash(t('flash file too large'), 'error')
    return redirect(url_for('scan'))

# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE BLOCK: cc_admin, network graph, threat hunt, timeline,
#                fp_feedback, whitelist, playbooks, case SLA
# ═══════════════════════════════════════════════════════════════════════════════

# ── CC Admin ──────────────────────────────────────────────────────────────────
@app.route('/cc_admin/manage')
@cc_admin_required
def cc_admin_manage():
    c = get_config()
    users = c.get('users', {})
    roles = c.get('roles', {})
    me = session.get('user','')
    last_login = c.get('user_last_login', {})
    managed_by = c.get('managed_by', {})
    # Only analysts created by this cc_admin
    managed = [{'username': u, 'role': roles.get(u,'analyst'), 'last_login': last_login.get(u,'Never')}
               for u in users if roles.get(u,'analyst') == 'analyst' and managed_by.get(u) == me]
    # Pull login/logout audit events for managed analysts only
    analyst_names = {m['username'] for m in managed}
    activity_log = []
    audit_data = []
    with _AUDIT_LOCK:
        if AUDIT_PATH.exists():
            try:
                with open(AUDIT_PATH) as f:
                    audit_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                audit_data = []
    for ev in reversed(audit_data):
        if ev.get('action') in ('login','logout') and ev.get('user') in analyst_names:
            activity_log.append(ev)
    activity_log = activity_log[:200]
    return render_template('cc_admin.html', managed_users=managed, activity_log=activity_log)

@app.route('/cc_admin/add_user', methods=['POST'])
@cc_admin_required
def cc_admin_add_user():
    u    = request.form.get('username','').strip()
    p    = request.form.get('password','')[:256]
    # cc_admin can only create analyst accounts
    role = 'analyst'
    if not u or not p:
        flash(t('flash user pass required'), 'error')
        return redirect(url_for('cc_admin_manage'))
    if not re.match(r'^[A-Za-z0-9_]{1,32}$', u):
        flash(t('flash invalid username'), 'error')
        return redirect(url_for('cc_admin_manage'))
    if len(p) < 8:
        flash(t('flash password too short'), 'error')
        return redirect(url_for('cc_admin_manage'))
    with _CONFIG_LOCK:
        c = get_config()
        users = c.get('users', {})
        roles = c.get('roles', {})
        if u in users:
            flash(t('flash user exists').replace('{u}', u), 'error')
            return redirect(url_for('cc_admin_manage'))
        users[u] = hashlib.sha256(p.encode()).hexdigest()
        roles[u] = role
        c['users'] = users
        c['roles'] = roles
        # Track which cc_admin created this analyst
        managed_by = c.get('managed_by', {})
        managed_by[u] = session.get('user', '')
        c['managed_by'] = managed_by
        save_config(c)
        reload_config()
    audit('cc_admin_user_add', detail=f'CC Admin {session.get("user","")} added analyst {u}')
    flash(t('flash analyst added').replace('{u}', u), 'success')
    return redirect(url_for('cc_admin_manage'))

# ── Network Graph ─────────────────────────────────────────────────────────────
@app.route('/result/<scan_id>/graph')
@login_required
def network_graph(scan_id):
    entry, rows = load_results(scan_id)
    if entry is None:
        flash(t('flash scan not found'), 'error')
        return redirect(url_for('history'))
    current_user = session.get('user', '')
    if entry.get('user') not in (None, '', current_user) and session.get('role', 'analyst') not in ('admin', 'cc_admin'):
        flash(t('flash access denied scan'), 'error')
        return redirect(url_for('history'))
    # Build nodes & edges
    node_set = {}
    edges = []
    for r in rows:
        src = r.get('src_ip','N/A')
        dst = r.get('dst_ip','N/A')
        sev = r.get('severity','SAFE')
        label = r.get('label','BENIGN')
        if src == 'N/A' or dst == 'N/A':
            continue
        for ip in (src, dst):
            if ip not in node_set:
                node_set[ip] = {'id': ip, 'is_src': False, 'is_dst': False, 'attacks': set()}
        node_set[src]['is_src'] = True
        node_set[dst]['is_dst'] = True
        if r.get('is_malicious'):
            node_set[src]['attacks'].add(label)
        edges.append({'source': src, 'target': dst, 'severity': sev, 'label': label})
    nodes = []
    for ip, d in node_set.items():
        if d['is_src'] and d['is_dst']:
            role = 'both'
        elif d['is_src']:
            role = 'src'
        else:
            role = 'dst'
        nodes.append({'id': ip, 'role': role, 'attacks': list(d['attacks'])})
    edges_capped = edges[:5000]
    return render_template('network_graph.html',
                           entry=entry,
                           scan_id=scan_id,
                           nodes=nodes,
                           edges=edges_capped)

# ── Threat Hunting ────────────────────────────────────────────────────────────
@app.route('/hunt', methods=['GET','POST'])
@login_required
def threat_hunt():
    results = []
    total = 0
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (ValueError, TypeError):
        page = 1
    per_page = 50
    query = {}
    known_labels = list(SEVERITY.keys()) + ['BENIGN']

    if request.method == 'POST':
        try:
            page = max(1, int(request.form.get('page', 1)))
        except (ValueError, TypeError):
            page = 1
        _DATE_RE = re.compile(r'^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$')
        _raw_date_from = request.form.get('date_from','').strip()[:10]
        _raw_date_to   = request.form.get('date_to','').strip()[:10]
        query = {
            'src_ip':      request.form.get('src_ip','').strip()[:64],
            'dst_ip':      request.form.get('dst_ip','').strip()[:64],
            'attack_type': request.form.get('attack_type','').strip()[:128],
            'severity':    request.form.get('severity','').strip()[:32],
            'date_from':   _raw_date_from if _DATE_RE.match(_raw_date_from) else '',
            'date_to':     _raw_date_to   if _DATE_RE.match(_raw_date_to)   else '',
            'min_conf':    request.form.get('min_confidence','').strip()[:10],
        }
        # Scan all flows files
        # Admins/cc_admins can search across all users; analysts see only their own scans
        _hunt_role = session.get('role', get_roles().get(session.get('user',''), 'analyst'))
        history = load_history() if _hunt_role in ('admin', 'cc_admin') else load_user_history()
        all_rows = []
        _HUNT_ROW_CAP = 200_000   # guard against memory exhaustion
        for entry in history:
            if len(all_rows) >= _HUNT_ROW_CAP:
                break
            fp = Path(entry.get('flows_file') or '')
            ts = entry.get('timestamp','')
            if not fp.exists():
                continue
            # Date filter at scan level for efficiency
            if query['date_from'] and ts and ts[:10] < query['date_from']:
                continue
            if query['date_to'] and ts and ts[:10] > query['date_to']:
                continue
            try:
                remaining = _HUNT_ROW_CAP - len(all_rows)
                rows = pd.read_csv(fp, nrows=remaining).to_dict('records')
                for r in rows:
                    r['_scan_id']    = entry.get('scan_id','')
                    r['_timestamp']  = ts
                    r['_filename']   = entry.get('filename','')
                    all_rows.append(r)
            except Exception:
                continue

        # Apply filters
        try:
            min_conf = float(query['min_conf']) if query['min_conf'] else 0
        except (ValueError, TypeError):
            min_conf = 0
        for r in all_rows:
            label = str(r.get('label', r.get('Label',''))).strip()
            src   = str(r.get('src_ip', r.get(' Source IP',''))).strip()
            dst   = str(r.get('dst_ip', r.get(' Destination IP',''))).strip()
            sev,_,_ = get_severity(label)
            try:
                conf = float(r.get('confidence', r.get('Confidence', 0)) or 0)
            except (ValueError, TypeError):
                conf = 0.0
            if query['src_ip'] and query['src_ip'] not in src:
                continue
            if query['dst_ip'] and query['dst_ip'] not in dst:
                continue
            if query['attack_type'] and query['attack_type'].lower() not in label.lower():
                continue
            if query['severity'] and query['severity'] != sev:
                continue
            if min_conf and conf < min_conf:
                continue
            results.append({'label': label, 'src_ip': src, 'dst_ip': dst,
                            'severity': sev, 'confidence': conf,
                            'scan_id': r['_scan_id'], 'timestamp': r['_timestamp'],
                            'filename': r['_filename']})

        total = len(results)
        _pages_tmp = max(1, (total + per_page - 1) // per_page)
        page  = min(page, _pages_tmp)
        start = (page - 1) * per_page
        results = results[start:start + per_page]

    pages = max(1, (total + per_page - 1) // per_page)
    return render_template('hunt.html',
                           results=results, total=total,
                           page=page, pages=pages,
                           query=query, known_labels=known_labels)

# ── Attack Timeline ───────────────────────────────────────────────────────────
@app.route('/timeline')
@login_required
def attack_timeline():
    history = load_user_history()
    events = []
    for entry in history:
        ts = entry.get('timestamp','')
        for label, count in entry.get('threat_breakdown',{}).items():
            if label.upper() == 'BENIGN':
                continue
            sev, color, _ = get_severity(label)
            events.append({
                'timestamp': ts,
                'label':     label,
                'severity':  sev,
                'color':     color,
                'count':     count,
                'scan_id':   entry.get('scan_id',''),
                'filename':  entry.get('filename',''),
            })
    events.sort(key=lambda x: x['timestamp'], reverse=True)
    return render_template('timeline.html', events=events)

# ── FP Feedback ───────────────────────────────────────────────────────────────
@app.route('/fp_feedback')
@admin_required
def fp_feedback():
    with _FP_LOCK:
        records = load_fp_feedback()
    # Group by label
    grouped = {}
    for r in records:
        lbl = r.get('label','Unknown')
        grouped.setdefault(lbl, []).append(r)
    return render_template('fp_feedback.html', records=records, grouped=grouped)

# ── IP Whitelist ──────────────────────────────────────────────────────────────
@app.route('/whitelist_ips', methods=['GET','POST'])
@admin_required
def whitelist_ips():
    if request.method == 'POST':
        action = request.form.get('action','add')
        if action == 'add':
            ip_or_cidr = request.form.get('ip','').strip()[:64]
            note = request.form.get('note','').strip()[:500]
            if ip_or_cidr:
                try:
                    ipaddress.ip_network(ip_or_cidr, strict=False)
                    valid_ip = True
                except ValueError:
                    valid_ip = False
                if not valid_ip:
                    flash(t('flash ip required'), 'error')
                else:
                    with _WHITELIST_LOCK:
                        wl = load_whitelist()
                        if any(e.get('cidr') == ip_or_cidr for e in wl):
                            flash(t('flash ip already watchlist').replace('{ip}', ip_or_cidr), 'error')
                            return redirect(url_for('whitelist_ips'))
                        wl.append({
                            'ip':       ip_or_cidr,
                            'cidr':     ip_or_cidr,
                            'note':     note,
                            'added_by': session.get('user',''),
                            'added_at': datetime.now().isoformat(),
                        })
                        save_whitelist(wl)
                    audit('whitelist_add', detail=f'Added {ip_or_cidr}')
                    flash(t('flash ip whitelist added').replace('{ip}', ip_or_cidr), 'success')
        elif action == 'remove':
            cidr = request.form.get('cidr','').strip()[:64]
            with _WHITELIST_LOCK:
                wl = load_whitelist()
                wl = [e for e in wl if e.get('cidr') != cidr]
                save_whitelist(wl)
            audit('whitelist_remove', detail=f'Removed {cidr}')
            flash(t('flash entry removed'), 'success')
        return redirect(url_for('whitelist_ips'))
    with _WHITELIST_LOCK:
        wl = load_whitelist()
    return render_template('whitelist_ips.html', whitelist=wl)

# ── Response Playbooks ────────────────────────────────────────────────────────
PLAYBOOKS = {
    'DDoS': [
        '1. Enable rate limiting on edge firewall immediately.',
        '2. Identify and block top attacker IPs (see Flow Table).',
        '3. Contact upstream ISP to apply null-routing.',
        '4. Enable DDoS scrubbing service if available.',
        '5. Monitor traffic volume every 5 minutes until subsides.',
        '6. Document start/end time and peak volume for post-incident report.',
    ],
    'DoS Hulk': [
        '1. Block source IPs sending high request volume.',
        '2. Apply HTTP connection rate limits on web server.',
        '3. Check server health metrics (CPU, memory, connections).',
        '4. Enable web application firewall (WAF) rules.',
        '5. Scale horizontally if infrastructure allows.',
    ],
    'DoS GoldenEye': [
        '1. Identify and block source IPs at firewall.',
        '2. Enable Keep-Alive connection limits on web server.',
        '3. Apply HTTP header validation rules.',
        '4. Monitor web server logs for continued attempts.',
    ],
    'DoS slowloris': [
        '1. Apply connection timeout settings (reduce to 10-15s).',
        '2. Increase MinSpareServers and MaxClients limits.',
        '3. Deploy mod_reqtimeout (Apache) or similar.',
        '4. Block source IP ranges at firewall.',
    ],
    'DoS Slowhttptest': [
        '1. Set aggressive timeout on slow HTTP connections.',
        '2. Block identified source IPs immediately.',
        '3. Apply reverse proxy (Nginx/HAProxy) in front of server.',
        '4. Review and harden web server timeouts.',
    ],
    'PortScan': [
        '1. Identify scanning source IPs and block at perimeter firewall.',
        '2. Review which ports were scanned — harden exposed services.',
        '3. Enable IDS/IPS alerting for continued scanning activity.',
        '4. Check for internal compromised hosts as scan origin.',
        '5. Log all firewall blocks and generate ticket for investigation.',
    ],
    'FTP-Patator': [
        '1. Lock out source IP after N failed attempts (account lockout policy).',
        '2. Disable FTP if not required — use SFTP instead.',
        '3. Enable multi-factor authentication on FTP accounts.',
        '4. Review FTP logs for successful logins after brute force.',
        '5. Reset passwords for accounts targeted in attack.',
    ],
    'SSH-Patator': [
        '1. Block source IP at firewall immediately.',
        '2. Enable fail2ban or equivalent intrusion prevention.',
        '3. Disable password auth — enforce SSH key-based auth.',
        '4. Move SSH to non-standard port (security by obscurity).',
        '5. Review SSH auth logs for any successful logins.',
        '6. Rotate SSH keys for affected accounts.',
    ],
    'Web Attack Brute Force': [
        '1. Enable CAPTCHA on login pages.',
        '2. Implement account lockout after 5 failed attempts.',
        '3. Block source IP at WAF.',
        '4. Audit accounts for unauthorized access post-attack.',
        '5. Enforce MFA on all web application accounts.',
    ],
    'Web Attack XSS': [
        '1. Identify and patch vulnerable input fields immediately.',
        '2. Implement Content Security Policy (CSP) headers.',
        '3. Sanitize and encode all user inputs server-side.',
        '4. Review application logs for data exfiltration attempts.',
        '5. Notify affected users if session data may be compromised.',
    ],
    'Web Attack Sql Injection': [
        '1. Take vulnerable endpoint offline until patched.',
        '2. Apply parameterized queries / prepared statements.',
        '3. Review database for unauthorized access or data modification.',
        '4. Apply WAF rule to block SQL injection patterns.',
        '5. Conduct full application security audit.',
        '6. Report data breach if PII was accessed.',
    ],
    'Bot': [
        '1. Identify C2 domains/IPs from traffic patterns and block.',
        '2. Isolate infected hosts from network immediately.',
        '3. Run full malware scan on suspected hosts.',
        '4. Reset credentials for all accounts on infected systems.',
        '5. Analyze botnet traffic for data exfiltration evidence.',
        '6. Report to law enforcement if criminal botnet activity confirmed.',
    ],
    'Heartbleed': [
        '1. Patch OpenSSL to version 1.0.1g or later IMMEDIATELY.',
        '2. Revoke and reissue all SSL/TLS certificates on affected servers.',
        '3. Force password resets for all users.',
        '4. Revoke all active session tokens.',
        '5. Audit logs for any private key or session data exposure.',
    ],
    'Infiltration': [
        '1. Isolate affected systems from network immediately.',
        '2. Identify compromised accounts and disable them.',
        '3. Forensic investigation: preserve memory and disk images.',
        '4. Review all outbound connections for data exfiltration.',
        '5. Engage incident response team.',
        '6. Notify legal/compliance if sensitive data was accessed.',
    ],
    'BENIGN': [
        '1. No immediate action required.',
        '2. Continue routine monitoring.',
        '3. Review periodically for any pattern changes.',
    ],
}

@app.route('/playbooks')
@login_required
def playbooks():
    lang = session.get('lang', cfg('language', 'en'))
    book = PLAYBOOKS_AR if lang == 'ar' else PLAYBOOKS
    return render_template('playbooks.html', playbooks=book)

PLAYBOOKS_AR = {
    'DDoS': [
        'تفعيل تحديد معدل الطلبات على جدار الحماية الطرفي فوراً.',
        'تحديد وحظر عناوين IP الأكثر هجوماً (انظر جدول التدفقات).',
        'التواصل مع مزود خدمة الإنترنت لتطبيق توجيه فارغ.',
        'تفعيل خدمة تنظيف DDoS إن توفرت.',
        'مراقبة حجم الحركة كل 5 دقائق حتى تهدأ.',
        'توثيق وقت البدء والانتهاء وذروة الحجم لتقرير ما بعد الحادثة.',
    ],
    'DoS Hulk': [
        'حظر عناوين IP التي ترسل حجماً عالياً من الطلبات.',
        'تطبيق حدود معدل اتصال HTTP على خادم الويب.',
        'فحص مقاييس صحة الخادم (المعالج، الذاكرة، الاتصالات).',
        'تفعيل قواعد جدار حماية تطبيقات الويب (WAF).',
        'التوسع الأفقي إن كانت البنية التحتية تسمح بذلك.',
    ],
    'DoS GoldenEye': [
        'تحديد وحظر عناوين IP المصدر على جدار الحماية.',
        'تفعيل حدود اتصال Keep-Alive على خادم الويب.',
        'تطبيق قواعد التحقق من رأس HTTP.',
        'مراقبة سجلات خادم الويب للمحاولات المستمرة.',
    ],
    'DoS slowloris': [
        'تطبيق إعدادات مهلة الاتصال (خفضها إلى 10-15 ثانية).',
        'زيادة حدود MinSpareServers و MaxClients.',
        'نشر mod_reqtimeout (Apache) أو ما يعادله.',
        'حظر نطاقات عناوين IP المصدر على جدار الحماية.',
    ],
    'DoS Slowhttptest': [
        'ضبط مهلة صارمة على اتصالات HTTP البطيئة.',
        'حظر عناوين IP المحددة فوراً.',
        'تطبيق وكيل عكسي (Nginx/HAProxy) أمام الخادم.',
        'مراجعة وتصليب مهلات خادم الويب.',
    ],
    'PortScan': [
        'تحديد عناوين IP الماسحة وحظرها على جدار الحماية المحيطي.',
        'مراجعة المنافذ التي تم مسحها وتحصين الخدمات المكشوفة.',
        'تفعيل تنبيهات IDS/IPS للنشاط الاستكشافي المستمر.',
        'التحقق من المضيفين الداخليين المخترقين بوصفهم مصدر المسح.',
        'تسجيل جميع حظر جدار الحماية وإنشاء تذكرة للتحقيق.',
    ],
    'FTP-Patator': [
        'قفل عنوان IP المصدر بعد N محاولات فاشلة (سياسة قفل الحساب).',
        'تعطيل FTP إن لم يكن مطلوباً — استخدم SFTP بدلاً منه.',
        'تفعيل المصادقة متعددة العوامل على حسابات FTP.',
        'مراجعة سجلات FTP للدخول الناجح بعد القوة الغاشمة.',
        'إعادة تعيين كلمات المرور للحسابات المستهدفة في الهجوم.',
    ],
    'SSH-Patator': [
        'حظر عنوان IP المصدر على جدار الحماية فوراً.',
        'تفعيل fail2ban أو ما يعادله من أنظمة منع التسلل.',
        'تعطيل مصادقة كلمة المرور — إلزام المصادقة بمفتاح SSH.',
        'نقل SSH إلى منفذ غير قياسي (الحماية بالغموض).',
        'مراجعة سجلات مصادقة SSH لأي عمليات تسجيل دخول ناجحة.',
        'تدوير مفاتيح SSH للحسابات المتأثرة.',
    ],
    'Web Attack Brute Force': [
        'تفعيل CAPTCHA على صفحات تسجيل الدخول.',
        'تطبيق قفل الحساب بعد 5 محاولات فاشلة.',
        'حظر عنوان IP المصدر على WAF.',
        'مراجعة الحسابات بحثاً عن وصول غير مصرح به بعد الهجوم.',
        'إلزام المصادقة متعددة العوامل على جميع حسابات تطبيق الويب.',
    ],
    'Web Attack XSS': [
        'تحديد وإصلاح حقول الإدخال الضعيفة فوراً.',
        'تطبيق رؤوس سياسة أمان المحتوى (CSP).',
        'تنظيف وترميز جميع مدخلات المستخدم من جانب الخادم.',
        'مراجعة سجلات التطبيق لمحاولات تسريب البيانات.',
        'إخطار المستخدمين المتأثرين إن كانت بيانات الجلسة مخترقة.',
    ],
    'Web Attack Sql Injection': [
        'تعطيل نقطة النهاية الضعيفة حتى يتم الإصلاح.',
        'تطبيق الاستعلامات ذات المعاملات / العبارات المُعدَّة.',
        'مراجعة قاعدة البيانات بحثاً عن وصول غير مصرح به أو تعديل بيانات.',
        'تطبيق قاعدة WAF لحظر أنماط حقن SQL.',
        'إجراء تدقيق أمني شامل للتطبيق.',
        'الإبلاغ عن خرق البيانات إذا تم الوصول إلى بيانات شخصية.',
    ],
    'Bot': [
        'تحديد نطاقات/عناوين IP للقيادة والتحكم من أنماط الحركة وحظرها.',
        'عزل المضيفين المصابين عن الشبكة فوراً.',
        'تشغيل فحص شامل للبرامج الضارة على المضيفين المشتبه بهم.',
        'إعادة تعيين بيانات الاعتماد لجميع الحسابات على الأنظمة المصابة.',
        'تحليل حركة الشبكة الروبوتية لأدلة تسريب البيانات.',
        'الإبلاغ إلى جهات إنفاذ القانون إذا تأكد نشاط شبكة الروبوت الإجرامية.',
    ],
    'Heartbleed': [
        'تحديث OpenSSL إلى الإصدار 1.0.1g أو أحدث فوراً.',
        'إلغاء وإعادة إصدار جميع شهادات SSL/TLS على الخوادم المتأثرة.',
        'إجبار جميع المستخدمين على إعادة تعيين كلمات المرور.',
        'إلغاء جميع رموز الجلسة النشطة.',
        'مراجعة السجلات لأي كشف لمفاتيح خاصة أو بيانات جلسة.',
    ],
    'Infiltration': [
        'عزل الأنظمة المتأثرة عن الشبكة فوراً.',
        'تحديد الحسابات المخترقة وتعطيلها.',
        'التحقيق الجنائي: حفظ صور الذاكرة والقرص.',
        'مراجعة جميع الاتصالات الصادرة لأدلة تسريب البيانات.',
        'استدعاء فريق الاستجابة للحوادث.',
        'إخطار الفريق القانوني/الامتثال إذا تم الوصول إلى بيانات حساسة.',
    ],
    'BENIGN': [
        'لا يلزم اتخاذ أي إجراء فوري.',
        'الاستمرار في المراقبة الروتينية.',
        'المراجعة الدورية لأي تغيرات في الأنماط.',
    ],
}

@app.route('/api/playbook/<path:attack_type>')
@login_required
def api_playbook(attack_type):
    lang = session.get('lang', cfg('language', 'en'))
    book = PLAYBOOKS_AR if lang == 'ar' else PLAYBOOKS
    # Fuzzy match
    steps = None
    for k, v in book.items():
        if k.lower() == attack_type.lower() or k.lower() in attack_type.lower() or attack_type.lower() in k.lower():
            steps = v
            break
    if steps is None:
        if lang == 'ar':
            steps = ['لا يوجد كتيب تشغيل خاص. اتبع إجراءات الاستجابة للحوادث العامة.',
                     'توثيق الحادثة.',
                     'عزل الأنظمة المتأثرة.',
                     'إخطار فريق الأمن.',
                     'الحفاظ على الأدلة.',
                     'المعالجة والتعافي.']
        else:
            steps = ['No specific playbook available. Follow general IR procedures.',
                     '1. Document the incident.',
                     '2. Isolate affected systems.',
                     '3. Notify security team.',
                     '4. Preserve evidence.',
                     '5. Remediate and recover.']
    return jsonify(attack_type=attack_type, steps=steps)

# ── Case SLA Tracking (extend /cases route) ───────────────────────────────────
@app.route('/cases/archive')
@login_required
def case_archive():
    from collections import defaultdict
    auto_archive_closed_cases()
    me = session.get('user', '')
    roles = get_roles()
    role = roles.get(me, 'analyst')
    is_admin_user = role in ('admin', 'cc_admin')
    is_admin = role == 'admin'
    is_cc_admin = role == 'cc_admin'
    with _CASES_LOCK:
        all_cases = load_cases()
    archived = [c for c in all_cases if c.get('archived') and c.get('status') == 'closed']
    if not is_admin_user:
        archived = [c for c in archived if c.get('analyst') == me or me in get_assignees(c)]
    grouped = defaultdict(lambda: defaultdict(list))
    for c in archived:
        close_str = c.get('closed_at') or c.get('cc_closed_at') or c.get('analyst_closed_at') or c.get('created', '')
        try:
            close_dt = datetime.fromisoformat(close_str)
        except Exception:
            close_dt = datetime.now()
        grouped[close_dt.year][close_dt.month].append(c)
    sorted_grouped = {}
    for year in sorted(grouped.keys(), reverse=True):
        sorted_grouped[year] = {}
        for month in sorted(grouped[year].keys(), reverse=True):
            sorted_grouped[year][month] = sorted(grouped[year][month],
                                                  key=lambda x: x.get('closed_at') or x.get('cc_closed_at') or '',
                                                  reverse=True)
    month_names = {1:'January',2:'February',3:'March',4:'April',5:'May',6:'June',
                   7:'July',8:'August',9:'September',10:'October',11:'November',12:'December'}
    month_names_ar = {1:'يناير',2:'فبراير',3:'مارس',4:'أبريل',5:'مايو',6:'يونيو',
                      7:'يوليو',8:'أغسطس',9:'سبتمبر',10:'أكتوبر',11:'نوفمبر',12:'ديسمبر'}
    return render_template('cases_archive.html',
                           grouped=sorted_grouped,
                           month_names=month_names,
                           month_names_ar=month_names_ar,
                           total_archived=len(archived),
                           is_admin=is_admin,
                           is_cc_admin=is_cc_admin,
                           get_assignees=get_assignees)

@app.route('/cases')
@login_required
def cases():
    auto_archive_closed_cases()
    me = session.get('user', '')
    roles = get_roles()
    is_admin_user = roles.get(me) in ('admin', 'cc_admin')
    with _CASES_LOCK:
        all_cases = load_cases()
    visible = all_cases if is_admin_user else [c for c in all_cases if c.get('analyst') == me or me in get_assignees(c)]
    # Exclude archived cases from main view
    visible = [c for c in visible if not c.get('archived')]
    now = datetime.now()
    for c in visible:
        try:
            created = datetime.fromisoformat(c.get('created', now.isoformat()))
        except Exception:
            created = now
        hours_open = (now - created).total_seconds() / 3600
        try:
            sla_hours = float(c.get('sla_hours') or 24)
        except (ValueError, TypeError):
            sla_hours = 24.0
        c['hours_open']   = round(hours_open, 1)
        c['sla_breached'] = (c.get('status') != 'closed') and (hours_open > sla_hours)
        c['sla_hours']    = sla_hours
    config = get_config()
    is_admin = roles.get(me) == 'admin'
    is_cc_admin = roles.get(me) == 'cc_admin'
    available_assignees = _available_assignees_for(me, roles, config)
    can_assign = roles.get(me) in ('admin', 'cc_admin')
    managed_analysts = {u for u, mgr in config.get('managed_by', {}).items() if mgr == me} if is_cc_admin else set()
    # Count archived for the archive badge (reuse already-loaded all_cases)
    all_archived = [c for c in all_cases if c.get('archived')]
    if not is_admin_user:
        all_archived = [c for c in all_archived if c.get('analyst') == me or me in get_assignees(c)]
    return render_template('cases.html', cases=visible, available_assignees=available_assignees,
                           can_assign=can_assign, is_admin=is_admin, is_cc_admin=is_cc_admin,
                           managed_analysts=managed_analysts, get_assignees=get_assignees,
                           current_user=me, archived_count=len(all_archived))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5050, threaded=True)
