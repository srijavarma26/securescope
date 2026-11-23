"""
SecureScope — SQLite Database Module
Manages persistence for Scan History, Targets, Vulnerabilities, and Reports.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'securescope.db')

def get_db_connection():
    """Returns a connection to the SQLite database with row_factory set to Row."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema and creates all required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Scan_History
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Scan_History (
            scan_id TEXT PRIMARY KEY,
            app_name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            duration TEXT DEFAULT '0s',
            scan_status TEXT DEFAULT 'In Progress',
            total_vulnerabilities INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'LOW',
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0
        )
    ''')

    # 2. Scan_Targets
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Scan_Targets (
            target_id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL,
            target_url TEXT NOT NULL UNIQUE,
            authorization_confirmed INTEGER DEFAULT 1,
            created_date TEXT NOT NULL
        )
    ''')

    # 3. Vulnerabilities
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Vulnerabilities (
            vuln_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            vuln_name TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT DEFAULT 'High',
            affected_url TEXT NOT NULL,
            description TEXT NOT NULL,
            impact TEXT NOT NULL,
            remediation TEXT NOT NULL,
            status TEXT DEFAULT 'Open',
            FOREIGN KEY (scan_id) REFERENCES Scan_History (scan_id) ON DELETE CASCADE
        )
    ''')

    # 4. Reports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Reports (
            report_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            report_date TEXT NOT NULL,
            report_type TEXT DEFAULT 'Executive Security Report',
            report_summary TEXT NOT NULL,
            pdf_path TEXT,
            FOREIGN KEY (scan_id) REFERENCES Scan_History (scan_id) ON DELETE CASCADE
        )
    ''')

    # Pre-populate authorized test targets if not already present
    cursor.execute('SELECT COUNT(*) FROM Scan_Targets')
    if cursor.fetchone()[0] == 0:
        initial_targets = [
            ('DemoShop', 'https://demo-shop.local', 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('SecurePortal', 'https://portal-demo.local', 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('StudentCMS', 'https://cms-demo.local', 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('TestBank', 'https://bank-demo.local', 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        ]
        cursor.executemany('''
            INSERT INTO Scan_Targets (app_name, target_url, authorization_confirmed, created_date)
            VALUES (?, ?, ?, ?)
        ''', initial_targets)

    conn.commit()
    conn.close()

# ----------------- SCAN HISTORY OPERATIONS -----------------

def create_scan_record(scan_id, app_name, target_url):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M')
    cursor.execute('''
        INSERT INTO Scan_History (scan_id, app_name, target_url, scan_date, scan_status)
        VALUES (?, ?, ?, ?, 'In Progress')
    ''', (scan_id, app_name, target_url, now_str))
    conn.commit()
    conn.close()

def update_scan_record(scan_id, status, duration, total_vulns, risk_score, risk_level, critical, high, medium, low):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE Scan_History
        SET scan_status = ?, duration = ?, total_vulnerabilities = ?, risk_score = ?, risk_level = ?,
            critical_count = ?, high_count = ?, medium_count = ?, low_count = ?
        WHERE scan_id = ?
    ''', (status, duration, total_vulns, risk_score, risk_level, critical, high, medium, low, scan_id))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Scan_History ORDER BY scan_date DESC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Scan_History WHERE scan_id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# ----------------- VULNERABILITIES OPERATIONS -----------------

def insert_vulnerability(vuln):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Ensure remediation is stored as JSON string
    remediation_str = vuln.get('remediation', '[]')
    if isinstance(remediation_str, list):
        remediation_str = json.dumps(remediation_str)

    cursor.execute('''
        INSERT OR REPLACE INTO Vulnerabilities 
        (vuln_id, scan_id, vuln_name, category, severity, confidence, affected_url, description, impact, remediation, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        vuln['vuln_id'],
        vuln['scan_id'],
        vuln['vuln_name'],
        vuln.get('category', 'General'),
        vuln.get('severity', 'Medium'),
        vuln.get('confidence', 'High'),
        vuln['affected_url'],
        vuln.get('description', ''),
        vuln.get('impact', ''),
        remediation_str,
        vuln.get('status', 'Open')
    ))
    conn.commit()
    conn.close()

def get_vulnerabilities_by_scan_id(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Vulnerabilities WHERE scan_id = ? ORDER BY CASE severity WHEN "Critical" THEN 1 WHEN "High" THEN 2 WHEN "Medium" THEN 3 ELSE 4 END', (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        r = dict(row)
        try:
            r['remediation'] = json.loads(r['remediation'])
        except Exception:
            r['remediation'] = [r['remediation']] if r['remediation'] else []
        results.append(r)
    return results

def get_all_vulnerabilities():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT v.*, s.app_name 
        FROM Vulnerabilities v
        LEFT JOIN Scan_History s ON v.scan_id = s.scan_id
        ORDER BY CASE v.severity WHEN "Critical" THEN 1 WHEN "High" THEN 2 WHEN "Medium" THEN 3 ELSE 4 END
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        r = dict(row)
        try:
            r['remediation'] = json.loads(r['remediation'])
        except Exception:
            r['remediation'] = [r['remediation']] if r['remediation'] else []
        results.append(r)
    return results

def update_vulnerability_status(vuln_id, new_status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE Vulnerabilities SET status = ? WHERE vuln_id = ?', (new_status, vuln_id))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated

# ----------------- REPORTS OPERATIONS -----------------

def insert_report(report_id, scan_id, report_date, report_type, report_summary, pdf_path):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO Reports (report_id, scan_id, report_date, report_type, report_summary, pdf_path)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (report_id, scan_id, report_date, report_type, report_summary, pdf_path))
    conn.commit()
    conn.close()

def get_report_by_scan_id(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Reports WHERE scan_id = ? ORDER BY report_date DESC LIMIT 1', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_reports():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, s.app_name, s.target_url, s.risk_score, s.risk_level
        FROM Reports r
        JOIN Scan_History s ON r.scan_id = s.scan_id
        ORDER BY r.report_date DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# ----------------- TARGETS OPERATIONS -----------------

def get_all_targets():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Scan_Targets ORDER BY created_date DESC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def add_target(app_name, target_url, authorized=1):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        INSERT OR IGNORE INTO Scan_Targets (app_name, target_url, authorization_confirmed, created_date)
        VALUES (?, ?, ?, ?)
    ''', (app_name, target_url, authorized, now_str))
    conn.commit()
    conn.close()

# ----------------- DASHBOARD STATISTICS -----------------

def get_dashboard_stats():
    """Calculates all live dashboard statistics directly from SQLite tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM Scan_History WHERE scan_status = "Completed"')
    total_scans = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(DISTINCT app_name) FROM Scan_History')
    apps_analyzed = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM Vulnerabilities')
    total_findings = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM Vulnerabilities WHERE severity = "Critical"')
    critical = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM Vulnerabilities WHERE severity = "High"')
    high = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM Vulnerabilities WHERE severity = "Medium"')
    medium = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM Vulnerabilities WHERE severity IN ("Low", "Informational")')
    low = cursor.fetchone()[0]

    # Calculate overall risk score
    # Formula: weighted score normalized out of 100
    if total_findings == 0:
        overall_score = 0
        overall_level = 'SECURE'
    else:
        raw_score = (critical * 30) + (high * 15) + (medium * 7) + (low * 2)
        overall_score = min(100, max(10, int(raw_score)))
        if critical > 0 or overall_score >= 70:
            overall_level = 'CRITICAL' if critical >= 2 else 'HIGH'
        elif high > 0 or overall_score >= 40:
            overall_level = 'MEDIUM'
        else:
            overall_level = 'LOW'

    # Recent scans (latest 5)
    cursor.execute('''
        SELECT scan_id, app_name, target_url, scan_date, duration, total_vulnerabilities, risk_level, risk_score, scan_status
        FROM Scan_History
        ORDER BY scan_date DESC
        LIMIT 5
    ''')
    recent_scans = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        'total_scans': total_scans,
        'apps_analyzed': apps_analyzed,
        'total_findings': total_findings,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'overall_risk_score': overall_score,
        'overall_risk_level': overall_level,
        'recent_scans': recent_scans,
        'distribution': {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        }
    }
