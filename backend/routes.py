"""
SecureScope — REST API Routes
Implements endpoints for target management, scanning, vulnerability tracking,
dashboard metrics, and PDF report downloads.
"""

import os
import time
import threading
from datetime import datetime
from flask import Blueprint, request, jsonify, send_file, current_app
import database
from scanner import SecurityScanner
from reports import generate_pdf_report

api_bp = Blueprint('api', __name__)

# In-memory registry for tracking active background scans & logs
ACTIVE_SCANS = {}

def execute_background_scan(scan_id, app_name, target_url, profile):
    """Worker function executed inside a background thread."""
    scan_state = ACTIVE_SCANS[scan_id]

    def log_tracker(msg, msg_type="info"):
        now_time = datetime.now().strftime("%H:%M:%S")
        scan_state['logs'].append({
            'time': now_time,
            'message': msg,
            'type': msg_type
        })
        
        # Heuristic stage & progress updates based on log messages
        if "[STAGE 1/5]" in msg:
            scan_state['stage'] = 1
            scan_state['progress'] = 15
        elif "[STAGE 2/5]" in msg:
            scan_state['stage'] = 2
            scan_state['progress'] = 35
        elif "[STAGE 3/5]" in msg:
            scan_state['stage'] = 3
            scan_state['progress'] = 60
        elif "[STAGE 4/5]" in msg:
            scan_state['stage'] = 4
            scan_state['progress'] = 85
        elif "[STAGE 5/5]" in msg:
            scan_state['stage'] = 5
            scan_state['progress'] = 95

    try:
        scanner = SecurityScanner(
            target_url=target_url,
            app_name=app_name,
            profile=profile,
            log_callback=log_tracker
        )
        
        results = scanner.run_full_scan(scan_id)

        # Persist results in SQLite database
        database.update_scan_record(
            scan_id=scan_id,
            status='Completed',
            duration=results['duration'],
            total_vulns=results['total_findings'],
            risk_score=results['risk_score'],
            risk_level=results['risk_level'],
            critical=results['critical'],
            high=results['high'],
            medium=results['medium'],
            low=results['low']
        )

        for finding in results['findings']:
            database.insert_vulnerability(finding)

        # Automatically generate default executive PDF report
        try:
            pdf_path = generate_pdf_report(results, results['findings'], "Executive Security Report")
            report_id = f"REP-{scan_id[-4:]}"
            database.insert_report(
                report_id=report_id,
                scan_id=scan_id,
                report_date=datetime.now().strftime('%Y-%m-%d %H:%M'),
                report_type="Executive Security Report",
                report_summary=f"Automated scan for {app_name} identified {results['total_findings']} vulnerabilities with risk level {results['risk_level']}.",
                pdf_path=pdf_path
            )
        except Exception as e:
            log_tracker(f"Report generation note: {str(e)}", "warn")

        scan_state['progress'] = 100
        scan_state['stage'] = 5
        scan_state['status'] = 'Completed'
        scan_state['results'] = results

    except Exception as e:
        scan_state['status'] = 'Failed'
        scan_state['error'] = str(e)
        log_tracker(f"Scan aborted with error: {str(e)}", "alert")
        database.update_scan_record(
            scan_id=scan_id,
            status='Failed',
            duration='0s',
            total_vulns=0,
            risk_score=0,
            risk_level='N/A',
            critical=0,
            high=0,
            medium=0,
            low=0
        )

# ----------------- 1. START SCAN (POST /api/scan) -----------------
@api_bp.route('/scan', methods=['POST'])
def start_scan():
    data = request.get_json() or {}
    target_url = data.get('target_url', '').strip()
    app_name = data.get('app_name', '').strip() or 'Web Application'
    profile = data.get('profile', 'Full')
    authorization = data.get('authorization', True)

    if not target_url:
        return jsonify({'error': 'Target URL is required.'}), 400

    if not authorization:
        return jsonify({'error': 'Explicit authorization confirmation is required to perform scanning.'}), 403

    # Generate unique scan ID
    import random
    scan_id = f"SCN-{random.randint(1000, 9999)}"

    # Record in database
    database.create_scan_record(scan_id, app_name, target_url)
    database.add_target(app_name, target_url, 1)

    # Initialize in-memory progress tracker
    ACTIVE_SCANS[scan_id] = {
        'scan_id': scan_id,
        'app_name': app_name,
        'target_url': target_url,
        'status': 'In Progress',
        'progress': 5,
        'stage': 1,
        'logs': [
            {'time': datetime.now().strftime("%H:%M:%S"), 'message': f"[SYSTEM] Initialized security analysis job {scan_id} for {app_name}", 'type': 'info'}
        ],
        'error': None,
        'results': None
    }

    # Dispatch asynchronous background thread
    scan_thread = threading.Thread(
        target=execute_background_scan,
        args=(scan_id, app_name, target_url, profile),
        daemon=True
    )
    scan_thread.start()

    return jsonify({
        'status': 'In Progress',
        'scan_id': scan_id,
        'app_name': app_name,
        'target_url': target_url,
        'message': f'Analysis job {scan_id} initiated.'
    }), 202

# ----------------- 2. SCAN PROGRESS (GET /api/scan/progress/<scan_id>) -----------------
@api_bp.route('/scan/progress/<scan_id>', methods=['GET'])
def get_scan_progress(scan_id):
    if scan_id in ACTIVE_SCANS:
        state = ACTIVE_SCANS[scan_id]
        return jsonify({
            'scan_id': scan_id,
            'status': state['status'],
            'progress': state['progress'],
            'stage': state['stage'],
            'logs': state['logs'],
            'error': state['error'],
            'results': state['results']
        })

    # If scan is already completed and in DB
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({'error': 'Scan ID not found'}), 404

    vulns = database.get_vulnerabilities_by_scan_id(scan_id)
    return jsonify({
        'scan_id': scan_id,
        'status': scan['scan_status'],
        'progress': 100 if scan['scan_status'] == 'Completed' else 0,
        'stage': 5 if scan['scan_status'] == 'Completed' else 1,
        'logs': [{'time': '', 'message': 'Scan records retrieved from persistent storage.', 'type': 'info'}],
        'error': None if scan['scan_status'] == 'Completed' else 'Scan failed or was interrupted.',
        'results': {
            'scan_id': scan['scan_id'],
            'app_name': scan['app_name'],
            'target_url': scan['target_url'],
            'duration': scan['duration'],
            'total_findings': scan['total_vulnerabilities'],
            'risk_score': scan['risk_score'],
            'risk_level': scan['risk_level'],
            'critical': scan['critical_count'],
            'high': scan['high_count'],
            'medium': scan['medium_count'],
            'low': scan['low_count'],
            'findings': vulns
        }
    })

# ----------------- 3. RETRIEVE ALL SCANS (GET /api/scans) -----------------
@api_bp.route('/scans', methods=['GET'])
def list_scans():
    scans = database.get_all_scans()
    return jsonify(scans)

# ----------------- 4. RETRIEVE INDIVIDUAL SCAN (GET /api/scans/<scan_id>) -----------------
@api_bp.route('/scans/<scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({'error': 'Scan ID not found'}), 404

    vulns = database.get_vulnerabilities_by_scan_id(scan_id)
    return jsonify({
        'scan': scan,
        'vulnerabilities': vulns
    })

# ----------------- 5. DASHBOARD STATS (GET /api/dashboard) -----------------
@api_bp.route('/dashboard', methods=['GET'])
def dashboard_stats():
    stats = database.get_dashboard_stats()
    return jsonify(stats)

# ----------------- 6. VULNERABILITIES LIST (GET /api/vulnerabilities) -----------------
@api_bp.route('/vulnerabilities', methods=['GET'])
def list_all_vulnerabilities():
    scan_id = request.args.get('scan_id')
    severity = request.args.get('severity')
    status = request.args.get('status')
    search = request.args.get('search', '').lower()

    if scan_id:
        vulns = database.get_vulnerabilities_by_scan_id(scan_id)
    else:
        vulns = database.get_all_vulnerabilities()

    if severity and severity != 'ALL':
        vulns = [v for v in vulns if v.get('severity', '').lower() == severity.lower()]

    if status and status != 'ALL':
        vulns = [v for v in vulns if v.get('status', '').lower() == status.lower()]

    if search:
        vulns = [
            v for v in vulns 
            if search in v.get('vuln_name', '').lower() 
            or search in v.get('vuln_id', '').lower() 
            or search in v.get('affected_url', '').lower()
        ]

    return jsonify(vulns)

# ----------------- 7. VULNERABILITIES FOR SCAN (GET /api/vulnerabilities/<scan_id>) -----------------
@api_bp.route('/vulnerabilities/<scan_id>', methods=['GET'])
def get_vulnerabilities_for_scan(scan_id):
    vulns = database.get_vulnerabilities_by_scan_id(scan_id)
    return jsonify(vulns)

# ----------------- 8. UPDATE VULNERABILITY STATUS (PATCH /api/vulnerabilities/<vuln_id>/status) -----------------
@api_bp.route('/vulnerabilities/<vuln_id>/status', methods=['PATCH', 'POST'])
def update_status(vuln_id):
    data = request.get_json() or {}
    new_status = data.get('status')

    if not new_status:
        # Default toggle between Open and Resolved
        conn = database.get_db_connection()
        row = conn.execute('SELECT status FROM Vulnerabilities WHERE vuln_id = ?', (vuln_id,)).fetchone()
        conn.close()
        if not row:
            return jsonify({'error': 'Vulnerability not found'}), 404
        new_status = 'Resolved' if row['status'] == 'Open' else 'Open'

    updated = database.update_vulnerability_status(vuln_id, new_status)
    if not updated:
        return jsonify({'error': 'Vulnerability not found or unchanged'}), 404

    return jsonify({'vuln_id': vuln_id, 'status': new_status, 'message': f'Status updated to {new_status}'})

# ----------------- 9. GET REPORT INFO (GET /api/reports/<scan_id>) -----------------
@api_bp.route('/reports/<scan_id>', methods=['GET'])
def get_report_info(scan_id):
    report = database.get_report_by_scan_id(scan_id)
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({'error': 'Scan ID not found'}), 404

    vulns = database.get_vulnerabilities_by_scan_id(scan_id)

    return jsonify({
        'report': report,
        'scan': scan,
        'vulnerabilities': vulns
    })

# ----------------- 10. DOWNLOAD PDF REPORT (GET /api/reports/<scan_id>/download) -----------------
@api_bp.route('/reports/<scan_id>/download', methods=['GET'])
def download_pdf_report(scan_id):
    report_type = request.args.get('type', 'Executive Security Report')
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({'error': 'Scan ID not found'}), 404

    vulns = database.get_vulnerabilities_by_scan_id(scan_id)

    # Generate or retrieve PDF report
    pdf_path = generate_pdf_report(scan, vulns, report_type)

    if not os.path.exists(pdf_path):
        return jsonify({'error': 'PDF generation failed'}), 500

    filename = f"SecureScope_{scan.get('app_name', 'Report')}_{scan_id}.pdf"
    return send_file(
        pdf_path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )

# ----------------- 11. LIST AUTHORIZED TARGETS (GET /api/targets) -----------------
@api_bp.route('/targets', methods=['GET'])
def list_targets():
    targets = database.get_all_targets()
    return jsonify(targets)
