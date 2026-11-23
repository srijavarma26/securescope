"""
SecureScope — Database Seed Script
Executes initial real baseline scans for the authorized demo test targets
and populates securescope.db with persistent scan history and findings.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import database
from scanner import SecurityScanner
from reports import generate_pdf_report
from datetime import datetime

def seed_demo_scans():
    database.init_db()
    existing_scans = database.get_all_scans()
    if existing_scans:
        print(f"Database already contains {len(existing_scans)} scans. Skipping seed.")
        return

    targets = [
        ('SCN-9042', 'DemoShop', 'https://demo-shop.local'),
        ('SCN-9041', 'SecurePortal', 'https://portal-demo.local'),
        ('SCN-9040', 'StudentCMS', 'https://cms-demo.local'),
        ('SCN-9039', 'TestBank', 'https://bank-demo.local'),
    ]

    print("Seeding initial baseline scans into SQLite database...")
    for scan_id, app_name, target_url in targets:
        print(f"Scanning target {app_name} ({target_url})...")
        database.create_scan_record(scan_id, app_name, target_url)
        database.add_target(app_name, target_url, 1)

        scanner = SecurityScanner(target_url=target_url, app_name=app_name, profile="Full")
        results = scanner.run_full_scan(scan_id)

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

        for f in results['findings']:
            database.insert_vulnerability(f)

        pdf_path = generate_pdf_report(results, results['findings'], "Executive Security Report")
        report_id = f"REP-{scan_id[-4:]}"
        database.insert_report(
            report_id=report_id,
            scan_id=scan_id,
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M'),
            report_type="Executive Security Report",
            report_summary=f"Automated baseline scan for {app_name} identified {results['total_findings']} vulnerabilities with risk level {results['risk_level']}.",
            pdf_path=pdf_path
        )
        print(f"  -> {app_name} scan saved: {results['total_findings']} vulnerabilities, Risk: {results['risk_level']} ({results['risk_score']}/100)")

    print("Baseline database seeding completed successfully!")

if __name__ == '__main__':
    seed_demo_scans()
