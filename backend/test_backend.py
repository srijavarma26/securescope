"""
SecureScope — Backend & Integration Test Suite
Verifies all REST API endpoints, SQLite persistence, scanning engine, and report generation.
"""

import os
import sys
import json
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
import database

def run_tests():
    print("==================================================================")
    print("  SECURESCOPE TEST SUITE — VERIFYING ALL BACKEND CAPABILITIES")
    print("==================================================================")
    
    client = app.test_client()
    passed = 0
    failed = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, failed
        if condition:
            print(f"  [PASS] {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name} - {details}")
            failed += 1

    # 1. Test Static & Frontend Serving
    print("\n--- 1. Testing Frontend Route Serving ---")
    res = client.get('/')
    assert_test("GET / (Index HTML)", res.status_code == 200 and b"SecureScope" in res.data)

    res = client.get('/styles.css')
    assert_test("GET /styles.css (CSS Assets)", res.status_code == 200 and len(res.data) > 1000)

    res = client.get('/app.js')
    assert_test("GET /app.js (JavaScript Controller)", res.status_code == 200 and b"SecureScope" in res.data)

    # 2. Test GET /api/dashboard
    print("\n--- 2. Testing Dashboard Statistics API ---")
    res = client.get('/api/dashboard')
    assert_test("GET /api/dashboard status 200", res.status_code == 200)
    data = json.loads(res.data)
    assert_test("Dashboard contains total_scans", 'total_scans' in data and data['total_scans'] >= 4)
    assert_test("Dashboard contains total_findings", 'total_findings' in data and data['total_findings'] >= 10)
    assert_test("Dashboard contains severity distribution", 'critical' in data and 'high' in data and 'medium' in data and 'low' in data)
    assert_test("Dashboard contains risk score & level", 'overall_risk_score' in data and 'overall_risk_level' in data)

    # 3. Test GET /api/scans
    print("\n--- 3. Testing Scan History API ---")
    res = client.get('/api/scans')
    assert_test("GET /api/scans status 200", res.status_code == 200)
    scans = json.loads(res.data)
    assert_test("Scans list returned from SQLite", isinstance(scans, list) and len(scans) >= 4)
    first_scan = scans[0]
    sample_scan_id = first_scan['scan_id']

    # 4. Test GET /api/scans/<scan_id>
    print(f"\n--- 4. Testing Individual Scan Details for {sample_scan_id} ---")
    res = client.get(f'/api/scans/{sample_scan_id}')
    assert_test(f"GET /api/scans/{sample_scan_id} status 200", res.status_code == 200)
    scan_detail = json.loads(res.data)
    assert_test("Scan details contains scan record", 'scan' in scan_detail and scan_detail['scan']['scan_id'] == sample_scan_id)
    assert_test("Scan details contains vulnerabilities array", 'vulnerabilities' in scan_detail and len(scan_detail['vulnerabilities']) > 0)

    # 5. Test GET /api/vulnerabilities
    print("\n--- 5. Testing Vulnerability Management APIs ---")
    res = client.get('/api/vulnerabilities')
    assert_test("GET /api/vulnerabilities status 200", res.status_code == 200)
    vulns = json.loads(res.data)
    assert_test("Vulnerabilities list populated", len(vulns) >= 10)
    sample_vuln_id = vulns[0]['vuln_id']
    sample_status = vulns[0]['status']

    # 6. Test PATCH /api/vulnerabilities/<vuln_id>/status
    print(f"\n--- 6. Testing Status Toggle for {sample_vuln_id} ---")
    res = client.patch(f'/api/vulnerabilities/{sample_vuln_id}/status', json={})
    assert_test(f"PATCH /api/vulnerabilities/{sample_vuln_id}/status 200", res.status_code == 200)
    patch_data = json.loads(res.data)
    expected_new_status = 'Resolved' if sample_status == 'Open' else 'Open'
    assert_test("Status toggled correctly in database", patch_data.get('status') == expected_new_status)

    # Toggle back to maintain test consistency
    client.patch(f'/api/vulnerabilities/{sample_vuln_id}/status', json={'status': sample_status})

    # 7. Test POST /api/scan & Progress Polling
    print("\n--- 7. Testing New Security Analysis Scan Flow ---")
    new_scan_payload = {
        'app_name': 'TestSuiteApp',
        'target_url': 'https://demo-shop.local',
        'profile': 'Full',
        'authorization': True
    }
    res = client.post('/api/scan', json=new_scan_payload)
    assert_test("POST /api/scan accepted (202)", res.status_code == 202)
    scan_resp = json.loads(res.data)
    created_scan_id = scan_resp.get('scan_id')
    assert_test("Scan ID returned", created_scan_id is not None)

    # Poll progress for completion
    completed = False
    for attempt in range(15):
        time.sleep(0.5)
        prog_res = client.get(f'/api/scan/progress/{created_scan_id}')
        assert prog_res.status_code == 200
        prog_data = json.loads(prog_res.data)
        if prog_data['status'] == 'Completed':
            completed = True
            break

    assert_test("Background scan completed successfully", completed)
    assert_test("Scan findings saved to SQLite", prog_data.get('results') is not None)
    assert_test("Stage 5 reached with 100% progress", prog_data['stage'] == 5 and prog_data['progress'] == 100)

    # 8. Test Reports & PDF Download
    print(f"\n--- 8. Testing Report Info & PDF Download for {created_scan_id} ---")
    res = client.get(f'/api/reports/{created_scan_id}')
    assert_test(f"GET /api/reports/{created_scan_id} status 200", res.status_code == 200)

    res = client.get(f'/api/reports/{created_scan_id}/download')
    assert_test("GET /api/reports/.../download status 200", res.status_code == 200)
    assert_test("PDF content returned with application/pdf header", res.headers.get('Content-Type') == 'application/pdf')
    assert_test("Valid PDF binary signature (%PDF-)", res.data.startswith(b'%PDF-'))

    print("\n==================================================================")
    print(f"  TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("==================================================================")
    return failed == 0

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
