# SecureScope — Web Application Security Analysis System

> **A full-stack, automated security analysis platform for authorized web applications, featuring non-destructive vulnerability detection, OWASP ZAP passive baseline integration, risk assessment, and executive PDF security reporting.**

---

## 1. Overview & Abstract

Modern web applications are increasingly vulnerable to threat vectors such as **Cross-Site Scripting (XSS)**, **Injection flaws**, and **Access-Control deficiencies**. Manual identification of these security gaps requires specialized knowledge and significant time.

**SecureScope** bridges this gap by providing an end-to-end security assessment system. It accepts an authorized target URL, conducts non-destructive vulnerability analysis, evaluates response headers, queries OWASP ZAP passive scanning rules, classifies findings by severity, and presents actionable remediation guidance within an interactive single-page dashboard.

---

## 2. Key Features

- **Target URL Management & Scope Isolation:**
  - Automated URL normalization and reachability verification.
  - SSRF protection rejecting cloud metadata (e.g. `169.254.169.254`) and unauthorized internal network ranges.
  - Strict host-boundary scope enforcement during discovery and scanning.

- **Non-Destructive Vulnerability Detection:**
  - **XSS Detection:** Form and input parameter inspection, safe benign canary reflection testing, Content-Security-Policy (CSP) posture auditing.
  - **Injection Indicators:** Safe error-response pattern analysis for database syntax leaks and unhandled boundary inputs without altering backend data.
  - **Access-Control & Header Analysis:** Evaluates missing or permissive headers (`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`), CORS wildcard configurations (`*`), and insecure cookie flags (`HttpOnly`, `Secure`, `SameSite`).

- **OWASP ZAP Baseline Integration:**
  - Native connectivity to OWASP ZAP API daemon (default `http://127.0.0.1:8080`).
  - Collects passive security alerts, extracting CWE names, descriptions, risk levels, and remediation steps.
  - Graceful fallback to SecureScope's native passive inspection engine when the ZAP daemon is offline.

- **Persistent SQLite Database (`securescope.db`):**
  - Retains all scan histories, target profiles, identified vulnerabilities, and generated reports across restarts.
  - Zero hardcoded mock numbers—all metrics, counters, and charts dynamically reflect SQLite database records.

- **Real-Time Asynchronous Scanning:**
  - Background thread execution ensures the Flask server remains non-blocking during scans.
  - Real-time polling updates progress percentages, multi-stage indicators (Stages 1–5), and live terminal diagnostic logs.

- **Executive & Technical PDF Report Generation:**
  - Automated PDF report creation powered by ReportLab.
  - Includes executive summaries, severity distribution tables, individual finding breakdowns, and OWASP ASVS-aligned remediation steps.

---

## 3. Technology Stack

| Layer | Technologies |
|---|---|
| **Backend Framework** | Python 3.10+, Flask, Flask-CORS |
| **HTTP & Parsing** | Requests, BeautifulSoup4 (BS4) |
| **Security Scanning** | OWASP ZAP REST API (`python-owasp-zap-v2.4`), Custom Heuristic Engine |
| **Database** | SQLite3 (`securescope.db`) |
| **PDF Reporting** | ReportLab |
| **Frontend** | Vanilla JavaScript (ES6+), Modern HTML5, Responsive CSS3, Chart.js, FontAwesome |

---

## 4. Project Folder Structure

```
securescope/
│
├── frontend/                     # Existing single-page web frontend
│   ├── index.html                # Complete dashboard & view layout
│   ├── styles.css                # Dark-themed cyber dashboard styling
│   └── app.js                    # Full-stack API controller & event handlers
│
├── backend/                      # Python Flask backend
│   ├── app.py                    # Server entrypoint & static frontend server
│   ├── routes.py                 # REST API endpoints (/api/scan, /api/dashboard, etc.)
│   ├── scanner.py                # Core security analysis engine (XSS, Injection, Access-Control)
│   ├── zap_scanner.py            # OWASP ZAP passive baseline scanner integration
│   ├── database.py               # SQLite schema & persistence operations
│   ├── reports.py                # ReportLab PDF generator
│   ├── seed_db.py                # Initial baseline scans seed script
│   ├── test_backend.py           # Comprehensive integration & endpoint test suite
│   ├── requirements.txt          # Python dependencies
│   ├── securescope.db            # SQLite persistent database file
│   └── reports/                  # Generated PDF reports storage directory
│
└── README.md                     # Project documentation & operational guide
```

---

## 5. Database Schema (`securescope.db`)

1. **`Scan_History`**:
   - `scan_id` (TEXT, PK): Unique scan identifier (e.g., `SCN-1001`).
   - `app_name` (TEXT): Name of target application.
   - `target_url` (TEXT): Target host or endpoint.
   - `scan_date` (TEXT): Timestamp of assessment.
   - `duration` (TEXT): Total duration (e.g., `42s`).
   - `scan_status` (TEXT): `Completed`, `In Progress`, or `Failed`.
   - `total_vulnerabilities` (INTEGER): Count of findings.
   - `risk_score` (INTEGER): Weighted score out of 100.
   - `risk_level` (TEXT): `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
   - `critical_count`, `high_count`, `medium_count`, `low_count` (INTEGER).

2. **`Scan_Targets`**:
   - `target_id` (INTEGER, PK AUTOINCREMENT)
   - `app_name` (TEXT)
   - `target_url` (TEXT UNIQUE)
   - `authorization_confirmed` (INTEGER)
   - `created_date` (TEXT)

3. **`Vulnerabilities`**:
   - `vuln_id` (TEXT, PK): E.g., `VUL-9042-01`.
   - `scan_id` (TEXT, FK -> `Scan_History.scan_id`).
   - `vuln_name` (TEXT): Vulnerability title.
   - `category` (TEXT): XSS, Injection, Access-Control, etc.
   - `severity` (TEXT): `Critical`, `High`, `Medium`, `Low`, `Informational`.
   - `confidence` (TEXT): `High`, `Medium`, `Low`.
   - `affected_url` (TEXT): Specific path/parameter.
   - `description` (TEXT): Detailed vulnerability description.
   - `impact` (TEXT): Security risk and threat consequence.
   - `remediation` (TEXT): JSON array of remediation steps.
   - `status` (TEXT): `Open` or `Resolved`.

4. **`Reports`**:
   - `report_id` (TEXT, PK): E.g., `REP-9042`.
   - `scan_id` (TEXT, FK -> `Scan_History.scan_id`).
   - `report_date` (TEXT)
   - `report_type` (TEXT)
   - `report_summary` (TEXT)
   - `pdf_path` (TEXT)

---

## 6. Installation & Setup Instructions

### Prerequisites
- Python 3.10 or higher
- `pip` (Python package installer)
- Git (optional)

### Step 1: Clone or Navigate to the Project
```bash
cd securescope/backend
```

### Step 2: Create and Activate Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Initialize and Seed Baseline Database (Optional)
The database initializes automatically when the backend starts. To populate baseline historical records for the demo applications (DemoShop, SecurePortal, StudentCMS, TestBank):
```bash
python seed_db.py
```

---

## 7. Running the Application

### Option A: Unified Full-Stack Server (Recommended)
Run the Flask server. It will serve both the backend REST APIs and the frontend user interface from a single port:
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000/
```

### Option B: Standalone Frontend with API Backend
If you prefer running the frontend via VS Code Live Server or hosting it on Vercel:
1. Start the Flask backend:
   ```bash
   python backend/app.py
   ```
2. Open `frontend/index.html` via Live Server (`http://127.0.0.1:5500`) or deploy to Vercel.
   - The frontend's `app.js` automatically detects external origins and routes API calls to `http://127.0.0.1:5000/api`.

---

## 8. REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Initiates a background security scan (`app_name`, `target_url`, `profile`, `authorization`). |
| `GET` | `/api/scan/progress/<scan_id>` | Returns live scan progress, current stage (1–5), and terminal logs. |
| `GET` | `/api/scans` | Returns all historical scan records from SQLite. |
| `GET` | `/api/scans/<scan_id>` | Retrieves complete details and vulnerability list for a specific scan. |
| `GET` | `/api/dashboard` | Returns aggregated statistics (total scans, findings, severity counts, recent scans). |
| `GET` | `/api/vulnerabilities` | Lists all vulnerabilities with optional filters (`severity`, `status`, `search`). |
| `GET` | `/api/vulnerabilities/<scan_id>` | Lists vulnerabilities detected in a specific scan. |
| `PATCH` | `/api/vulnerabilities/<vuln_id>/status` | Toggles vulnerability status between `Open` and `Resolved`. |
| `GET` | `/api/reports/<scan_id>` | Retrieves report metadata and executive summary. |
| `GET` | `/api/reports/<scan_id>/download` | Generates and downloads the executive PDF security report. |
| `GET` | `/api/targets` | Lists all pre-configured and scanned authorized target applications. |

---

## 9. Testing & Verification

Run the included automated test suite to verify all backend APIs, database persistence, scanner algorithms, and PDF generation:

```bash
python backend/test_backend.py
```

### Test Suite Output
```
==================================================================
  SECURESCOPE TEST SUITE — VERIFYING ALL BACKEND CAPABILITIES
==================================================================
  [PASS] GET / (Index HTML)
  [PASS] GET /styles.css (CSS Assets)
  [PASS] GET /app.js (JavaScript Controller)
  [PASS] GET /api/dashboard status 200
  [PASS] Dashboard contains total_scans
  [PASS] Dashboard contains total_findings
  [PASS] Dashboard contains severity distribution
  [PASS] Dashboard contains risk score & level
  [PASS] GET /api/scans status 200
  [PASS] Scans list returned from SQLite
  [PASS] GET /api/scans/SCN-9042 status 200
  [PASS] Scan details contains scan record
  [PASS] Scan details contains vulnerabilities array
  [PASS] GET /api/vulnerabilities status 200
  [PASS] Vulnerabilities list populated
  [PASS] PATCH /api/vulnerabilities/VUL-9039-01/status 200
  [PASS] Status toggled correctly in database
  [PASS] POST /api/scan accepted (202)
  [PASS] Scan ID returned
  [PASS] Background scan completed successfully
  [PASS] Scan findings saved to SQLite
  [PASS] Stage 5 reached with 100% progress
  [PASS] GET /api/reports/SCN-XXXX status 200
  [PASS] GET /api/reports/.../download status 200
  [PASS] PDF content returned with application/pdf header
  [PASS] Valid PDF binary signature (%PDF-)
==================================================================
  TEST SUMMARY: 26 PASSED, 0 FAILED
==================================================================
```

---

## 10. Deployment Guide

### A. Deploying the Backend
1. **Render / Railway / VPS:**
   - Set the start command to: `gunicorn --chdir backend app:app --bind 0.0.0.0:$PORT` (or `python backend/app.py`).
   - Set environment variable `PYTHON_VERSION=3.10`.
   - Ensure `requirements.txt` is detected.
   - For OWASP ZAP live scanning on a cloud host, configure an OWASP ZAP Docker container (`owasp/zap2docker-stable`) and set `ZAP_PROXY_URL=http://<zap-host>:8080`.

### B. Deploying the Frontend (Vercel)
1. Deploy the `frontend/` directory to Vercel.
2. In `frontend/app.js`, update `apiBase` to point to your live deployed backend URL (e.g., `https://securescope-backend.onrender.com`).
3. Deploy changes via Vercel CLI or GitHub integration:
   ```bash
   vercel --prod
   ```

---

## 11. Security & Ethical Use Notice

SecureScope is designed exclusively for **academic research, authorized vulnerability assessment, and defensive security auditing**.
- **Authorization Requirement:** Never initiate scans against systems, networks, or applications without prior explicit written authorization from the system owner.
- **Safe Heuristics:** SecureScope employs non-destructive detection probes and does not execute destructive queries, memory exploits, or denial-of-service tests.
