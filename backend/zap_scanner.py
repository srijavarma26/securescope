"""
SecureScope — OWASP ZAP Integration Module
Integrates OWASP ZAP passive scanning via its REST API (default http://127.0.0.1:8080)
and formats passive alerts into standard SecureScope vulnerability objects.
"""

import os
import requests
import logging

logger = logging.getLogger(__name__)

ZAP_PROXY_URL = os.environ.get('ZAP_PROXY_URL', 'http://127.0.0.1:8080')
ZAP_API_KEY = os.environ.get('ZAP_API_KEY', '')

class ZapScanner:
    def __init__(self, zap_url=ZAP_PROXY_URL, api_key=ZAP_API_KEY):
        self.zap_url = zap_url.rstrip('/')
        self.api_key = api_key
        self.available = False
        self._check_connection()

    def _check_connection(self):
        """Checks if the OWASP ZAP daemon is running and reachable."""
        try:
            params = {}
            if self.api_key:
                params['apikey'] = self.api_key
            res = requests.get(f"{self.zap_url}/JSON/core/view/version/", params=params, timeout=2)
            if res.status_code == 200:
                self.available = True
                logger.info(f"OWASP ZAP connected successfully. Version: {res.json().get('version')}")
            else:
                self.available = False
        except Exception:
            self.available = False

    def is_available(self):
        self._check_connection()
        return self.available

    def run_passive_scan(self, target_url, log_callback=None):
        """
        Runs a safe passive scan through OWASP ZAP if daemon is available.
        Returns a list of standardized vulnerability dictionaries.
        """
        findings = []
        if not self.is_available():
            if log_callback:
                log_callback(f"[ZAP-PASSIVE] OWASP ZAP daemon offline at {self.zap_url}. Utilizing SecureScope native passive engine.", "info")
            return findings

        if log_callback:
            log_callback(f"[ZAP-PASSIVE] Connected to OWASP ZAP at {self.zap_url}. Accessing target URL passively...", "info")

        try:
            params = {'url': target_url}
            if self.api_key:
                params['apikey'] = self.api_key

            # 1. Access the target URL through ZAP to register requests in its session
            requests.get(f"{self.zap_url}/JSON/core/action/accessUrl/", params=params, timeout=10)
            
            if log_callback:
                log_callback("[ZAP-PASSIVE] Waiting for ZAP passive scan queue to drain...", "info")

            # 2. Check passive scan records remaining
            import time
            for _ in range(5):
                pscan_res = requests.get(f"{self.zap_url}/JSON/pscan/view/recordsToScan/", params=params, timeout=5)
                if pscan_res.status_code == 200:
                    records = int(pscan_res.json().get('recordsToScan', 0))
                    if records == 0:
                        break
                time.sleep(1)

            # 3. Retrieve passive alerts
            alert_params = {'baseurl': target_url}
            if self.api_key:
                alert_params['apikey'] = self.api_key
            alerts_res = requests.get(f"{self.zap_url}/JSON/core/view/alerts/", params=alert_params, timeout=10)

            if alerts_res.status_code == 200:
                raw_alerts = alerts_res.json().get('alerts', [])
                if log_callback:
                    log_callback(f"[ZAP-PASSIVE] Retrieved {len(raw_alerts)} passive security alerts from OWASP ZAP.", "success")

                for alert in raw_alerts:
                    risk = alert.get('risk', 'Low').capitalize()
                    if risk not in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
                        risk = 'Medium'

                    solution = alert.get('solution', '').strip()
                    remediation_list = [s.strip() for s in solution.split('\n') if s.strip()] if solution else [
                        'Review target configuration',
                        'Apply recommended OWASP security headers',
                        'Follow secure development guidelines'
                    ]

                    findings.append({
                        'vuln_name': f"OWASP ZAP: {alert.get('alert', alert.get('name', 'Passive Alert'))}",
                        'category': 'OWASP ZAP Baseline',
                        'severity': risk,
                        'confidence': alert.get('confidence', 'High').capitalize(),
                        'affected_url': alert.get('url', target_url),
                        'description': alert.get('description', 'Detected by OWASP ZAP passive scanner rules.'),
                        'impact': alert.get('other', 'Passive security violation identified during HTTP traffic inspection.'),
                        'remediation': remediation_list,
                        'status': 'Open'
                    })
        except Exception as e:
            if log_callback:
                log_callback(f"[ZAP-PASSIVE] Error querying OWASP ZAP: {str(e)}", "warn")
            logger.error(f"ZAP error: {e}")

        return findings
