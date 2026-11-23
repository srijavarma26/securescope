"""
SecureScope — Web Application Security Analysis System
Main Flask Application Server
"""

import os
import sys
from flask import Flask, send_from_directory, render_template_string
from flask_cors import CORS
import database
from routes import api_bp

# Set up paths
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR)
CORS(app)  # Enable Cross-Origin Resource Sharing for API consumers

# Register API Blueprint
app.register_blueprint(api_bp, url_prefix='/api')

# Initialize SQLite database on startup
with app.app_context():
    database.init_db()

# Serve Frontend static assets and index.html
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path != "" and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, 'index.html')

if __name__ == '__main__':
    print("==================================================================")
    print("  SECURESCOPE — Web Application Security Analysis System")
    print("  Backend Server starting on http://127.0.0.1:5000")
    print("  Frontend UI served directly on http://127.0.0.1:5000")
    print("  REST API available on http://127.0.0.1:5000/api")
    print("==================================================================")
    app.run(host='0.0.0.0', port=5000, debug=True)
