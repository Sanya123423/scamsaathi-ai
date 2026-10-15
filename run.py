#!/usr/bin/env python3
"""
ScamSaathi - Cyber Threat Detection & Risk Assessment System
Single-Command Local Launcher Script
"""

import sys
import os
from pathlib import Path

# Ensure root directory is on Python path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from app import app
from db import init_db

def main():
    if sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

    print("=" * 68)
    print("  [+] ScamSaathi -- Intelligent Cyber Threat Detection System")
    print("  [+] Tagline: 'Think Before You Click. Verify Before You Trust.'")
    print("=" * 68)
    print("  [+] Initializing SQLite threat telemetry database...")
    init_db()
    print("  [+] Core Engine: Text Analysis, Zero-Request URL Forensics & ML Model Active")
    print("  [+] Serving Web Dashboard at: http://127.0.0.1:5000")
    print("  [+] Press CTRL+C to stop the server.")
    print("=" * 68)

    app.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    main()
