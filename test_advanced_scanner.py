"""
test_advanced_scanner.py — Smoke-test the Docker integrations locally.
Run: python test_advanced_scanner.py
"""

import sys
import json
from advanced_scanner import (
    check_docker_available,
    run_nmap_scan,
    run_nikto_scan,
    run_sqlmap_scan,
)

TARGET = "scanme.nmap.org"   # Official Nmap test host — legal to scan


def _pretty(label: str, data: dict):
    print(f"\n{'━'*60}")
    print(f"  {label}")
    print('━'*60)
    print(json.dumps(data, indent=2, default=str))


def main():
    print("\n🐋 Checking Docker availability...")
    status = check_docker_available()
    _pretty("Docker Status", status)
    if not status["available"]:
        print("\n❌ Docker is not running. Start Docker Desktop and retry.")
        sys.exit(1)

    print("\n🗺️  Running Nmap on scanme.nmap.org ...")
    nmap = run_nmap_scan(TARGET)
    _pretty("Nmap Results", nmap)

    print("\n🕷️  Running Nikto on http://scanme.nmap.org ...")
    nikto = run_nikto_scan("http://" + TARGET)
    _pretty("Nikto Results", nikto)

    # SQLMap — only test against the official demo site
    SQLMAP_TEST = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    print(f"\n💉 Running SQLMap on {SQLMAP_TEST} ...")
    sqlmap = run_sqlmap_scan(SQLMAP_TEST, test_forms=False)
    _pretty("SQLMap Results", sqlmap)

    print("\n✅ All tests complete.")


if __name__ == "__main__":
    main()
