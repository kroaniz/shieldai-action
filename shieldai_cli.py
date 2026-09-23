import os
import re
import sys
from pathlib import Path

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{12,}['\"]", "High-entropy secret or API key exposed"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token leaked"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token leaked"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID leaked")
]

OWASP_PATTERNS = [
    (r"(?i)execute\s*\(\s*['\"].*?%s.*?['\"]\s*%", "Potential SQL Injection (OWASP A03)"),
    (r"(?i)eval\s*\(", "Insecure code execution via eval() (OWASP A03)"),
    (r"(?i)subprocess\.call\(.*shell\s*=\s*True", "Command Injection risk via shell=True"),
    (r"(?i)DEBUG\s*=\s*True", "Production debug mode enabled (OWASP A05)")
]

IGNORE_DIRS = {".git", ".github", "node_modules", "venv", ".venv", "__pycache__"}

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                for pattern, desc in SECRET_PATTERNS:
                    if re.search(pattern, clean_line):
                        findings.append((idx, "CRITICAL", desc, clean_line[:80]))
                for pattern, desc in OWASP_PATTERNS:
                    if re.search(pattern, clean_line):
                        findings.append((idx, "HIGH", desc, clean_line[:80]))
    except Exception:
        pass
    return findings

def main():
    print(f"\n{CYAN}{BOLD}======================================================{RESET}")
    print(f"{CYAN}{BOLD}          ShieldAI DevSecOps Scanner v1.0             {RESET}")
    print(f"{CYAN}{BOLD}======================================================{RESET}\n")

    license_key = os.getenv("SHIELDAI_LICENSE_KEY", "").strip()
    fail_critical = os.getenv("FAIL_ON_CRITICAL", "true").lower() == "true"
    is_pro = bool(license_key)

    total_findings = 0
    critical_count = 0
    target_dir = os.getcwd()

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in {".py", ".js", ".ts", ".env", ".json", ".yml", ".yaml", ".sh"}:
                fpath = os.path.join(root, file)
                rel_path = os.path.relpath(fpath, target_dir)
                issues = scan_file(fpath)
                if issues:
                    for line_num, severity, desc, preview in issues:
                        total_findings += 1
                        if severity == "CRITICAL":
                            critical_count += 1
                        color = RED if severity == "CRITICAL" else YELLOW
                        print(f"{color}[{severity}]{RESET} {BOLD}{rel_path}:{line_num}{RESET}")
                        print(f"  {desc}")
                        print(f"  Snippet: {preview}\n")

    print(f"{BOLD}---------------- Scan Summary ----------------{RESET}")
    if total_findings == 0:
        print(f"{GREEN}✓ No vulnerabilities or secrets detected. Great job!{RESET}\n")
        sys.exit(0)

    print(f"Total findings: {BOLD}{total_findings}{RESET} (Critical: {RED}{critical_count}{RESET})\n")

    if not is_pro:
        print(f"{YELLOW}{BOLD}[!] ShieldAI Community Edition Notice:{RESET}")
        print("    Auto-remediation and fix patches are available in ShieldAI PRO.")
        print(f"    Upgrade for {BOLD}$9.99 USDT{RESET} to enable automatic security fixes.")
        print("    Docs & License: https://github.com/marketplace\n")

    if critical_count > 0 and fail_critical and not is_pro:
        print(f"{RED}{BOLD}Audit failed due to critical security issues.{RESET}")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
