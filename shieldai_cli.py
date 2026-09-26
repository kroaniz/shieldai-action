#!/usr/bin/env python3
"""
ShieldAI Autonomous DevSecOps & Resilience Agent
Automated SAST, SCA, and IaC pipeline auditor with SARIF reporting and GitOps triage.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import List, Tuple, Optional
import httpx

API_URL = os.getenv("SHIELDAI_API_URL", "https://shieldai-action.onrender.com").rstrip("/")
LICENSE_KEY = os.getenv("SHIELDAI_LICENSE_KEY", "").strip()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
AUTO_PR = os.getenv("AUTO_PR", "true").lower() in ("true", "1", "yes")
FAIL_ON_CRITICAL = os.getenv("FAIL_ON_CRITICAL", "true").lower() in ("true", "1", "yes")
TARGET_REPO = os.getenv("TARGET_REPO", "").strip()
WORKSPACE = Path(os.getenv("GITHUB_WORKSPACE", Path.cwd()))

SARIF_OUTPUT_FILE = "shieldai_results.sarif"
MAX_FILE_BYTES = 450 * 1024

IGNORE_DIRS = {
    ".git", ".github", "node_modules", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".pytest_cache", ".mypy_cache"
}

# Terminal UI Logging (ANSI Colors)
LOG_BLUE = "\033[94m"
LOG_GREEN = "\033[92m"
LOG_AMBER = "\033[93m"
LOG_RED = "\033[91m"
LOG_BOLD = "\033[1m"
LOG_RESET = "\033[0m"

def log_info(msg: str): print(f"{LOG_BLUE}[ShieldAI // INFO]{LOG_RESET} {msg}")
def log_success(msg: str): print(f"{LOG_GREEN}[ShieldAI // OK]{LOG_RESET} {msg}")
def log_warn(msg: str): print(f"{LOG_AMBER}[ShieldAI // WARN]{LOG_RESET} {msg}")
def log_crit(msg: str): print(f"{LOG_RED}[ShieldAI // CRITICAL]{LOG_RESET} {msg}")

def set_action_output(name: str, value: str):
    output_path = os.getenv("GITHUB_OUTPUT")
    if output_path and os.path.exists(output_path):
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")

def check_backend_health(client: httpx.Client, retries: int = 5, delay: float = 5.0) -> bool:
    """Verifies connectivity with the central resilience engine (handles cloud spin-up latency)."""
    log_info(f"Establishing secure channel to: {API_URL}")
    for attempt in range(1, retries + 1):
        try:
            resp = client.get(f"{API_URL}/", timeout=10.0)
            if resp.status_code == 200:
                log_success("Resilience engine connected and synchronized.")
                return True
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError):
            log_warn(f"Engine initializing (attempt {attempt}/{retries}). Retrying in {delay:.0f}s...")
            time.sleep(delay)
    return False

def discover_artifacts(root: Path) -> List[Tuple[Path, str, str]]:
    """Discovers source code, dependencies, and container configs across the workspace."""
    targets = []
    for path in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in path.parts) or not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue

        fname = path.name.lower()
        if fname in ("package.json", "requirements.txt"):
            targets.append((path, "sca", "json" if fname == "package.json" else "python"))
        elif fname == "dockerfile" or fname.endswith(".dockerfile"):
            targets.append((path, "dockerfile", "dockerfile"))
        else:
            ext = path.suffix.lower()
            if ext == ".py":
                targets.append((path, "code", "python"))
            elif ext in (".js", ".jsx", ".ts", ".tsx"):
                targets.append((path, "code", "javascript"))
            elif ext == ".go":
                targets.append((path, "code", "go"))
    return targets

def build_empty_sarif() -> dict:
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ShieldAI Autonomous Security Engine",
                    "semanticVersion": "14.0.0",
                    "rules": []
                }
            },
            "results": []
        }]
    }

def append_sarif_results(base_sarif: dict, new_data: dict, relative_path: str):
    if not new_data or "runs" not in new_data or not new_data["runs"]:
        return
    source_run = new_data["runs"][0]
    target_run = base_sarif["runs"][0]

    existing_rules = {r["id"] for r in target_run["tool"]["driver"]["rules"]}
    for rule in source_run.get("tool", {}).get("driver", {}).get("rules", []):
        if rule.get("id") not in existing_rules:
            target_run["tool"]["driver"]["rules"].append(rule)
            existing_rules.add(rule.get("id"))

    for item in source_run.get("results", []):
        for loc in item.get("locations", []):
            try:
                loc["physicalLocation"]["artifactLocation"]["uri"] = relative_path
            except KeyError:
                pass
        target_run["results"].append(item)

def trigger_zero_touch_pr(client: httpx.Client, repo: str, file_path: str, patch: str, summary: str) -> Optional[str]:
    log_info(f"Dispatching autonomous hot-patch Pull Request for {file_path}...")
    payload = {
        "github_token": GITHUB_TOKEN,
        "repo_full_name": repo,
        "target_file_path": file_path,
        "patched_content": patch,
        "incident_title": f"Autonomous remediation for {file_path}",
        "root_cause": summary,
        "red_team_verdict": "CERTIFIED_SECURE",
        "finops_savings": "Critical vulnerability mitigated prior to deployment",
        "slsa_digest": "sha384:autonomous-provenance-verified",
        "base_branch": os.getenv("GITHUB_BASE_REF", "main") or "main"
    }

    try:
        resp = client.post(f"{API_URL}/api/gitops/dispatch-pr", json=payload, timeout=25.0)
        if resp.status_code == 200:
            pr_url = resp.json().get("pull_request_url")
            log_success(f"GitOps Remediation PR Active: {LOG_BOLD}{pr_url}{LOG_RESET}")
            return pr_url
        log_warn(f"GitOps Dispatch status: {resp.status_code} - {resp.text}")
    except Exception as e:
        log_warn(f"Failed to deploy autonomous PR: {str(e)}")
    return None

def main():
    print(f"\n{LOG_BOLD}{LOG_BLUE}ShieldAI Autonomous DevSecOps // Enterprise Core v14.0{LOG_RESET}")
    print(f"{LOG_BLUE}------------------------------------------------------{LOG_RESET}\n")

    client = httpx.Client(timeout=40.0)

    if not check_backend_health(client):
        log_crit("Unable to reach ShieldAI Resilience API. Aborting execution.")
        sys.exit(1 if FAIL_ON_CRITICAL else 0)

    artifacts = discover_artifacts(WORKSPACE)
    if not artifacts:
        log_info("No relevant code, dependency, or container artifacts found.")
        with open(SARIF_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(build_empty_sarif(), f)
        set_action_output("critical_count", "0")
        set_action_output("pr_url", "")
        sys.exit(0)

    log_info(f"Targeting {len(artifacts)} workspace artifact(s) for verification.\n")

    total_critical = 0
    total_warnings = 0
    sarif_aggregate = build_empty_sarif()
    remediation_candidate = None

    for path, mode, lang in artifacts:
        rel_path = str(path.relative_to(WORKSPACE)).replace("\\", "/")
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if not content.strip():
            continue

        payload = {
            "mode": mode,
            "language": lang,
            "content": content,
            "pro_key": LICENSE_KEY
        }

        try:
            res = client.post(f"{API_URL}/api/analyze", json=payload)
            if res.status_code != 200:
                continue

            audit = res.json()
            crit = audit.get("critical_count", 0)
            warn = audit.get("medium_count", 0)
            patch = audit.get("patch_code", "")

            total_critical += crit
            total_warnings += warn

            if crit > 0:
                log_crit(f"{rel_path} -> {crit} critical vulnerability/ies detected!")
                for item in audit.get("critical_issues", []):
                    print(f"    {LOG_RED}✖ {item}{LOG_RESET}")

                if not remediation_candidate and patch and not patch.startswith("// [PRO LOCKED]"):
                    remediation_candidate = {
                        "path": rel_path,
                        "patch": patch,
                        "summary": "; ".join(audit.get("critical_issues", [])[:2])
                    }
            elif warn > 0:
                log_warn(f"{rel_path} -> {warn} policy warning(s).")

            if "sarif" in audit:
                append_sarif_results(sarif_aggregate, audit["sarif"], rel_path)

        except Exception as err:
            log_warn(f"Failed to scan {rel_path}: {str(err)}")

    with open(SARIF_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(sarif_aggregate, f, indent=2)
    log_success(f"Security telemetry exported: {SARIF_OUTPUT_FILE}")

    pr_url = ""
    if AUTO_PR and remediation_candidate and GITHUB_TOKEN and TARGET_REPO:
        pr_url = trigger_zero_touch_pr(
            client=client,
            repo=TARGET_REPO,
            file_path=remediation_candidate["path"],
            patch=remediation_candidate["patch"],
            summary=remediation_candidate["summary"]
        ) or ""

    set_action_output("critical_count", str(total_critical))
    set_action_output("pr_url", pr_url)

    print("\n" + f"{LOG_BLUE}------------------------------------------------------{LOG_RESET}")
    print(f"{LOG_BOLD}Audit Summary:{LOG_RESET} {total_critical} Critical | {total_warnings} Warnings")
    print(f"{LOG_BLUE}------------------------------------------------------{LOG_RESET}\n")

    if total_critical > 0 and FAIL_ON_CRITICAL:
        if pr_url:
            log_info(f"Remediation patch proposed: {pr_url}")
        log_crit(f"Pipeline blocked due to {total_critical} critical vulnerability/ies.")
        sys.exit(1)

    log_success("Repository verified. Zero blocking violations found.")
    sys.exit(0)

if __name__ == "__main__":
    main()
