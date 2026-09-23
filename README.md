# ShieldAI — Autonomous DevSecOps Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Marketplace](https://img.shields.io/badge/GitHub-Marketplace-blue.svg)](https://github.com/marketplace)

**ShieldAI** is a lightweight, zero-configuration security scanner for GitHub Actions. It scans your codebase in under 20 seconds to prevent secret leaks, OWASP top 10 vulnerabilities, and insecure dependencies before they hit production.

---

## 🚀 Quickstart

Add the following workflow to your repository in `.github/workflows/security.yml`:

```yaml
name: Security Audit

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  shieldai-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run ShieldAI Scanner
        uses: kroaniz/shieldai-action@main
        with:
          fail_on_critical: 'true'
          # license_key: ${{ secrets.SHIELDAI_PRO_KEY }} # Optional (PRO)
