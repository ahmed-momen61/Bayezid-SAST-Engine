# Bayezid SAST Engine: Advanced Static Analysis V0.2.5

![Node.js](https://img.shields.io/badge/Node.js-Environment-success?style=for-the-badge&logo=nodedotjs)
![Security](https://img.shields.io/badge/Analysis-Taint%20%26%20AST-darkred?style=for-the-badge)
![Format](https://img.shields.io/badge/Output-SARIF%20Standard-blue?style=for-the-badge)

## Why Bayezid?
**Bayezid** is not just a linter; it's a security-first Static Application Security Testing (SAST) engine designed to hunt for high-impact vulnerabilities. It goes beyond simple pattern matching by analyzing the **Data Flow** and **Abstract Syntax Trees (AST)** of application code.

## Key Features
* **Taint Analysis Engine:** Tracks unsanitized user input from "Sources" (like Express parameters) to "Sinks" (dangerous functions like `exec` or `eval`).
* **Visual Dashboard:** A built-in web interface to view scan statistics and detailed vulnerability reports.
* **DevSecOps Ready (CLI):** Includes a Command Line Interface that exits with non-zero codes on findings, making it perfect for CI/CD pipelines.
* **Industry Standard Reporting:** Generates **SARIF 2.1.0** reports, compatible with GitHub Security Center and major IDEs.

## How it Works
The engine processes code through two parallel pipelines:
1. **The Linter Layer:** Uses `eslint-plugin-security` for signature-based detection.
2. **The Intelligence Layer:** Uses `acorn` to parse code into AST and perform recursive Taint analysis to prove exploitability.

## Installation
```bash
# Clone and install
git clone [https://github.com/ahmed-momen61/sast.git](https://github.com/ahmed-momen61/sast.git)
cd sast
npm install

# Start the Dashboard Server
node server.js

# Run a CLI Scan
node cli.js ./uploads/vuln_cmd_injection.js
