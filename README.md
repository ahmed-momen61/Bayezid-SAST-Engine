# 🛡️ Bayezid SAST Engine

![Node.js](https://img.shields.io/badge/Node.js-Environment-success?style=for-the-badge&logo=nodedotjs)
![Express](https://img.shields.io/badge/Express.js-Framework-lightgrey?style=for-the-badge)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active_Development-orange?style=for-the-badge)

## 📌 Project Overview
**Bayezid SAST** is a custom-built Static Application Security Testing (SAST) engine designed to autonomously analyze source code for critical security vulnerabilities. Leveraging Abstract Syntax Tree (AST) parsing and customized security linting algorithms, the engine provides deep inspection capabilities alongside a unique visualizer to map out code execution and vulnerability paths.

## ✨ Core Features
* **Automated Code Scanning:** Rapidly identifies security flaws in user-uploaded code via a robust Express.js API.
* **AST Parsing & Visualization:** Utilizes parsing libraries (`acorn`/`espree`) to generate Abstract Syntax Trees, providing a clear visual representation of application logic via the internal `visualizer_logic.js` engine.
* **Multi-Language Targeting:** Designed to process and analyze both JavaScript and Python source files.
* **Persistent Vulnerability Tracking:** Securely logs scan results, engine states, and identified threats into a centralized, high-performance SQLite database (`bayezid.db`).

## 🚨 Vulnerability Coverage (Test Cases)
The engine is actively tested and calibrated against common attack vectors. The `uploads/` directory contains standard vulnerable test cases for engine validation:
* **Command Injection** (`vuln_cmd_injection.js`)
* **Cryptographic Failures & Weak Ciphers** (`vuln_crypto.py`)
* **Hardcoded Secrets & Credentials** (`vuln_secrets.py`)
* **Database Flaws / SQL Injection** (`vulnerable_db.js`)

## 🛠️ Technology Stack
* **Backend Core:** Node.js, Express.js
* **Database:** `better-sqlite3`
* **Analysis Engine:** Custom detection logic integrated with `eslint-plugin-security`
* **Code Parsing:** `acorn`, `espree`, `js-yaml`

## 🚀 Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/ahmed-momen61/sast.git](https://github.com/ahmed-momen61/sast.git)
