const Database = require('better-sqlite3');
const db = new Database('bayezid.db', { verbose: console.log });

db.pragma('foreign_keys = ON');

const initDB = () => {
    db.exec(`
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_path TEXT NOT NULL,
            language TEXT NOT NULL,
            scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_issues INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0
        )
    `);

    db.exec(`
        CREATE TABLE IF NOT EXISTS kb_definitions (
            vuln_id TEXT PRIMARY KEY, (B608 | security/detect-eval)
            cwe_id TEXT,
            title TEXT,
            description TEXT,
            remediation TEXT,
            cvss_score REAL
        )
    `);

    db.exec(`
        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            file_path TEXT,
            line_number INTEGER,
            vuln_id TEXT, 
            raw_text TEXT,
            severity TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    `);

    seedKnowledgeBase();
    console.log("🦁 Bayezid Database Initialized & Ready!");
};

const seedKnowledgeBase = () => {
    const insert = db.prepare(`
        INSERT OR IGNORE INTO kb_definitions (vuln_id, cwe_id, title, description, remediation, cvss_score)
        VALUES (@vuln_id, @cwe_id, @title, @description, @remediation, @cvss_score)
    `);

    const transaction = db.transaction((definitions) => {
        for (const def of definitions) insert.run(def);
    });

    transaction([{
            vuln_id: 'B608',
            cwe_id: 'CWE-89',
            title: 'Hardcoded SQL Injection',
            description: 'Possible SQL injection vector through string concatenation.',
            remediation: 'Use parameterized queries or ORM methods instead of building SQL strings.',
            cvss_score: 9.8
        },
        {
            vuln_id: 'security/detect-eval-with-expression',
            cwe_id: 'CWE-95',
            title: 'Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)',
            description: 'User input is passed correctly to eval() function allowing arbitrary code execution.',
            remediation: 'Avoid using eval(). Use JSON.parse() if parsing JSON, or safe math libraries.',
            cvss_score: 10.0
        },
        {
            vuln_id: 'security/detect-child-process',
            cwe_id: 'CWE-78',
            title: 'OS Command Injection',
            description: 'User input used in OS command execution.',
            remediation: 'Avoid using exec(). Use execFile() or spawn() and sanitize inputs.',
            cvss_score: 9.0
        }
    ]);
};

// دالة حفظ التقرير
const saveScanResult = (projectPath, language, report) => {
    // 1. تسجيل الفحص
    const insertScan = db.prepare(`
        INSERT INTO scans (project_path, language, total_issues, risk_score)
        VALUES (?, ?, ?, ?)
    `);

    const riskScore = report.issues.reduce((acc, issue) => acc + (issue.severity === 'HIGH' ? 5 : 1), 0);

    const info = insertScan.run(projectPath, language, report.vulnerabilities_count || 0, riskScore);
    const scanId = info.lastInsertRowid;

    // 2. تسجيل الثغرات
    if (report.issues && report.issues.length > 0) {
        const insertIssue = db.prepare(`
            INSERT INTO issues (scan_id, file_path, line_number, vuln_id, raw_text, severity)
            VALUES (@scan_id, @file_path, @line_number, @vuln_id, @raw_text, @severity)
        `);

        const saveMany = db.transaction((issues) => {
            for (const issue of issues) {
                insertIssue.run({
                    scan_id: scanId,
                    file_path: issue.file,
                    line_number: issue.line,
                    vuln_id: issue.rule_id || 'UNKNOWN', // هنا بنربط بالكود اللي جاي من المحرك
                    raw_text: issue.description,
                    severity: issue.severity
                });
            }
        });

        saveMany(report.issues);
    }

    console.log(`[Database] Scan #${scanId} saved successfully.`);
    return scanId;
};

module.exports = { db, initDB, saveScanResult };