const express = require('express');
const fs = require('fs');
const path = require('path');
const { analyzeCode } = require('./engines/sast_engine');
const { db, initDB, saveScanResult } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

initDB();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/scan', async(req, res) => {
    console.log("[Bayezid] New Scan Request:", req.body);
    const { filePath, language } = req.body;

    if (!filePath || !language) {
        return res.status(400).json({ error: "Missing filePath or language" });
    }

    try {
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: "Target file not found on server" });
        }
        const codeContent = fs.readFileSync(filePath, 'utf8');

        const report = await analyzeCode(codeContent, language);

        let scanId = "NOT_SAVED";
        try {
            scanId = saveScanResult(filePath, language, report);
            console.log(`[Server] Saved Scan ID: ${scanId}`);
        } catch (dbError) {
            console.error("[Server] DB Save Failed:", dbError.message);
        }

        res.json({
            status: "Success",
            warrior: "Bayezid",
            scan_id: scanId,
            report: report
        });

    } catch (err) {
        console.error("[Bayezid] Scan Failed:", err.message);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/latest-report', (req, res) => {
    const reportsDir = path.join(__dirname, 'reports');

    if (!fs.existsSync(reportsDir)) {
        return res.status(404).json({ error: "No reports directory found." });
    }

    const files = fs.readdirSync(reportsDir).filter(f => f.endsWith('.sarif'));

    if (files.length === 0) {
        return res.status(404).json({ error: "No SARIF reports found." });
    }

    const latestFile = files.map(fileName => ({
            name: fileName,
            time: fs.statSync(path.join(reportsDir, fileName)).mtime.getTime()
        }))
        .sort((a, b) => b.time - a.time)[0].name;

    const reportData = fs.readFileSync(path.join(reportsDir, latestFile), 'utf8');
    res.json(JSON.parse(reportData));
});

app.get('/report/:id', (req, res) => {
    const scanId = req.params.id;

    try {
        const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);

        if (!scan) {
            return res.status(404).json({ error: "Report not found" });
        }

        const issues = db.prepare(`
            SELECT 
                issues.file_path,
                issues.line_number,
                issues.severity,
                issues.raw_text,
                issues.vuln_id,
                kb.title AS issue_type,
                kb.description AS technical_desc,
                kb.remediation AS how_to_fix,
                kb.cvss_score,
                kb.cwe_id
            FROM issues
            LEFT JOIN kb_definitions AS kb ON issues.vuln_id = kb.vuln_id
            WHERE issues.scan_id = ?
        `).all(scanId);

        res.json({
            report_id: scan.id,
            project: scan.project_path,
            scan_date: scan.scan_date,
            risk_score: scan.risk_score,
            intelligence_summary: {
                total_vulns: issues.length,
                critical_issues: issues.filter(i => (i.cvss_score || 0) >= 9).length,
                description: "Automated analysis powered by Bayezid Engine"
            },
            details: issues
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`[+] Bayezid SAST Server is Ready on http://localhost:${PORT}`);
});