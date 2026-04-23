const express = require('express');
const { analyzeCode } = require('./engines/sast_engine');
const { db, initDB, saveScanResult } = require('./database'); // استدعاء الأدوات

const app = express();

// تشغيل قاعدة البيانات عند البدء
initDB();

app.use(express.json());

// 1. Endpoint للفحص (POST)
app.post('/scan', async(req, res) => {
    console.log("[Bayezid] New Scan Request:", req.body);
    const { filePath, language } = req.body;

    if (!filePath || !language) {
        return res.status(400).json({ error: "Missing filePath or language" });
    }

    try {
        // تشغيل المحرك
        const report = await analyzeCode(filePath, language);

        // حفظ النتيجة واستلام رقم الفحص
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

// 2. Endpoint للتقرير الذكي (GET)
// ده بيجيب تفاصيل الثغرة + الحل المقترح من قاعدة المعرفة
app.get('/report/:id', (req, res) => {
    const scanId = req.params.id;

    try {
        // جلب معلومات الفحص
        const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);

        if (!scan) {
            return res.status(404).json({ error: "Report not found" });
        }

        // جلب الثغرات مع دمجها بمعلومات الـ Knowledge Base
        // Left Join عشان لو الثغرة ملهاش تعريف، تظهر برضه بس من غير تفاصيل زيادة
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

app.listen(3000, () => console.log("Bayezid is Ready on Port 3000!"));