const fs = require('fs');
const path = require('path');
const { analyzeCode } = require('./engines/sast_engine');
const { saveSarifReport } = require('./utils/sarif_exporter');

const runCLI = async() => {
    const targetFile = process.argv[2];
    if (!targetFile) {
        console.error('[-] Usage: node cli.js <file-path>');
        process.exit(1);
    }

    const resolvedPath = path.resolve(targetFile);
    if (!fs.existsSync(resolvedPath)) {
        console.error('[-] File not found.');
        process.exit(1);
    }

    console.log(`[*] Bayezid SAST is analyzing: ${path.basename(targetFile)}...`);
    const code = fs.readFileSync(resolvedPath, 'utf8');
    const language = targetFile.endsWith('.py') ? 'python' : 'javascript';

    const report = await analyzeCode(code, language);

    if (report.vulnerabilities_count > 0) {
        console.log(`[!] Found ${report.vulnerabilities_count} vulnerabilities!`);
        console.table(report.issues.map(i => ({ Rule: i.rule_id, Severity: i.severity, Line: i.line })));

        const reportsDir = path.join(process.cwd(), 'reports');
        if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

        const baseName = path.basename(targetFile, path.extname(targetFile));
        const reportPath = path.join(reportsDir, `bayezid-${baseName}.sarif`);

        saveSarifReport(report.issues, targetFile, reportPath);
        console.log(`\n[+] Full SARIF report saved to: ./reports/bayezid-${baseName}.sarif`);
        process.exit(1);
    } else {
        console.log('[+] Scan Passed: No vulnerabilities found.');
        process.exit(0);
    }
};

runCLI();