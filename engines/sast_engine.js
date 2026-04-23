const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { analyzeDataFlow } = require('./data_flow_analyzer');

const analyzeCode = (code, language = 'javascript') => {
    return new Promise((resolve) => {
        try {
            const tempFileName = `temp_scan_${Date.now()}.${language === 'python' ? 'py' : 'js'}`;
            const tempFilePath = path.resolve(__dirname, '..', tempFileName);
            fs.writeFileSync(tempFilePath, code, 'utf8');

            let command;
            let output = '';

            if (language === 'python') {
                command = `bandit -r "${tempFilePath}" -f json -q`;
            } else {
                const eslintPath = path.resolve(__dirname, '..', 'node_modules/eslint/bin/eslint.js');
                const eslintrcPath = path.resolve(__dirname, '..', '.eslintrc.json');
                command = `node "${eslintPath}" "${tempFilePath}" --no-eslintrc -c "${eslintrcPath}" --format json`;
            }

            try {
                output = execSync(command, { encoding: 'utf-8', stdio: 'pipe' });
            } catch (err) {
                output = err.stdout || err.stderr || '';
            }

            if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);

            const startChar = language === 'python' ? '{' : '[';
            const endChar = language === 'python' ? '}' : ']';
            const jsonStartIndex = output.indexOf(startChar);
            const jsonEndIndex = output.lastIndexOf(endChar);

            let cleanOutput = output;
            if (jsonStartIndex !== -1 && jsonEndIndex !== -1) {
                cleanOutput = output.substring(jsonStartIndex, jsonEndIndex + 1);
            }

            const rawData = JSON.parse(cleanOutput || (language === 'python' ? '{}' : '[]'));
            const processedIssues = processVulnerabilities(rawData, language);

            let finalIssues = processedIssues;
            if (language === 'javascript') {
                const taintIssues = analyzeDataFlow(code);
                const cleanTaintIssues = taintIssues.map(issue => ({
                    ...issue,
                    file: 'Uploaded_JS_File.js',
                    mitre_ref: 'T1059: Command and Scripting Interpreter',
                    id: `VULN-${Math.floor(Math.random() * 10000)}`
                }));
                finalIssues = [...processedIssues, ...cleanTaintIssues];
            }

            resolve({
                language,
                scan_time: new Date().toISOString(),
                vulnerabilities_count: finalIssues.length,
                issues: finalIssues
            });

        } catch (error) {
            console.error('[-] Bayezid Engine Error:', error.message);
            resolve({ vulnerabilities_count: 0, issues: [] });
        }
    });
};

const processVulnerabilities = (data, language) => {
    let issues = [];
    if (language === 'python') {
        issues = (data.results || []).map(issue => ({...issue, target_file: 'Uploaded_File.py' }));
    } else if (Array.isArray(data)) {
        data.forEach(fileResult => {
            if (fileResult.messages) {
                fileResult.messages.forEach(msg => {
                    issues.push({...msg, target_file: 'Uploaded_File.js' });
                });
            }
        });
    }

    return issues.map(issue => ({
        id: `VULN-${Math.floor(Math.random() * 10000)}`,
        rule_id: issue.test_id || issue.ruleId || 'SECURITY-RULE',
        severity: issue.issue_severity || (issue.severity === 2 ? 'HIGH' : 'LOW'),
        description: issue.issue_text || issue.message,
        line: issue.line_number || issue.line,
        mitre_ref: mapToMitre(issue.issue_text || issue.message || '')
    }));
};

const mapToMitre = (text) => {
    const t = text.toLowerCase();
    if (t.includes('sql')) return 'T1190';
    if (t.includes('exec') || t.includes('shell')) return 'T1059';
    if (t.includes('password') || t.includes('secret')) return 'T1552';
    return 'T1203';
};

module.exports = { analyzeCode };