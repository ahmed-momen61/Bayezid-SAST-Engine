const { exec } = require('child_process');

const analyzeCode = (filePath, language) => {
    return new Promise((resolve, reject) => {
        // تنظيف المسار من الرموز الزائدة
        const cleanPath = filePath.replace('./', '').replace('.\\', '');

        // مسار ESLint المباشر (الحل السحري لمشاكل الويندوز)
        const eslintPath = 'node_modules/eslint/bin/eslint.js';

        // تكوين الأمر حسب اللغة
        const command = language === 'python' ?
            `bandit -r "${cleanPath}" -f json -q` :
            `node "${eslintPath}" "${cleanPath}" --no-eslintrc -c .eslintrc.json --format json`;

        console.log(`[Bayezid] Scanning Command: ${command}`);

        exec(command, { maxBuffer: 1024 * 1024 * 5 }, (error, stdout, stderr) => {
            // محاولة استخراج JSON نظيف من المخرجات
            const jsonStartIndex = stdout.indexOf(language === 'python' ? '{' : '[');
            const jsonEndIndex = stdout.lastIndexOf(language === 'python' ? '}' : ']');

            let cleanOutput = stdout;
            if (jsonStartIndex !== -1 && jsonEndIndex !== -1) {
                cleanOutput = stdout.substring(jsonStartIndex, jsonEndIndex + 1);
            }

            try {
                // تحويل النص لـ JSON
                // لو المخرج فاضي بنحط قيمة افتراضية عشان الكود مايضربش
                const rawData = JSON.parse(cleanOutput || (language === 'python' ? '{}' : '[]'));

                // معالجة البيانات واستخراج الثغرات
                const processedIssues = processVulnerabilities(rawData, language);

                resolve({
                    language,
                    scan_time: new Date().toISOString(),
                    vulnerabilities_count: processedIssues.length,
                    issues: processedIssues
                });
            } catch (e) {
                console.error("[Bayezid] Parse Error:", e.message);
                // في حالة الخطأ بنرجع مصفوفة فاضية
                resolve({ vulnerabilities_count: 0, issues: [] });
            }
        });
    });
};

const processVulnerabilities = (data, language) => {
    let issues = [];

    if (language === 'python') {
        // في حالة Python (Bandit)، البيانات بتيجي جاهزة في results
        // وبنأكد إن اسم الملف موجود
        issues = (data.results || []).map(issue => ({
            ...issue,
            target_file: issue.filename
        }));
    } else {
        // في حالة JavaScript (ESLint)
        // البيانات بتيجي عبارة عن مصفوفة ملفات، وكل ملف جواه messages
        if (Array.isArray(data)) {
            data.forEach(fileResult => {
                // لو الملف ده فيه أخطاء
                if (fileResult.messages && fileResult.messages.length > 0) {
                    // بنلف على كل خطأ ونحط له اسم الملف بتاع الأب
                    fileResult.messages.forEach(msg => {
                        issues.push({
                            ...msg, // خد كل تفاصيل الخطأ
                            target_file: fileResult.filePath // وضيف عليها مسار الملف
                        });
                    });
                }
            });
        }
    }

    // توحيد شكل المخرجات النهائي (Mapping)
    return issues.map(issue => ({
        id: `VULN-${Math.floor(Math.random() * 10000)}`,
        // استخراج كود الثغرة للربط مع قاعدة البيانات (Knowledge Base)
        rule_id: issue.test_id || issue.ruleId || 'UNKNOWN',
        severity: issue.issue_severity || (issue.severity === 2 ? 'HIGH' : 'LOW'),
        description: issue.issue_text || issue.message,
        line: issue.line_number || issue.line,
        // هنا الحل للمشكلة: بنستخدم المسار اللي جهزناه فوق
        file: issue.target_file || issue.filename || issue.filePath || 'unknown',
        mitre_ref: mapToMitre(issue.issue_text || issue.message || issue.ruleId)
    }));
};

const mapToMitre = (text) => {
    const t = text ? text.toLowerCase() : "";

    // قواعد ربط MITRE ATT&CK
    if (t.includes('sql')) return 'T1190: Exploit Public-Facing Application';
    if (t.includes('password') || t.includes('secret') || t.includes('credential')) return 'T1552: Unsecured Credentials';
    if (t.includes('exec') || t.includes('shell') || t.includes('command') || t.includes('child_process')) return 'T1059: Command and Scripting Interpreter';
    if (t.includes('eval')) return 'T1059: Command and Scripting Interpreter';
    if (t.includes('md5') || t.includes('hash') || t.includes('crypto')) return 'T1027: Obfuscated Files or Information';

    return 'T1203: Exploitation for Client Execution';
};

module.exports = { analyzeCode };