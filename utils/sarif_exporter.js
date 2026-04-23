const fs = require('fs');

const generateSarif = (scanResults, fileName) => {
    const sarifTemplate = {
        version: "2.1.0",
        $schema: "http://json.schemastore.org/sarif-2.1.0-rtm.5",
        runs: [{
            tool: {
                driver: {
                    name: "Bayezid SAST Engine",
                    informationUri: "https://github.com/ahmed-momen61/sast",
                    version: "1.0.0",
                }
            },
            results: []
        }]
    };

    const mappedResults = scanResults.map((issue) => ({
        ruleId: issue.rule_id || "BAYEZID-VULN",
        message: {
            text: issue.description || "Potential security vulnerability detected."
        },
        locations: [{
            physicalLocation: {
                artifactLocation: {
                    uri: fileName
                },
                region: {
                    startLine: issue.line || 1,
                    startColumn: 1
                }
            }
        }],
        level: issue.severity === "HIGH" || issue.severity === "CRITICAL" ? "error" : "warning"
    }));

    sarifTemplate.runs[0].results = mappedResults;
    return sarifTemplate;
};

const saveSarifReport = (scanResults, fileName, outputPath) => {
    const report = generateSarif(scanResults, fileName);
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');
};

module.exports = {
    generateSarif,
    saveSarifReport
};