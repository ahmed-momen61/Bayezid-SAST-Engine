const mapToMitre = (issueText) => {
    // منطق بسيط لربط الكلمات المفتاحية بـ MITRE Techniques
    if (issueText.includes("sql")) return "T1190 - Exploit Public-Facing Application";
    if (issueText.includes("password") || issueText.includes("key")) return "T1552 - Unsecured Credentials";
    if (issueText.includes("process") || issueText.includes("exec")) return "T1059 - Command and Scripting Interpreter";
    return "T1068 - Exploitation for Privilege Escalation";
};

const prepareGraphData = (sastResults) => {
    // بستايل الـ Arrow functions بنحول الداتا لخريطة
    const nodes = [{ id: "SourceCode", label: "Entry Point", type: "root" }];
    const edges = [];

    if (sastResults.results) {
        sastResults.results.forEach((issue, index) => {
            const nodeId = `Vuln_${index}`;
            const mitreTech = mapToMitre(issue.issue_text.toLowerCase());

            nodes.push({
                id: nodeId,
                label: issue.test_id,
                severity: issue.issue_severity,
                mitre: mitreTech
            });

            edges.push({
                from: "SourceCode",
                to: nodeId,
                label: "detected"
            });
        });
    }

    return { nodes, edges };
};

module.exports = { prepareGraphData };