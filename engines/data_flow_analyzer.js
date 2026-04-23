const acorn = require('acorn');

const DANGEROUS_SINKS = ['exec', 'eval', 'setTimeout', 'setInterval', 'execSync'];
const USER_INPUT_SOURCES = ['req', 'request', 'body', 'query', 'params', 'userInput'];

const analyzeDataFlow = (code) => {
    let issues = [];
    try {
        const ast = acorn.parse(code, { ecmaVersion: 2020, locations: true });
        let taintedVariables = new Set();

        const walkAST = (node) => {
            if (!node) return;

            if (node.type === 'VariableDeclarator') {
                const varName = node.id.name;
                if (node.init && node.init.type === 'Identifier' && USER_INPUT_SOURCES.includes(node.init.name)) {
                    taintedVariables.add(varName);
                }
                if (node.init && node.init.type === 'MemberExpression') {
                    if (node.init.object && USER_INPUT_SOURCES.includes(node.init.object.name)) {
                        taintedVariables.add(varName);
                    }
                }
            }

            if (node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression') {
                node.params.forEach(param => {
                    taintedVariables.add(param.name);
                });
            }

            if (node.type === 'CallExpression') {
                const funcName = node.callee.name;
                if (DANGEROUS_SINKS.includes(funcName)) {
                    node.arguments.forEach(arg => {
                        if (arg.type === 'Identifier' && taintedVariables.has(arg.name)) {
                            issues.push(createIssue(funcName, arg.name, node.loc.start.line));
                        }
                        if (arg.type === 'BinaryExpression') {
                            if ((arg.left.type === 'Identifier' && taintedVariables.has(arg.left.name)) ||
                                (arg.right.type === 'Identifier' && taintedVariables.has(arg.right.name))) {
                                const taintedArg = arg.left.name || arg.right.name;
                                issues.push(createIssue(funcName, taintedArg, node.loc.start.line));
                            }
                        }
                    });
                }
            }

            for (let key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    if (Array.isArray(node[key])) {
                        node[key].forEach(child => walkAST(child));
                    } else {
                        walkAST(node[key]);
                    }
                }
            }
        };

        walkAST(ast);

    } catch (err) {
        console.error('[-] AST Parsing Error:', err.message);
    }

    return issues;
};

const createIssue = (sink, source, line) => {
    return {
        rule_id: `BAYEZID-TAINT-${sink.toUpperCase()}`,
        description: `Taint Analysis: User input '${source}' flows into dangerous sink '${sink}()' without sanitization.`,
        severity: 'CRITICAL',
        line: line
    };
};

module.exports = { analyzeDataFlow };