const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const minimumSeverity = core.getInput('minimum-severity'); // Einträge ab dieser Schwere aufnehmen


function sortBySeverity(vulnerabilities) {
    return vulnerabilities.sort(
        (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
    );
}

function filterByMinimumSeverity(vulnerabilities, minimumSeverity) {
    return vulnerabilities.filter(
        (vuln) => severityOrder.indexOf(vuln.severity) <= severityOrder.indexOf(minimumSeverity)
    );
}



function parseDependencyCheckReport(filePath) {
    const report = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    const findings = report.dependencies
        .filter((dep) => dep.vulnerabilities && dep.vulnerabilities.length > 0)
        .map((dep) => {
            const sortedVulnerabilities = sortBySeverity(dep.vulnerabilities);
            const filteredVulnerabilities = filterByMinimumSeverity(sortedVulnerabilities, minimumSeverity);

            return {
                fileName: dep.fileName,
                vulnerabilities: filteredVulnerabilities,
            };
        })
        .filter((dep) => dep.vulnerabilities.length > 0); // Nur Dependencies mit relevanten Schwachstellen behalten

    return findings;
}


const severityIcons = {
    CRITICAL: '🔥',
    HIGH: '⚠️',
    MEDIUM: '🔶',
    LOW: 'ℹ️',
    INFO: '💡',
};

function getSeverityIcon(severity) {
    return severityIcons[severity.toUpperCase()] || '❓';
}

function countVulnerabilities(findings) {
    return findings.reduce((total, dep) => total + dep.vulnerabilities.length, 0);
}

function generateVulnEntry(entries) {
    return entries
        .map((x) => `- [ ] **${getSeverityIcon(x.severity)} ${x.severity}: ${x.name}** \n ${x.description} (Severity: ${x.severity})`)
        .join('\n');
}

function generateIssueBody(findings) {
    let body = `# Dependency Vulnerability Report\n\n`;

    const totalDependencies = findings.length;
    body += `**Minimum Severity: ${minimumSeverity}\n` 
    body += `**Total Vulnerabilities:** ${countVulnerabilities(findings)}\n`;
    body += `**Total Dependencies:** ${totalDependencies}\n`;

    findings.forEach((finding) => {
        body += `## ${finding.fileName}\n`;
       
        body += `${generateVulnEntry(finding.vulnerabilities)}\n\n`;
    });

    return body;
}



async function run() {
    try {

        core.info("issue-labels:", core.getInput('issue-labels'));
        core.info("minimum-severity", minimumSeverity);
        core.info("report-file", core.getInput('report-file'));
        
        // GitHub Token aus Eingaben holen
        const token = core.getInput('repo-token');

        labels = core.getInput('issue-labels') ? core.getInput('issue-labels').split(',') : [];
        labels.push("owasp-autoscan", "vulnerabilities")
        core.debug("Labels:", labels)        

        const findings = parseDependencyCheckReport(core.getInput('report-file'));
        core.debug(findings);
        const title = "🆘 Vulnerability Report " + " - Found: " + countVulnerabilities(findings);
        



        const body = generateIssueBody(findings);

        core.debug("Issue-Body", body);

        // GitHub API Client initialisieren
        const octokit = github.getOctokit(token);

        // Repository und Owner holen
        const { owner, repo } = github.context.repo;

        // Issue erstellen
        const response = await octokit.rest.issues.create({
            owner,
            repo,
            title,
            body,
            labels,
        });

        core.setOutput('issue-url', response.data.html_url);
        console.log(`Issue created: ${response.data.html_url}`);
    } catch (error) {
        core.setFailed(error.message);
    }
}

module.exports = {
    run
}
