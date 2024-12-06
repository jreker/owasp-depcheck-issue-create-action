const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
let minimumSeverity = "HIGH"; // Einträge ab dieser Schwere aufnehmen


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
    CRITICAL: ':fire:',
    HIGH: ':warning:',
    MEDIUM: ':orange_circle:',
    LOW: 'X',
    INFO: 'X',
};

function getSeverityIcon(severity) {
    return severityIcons[severity.toUpperCase()] || '❓';
}

function countVulnerabilities(findings) {
    return findings.reduce((total, dep) => total + dep.vulnerabilities.length, 0);
}

function generateVulnEntry(entries) {
    return entries
        .map((x) => ` <details><summary><b>${x.name} :: ${x.severity} :: ${x.cvssv3 ? x.cvssv3.baseScore : ""} ${getSeverityIcon(x.severity)}</b></summary><detail> ${x.description}</details> \n `)
        .join('\n');
}

function generateIssueBody(findings) {
    let body = `# Dependency Vulnerability Report\n\n`;

    const totalDependencies = findings.length;
    body += `**Minimum Severity:** ${minimumSeverity}\n` 
    body += `**Total Vulnerabilities:** ${countVulnerabilities(findings)}\n`;
    body += `**Total Dependencies:** ${totalDependencies}\n`;

    findings.forEach((finding) => {
        body += `\n ## ${finding.fileName}\n`;
       body += `${generateVulnEntry(finding.vulnerabilities)}`;
    });

    body += "";
    return body;
}



async function run() {
    try {

        core.info("issue-labels:" + core.getInput('issue-labels'));
        core.info("minimum-severity:" + minimumSeverity);
        core.info("report-file:" + core.getInput('report-file'));
        
        // GitHub Token aus Eingaben holen
        const token = core.getInput('repo-token');

        minimumSeverity = core.getInput('minimum-severity')

        labels = core.getInput('issue-labels') ? core.getInput('issue-labels').split(',') : [];
        labels.push("owasp-autoscan", "vulnerabilities")
        core.debug("Labels:" + labels)        

        const findings = parseDependencyCheckReport(core.getInput('report-file'));
        const title = "Vulnerability Report " + core.getInput("issue-name") + " - Found: " + countVulnerabilities(findings);
        
        const body = generateIssueBody(findings);

        core.debug("Issue-Body" + body);

        // GitHub API Client initialisieren
        const octokit = github.getOctokit(token);
        core.info("octokit initialized")
        // Repository und Owner holen
        const { owner, repo } = github.context.repo;
        core.debug("owner:" + owner);
        core.debug("repo:" + repo);

        // Issue erstellen
        const response = await octokit.rest.issues.create({
            owner: owner,
            repo: repo,
            title: title,
            body: body,
        });

        core.info(response.data)

        core.setOutput('issue-url', response.data.html_url);
        console.log(`Issue created: ${response.data.html_url}`);
    } catch (error) {
        core.setFailed(error.message);
    }
}

run()
