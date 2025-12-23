"""
Security Checklist - Interactive manual security audit tool.

Features:
- Comprehensive security checklist organized by category
- Interactive mode with prompts and guidance
- Progress tracking and reporting
- Multi-LLM assisted explanations
- Compliance mapping (HIPAA, PCI DSS, SOC2)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from shared.src.llm_client import MultiLLMClient, LLMProvider


@dataclass
class ChecklistItem:
    id: str
    category: str
    title: str
    description: str
    guidance: str
    severity: str  # critical, high, medium, low
    compliance: list[str] = field(default_factory=list)  # hipaa, pci_dss, soc2
    automated_check: Optional[str] = None  # Reference to automated check if available
    status: str = "pending"  # pending, pass, fail, na
    notes: str = ""
    evidence: str = ""


@dataclass
class ChecklistResult:
    project_name: str
    auditor: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    items: list[ChecklistItem] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


# Comprehensive security checklist
SECURITY_CHECKLIST = {
    "authentication": {
        "name": "Authentication & Authorization",
        "items": [
            {
                "id": "AUTH-001",
                "title": "Password Policy",
                "description": "Verify password requirements meet security standards",
                "guidance": """Check for:
- Minimum 12 characters length
- Complexity requirements (uppercase, lowercase, numbers, symbols)
- Password history (prevent reuse of last 10 passwords)
- No common passwords allowed (dictionary check)
- Secure password hashing (bcrypt, Argon2, or PBKDF2)""",
                "severity": "high",
                "compliance": ["hipaa", "pci_dss", "soc2"],
            },
            {
                "id": "AUTH-002",
                "title": "Multi-Factor Authentication",
                "description": "Verify MFA is implemented and enforced appropriately",
                "guidance": """Check for:
- MFA available for all user accounts
- MFA enforced for admin/privileged accounts
- Multiple MFA options (TOTP, SMS, hardware keys)
- Backup codes generated securely
- MFA cannot be bypassed""",
                "severity": "high",
                "compliance": ["hipaa", "pci_dss"],
            },
            {
                "id": "AUTH-003",
                "title": "Session Management",
                "description": "Verify secure session handling",
                "guidance": """Check for:
- Secure session token generation (cryptographically random)
- Session tokens not in URLs
- Appropriate session timeout (idle and absolute)
- Session invalidation on logout
- New session on authentication
- Secure cookie flags (HttpOnly, Secure, SameSite)""",
                "severity": "high",
                "compliance": ["pci_dss", "soc2"],
            },
            {
                "id": "AUTH-004",
                "title": "Access Control",
                "description": "Verify proper authorization checks",
                "guidance": """Check for:
- Role-based access control (RBAC) implemented
- Principle of least privilege enforced
- Authorization checks on every request
- No direct object reference vulnerabilities (IDOR)
- Admin functions properly protected
- API endpoints have authorization checks""",
                "severity": "critical",
                "compliance": ["hipaa", "pci_dss", "soc2"],
            },
            {
                "id": "AUTH-005",
                "title": "Account Lockout",
                "description": "Verify brute force protection",
                "guidance": """Check for:
- Account lockout after failed attempts (max 5)
- Lockout duration appropriate (15+ minutes)
- Rate limiting on login endpoints
- CAPTCHA after failed attempts
- Lockout notifications to user""",
                "severity": "medium",
                "compliance": ["pci_dss"],
            },
        ],
    },
    "data_protection": {
        "name": "Data Protection",
        "items": [
            {
                "id": "DATA-001",
                "title": "Encryption at Rest",
                "description": "Verify sensitive data is encrypted when stored",
                "guidance": """Check for:
- Database encryption enabled
- File system encryption for sensitive files
- Encryption keys properly managed
- Strong encryption algorithms (AES-256)
- Key rotation procedures in place""",
                "severity": "critical",
                "compliance": ["hipaa", "pci_dss", "soc2"],
            },
            {
                "id": "DATA-002",
                "title": "Encryption in Transit",
                "description": "Verify all data transmission is encrypted",
                "guidance": """Check for:
- TLS 1.2 or higher enforced
- HSTS header present
- No mixed content
- Certificate validity and chain
- Strong cipher suites only
- Perfect forward secrecy enabled""",
                "severity": "critical",
                "compliance": ["hipaa", "pci_dss", "soc2"],
            },
            {
                "id": "DATA-003",
                "title": "PII Handling",
                "description": "Verify proper handling of personally identifiable information",
                "guidance": """Check for:
- PII identified and classified
- Minimum necessary data collection
- Data masking in logs and displays
- Secure deletion procedures
- Data retention policies enforced
- Third-party data sharing documented""",
                "severity": "high",
                "compliance": ["hipaa", "soc2"],
            },
            {
                "id": "DATA-004",
                "title": "PHI Protection",
                "description": "Verify protected health information safeguards (HIPAA)",
                "guidance": """Check for:
- PHI access logging enabled
- PHI encrypted at rest and in transit
- Minimum necessary access principle
- BAA agreements with vendors
- PHI disposal procedures
- Emergency access procedures""",
                "severity": "critical",
                "compliance": ["hipaa"],
            },
            {
                "id": "DATA-005",
                "title": "Payment Data Security",
                "description": "Verify PCI DSS compliance for payment handling",
                "guidance": """Check for:
- No storage of full card numbers
- CVV never stored
- Tokenization for stored cards
- PCI-compliant payment processor
- Secure payment pages (no iframes from untrusted sources)
- P2PE if handling card data""",
                "severity": "critical",
                "compliance": ["pci_dss"],
            },
        ],
    },
    "input_validation": {
        "name": "Input Validation & Output Encoding",
        "items": [
            {
                "id": "INPUT-001",
                "title": "SQL Injection Prevention",
                "description": "Verify protection against SQL injection",
                "guidance": """Check for:
- Parameterized queries / prepared statements
- ORM usage with proper escaping
- No string concatenation in queries
- Input validation on all parameters
- Stored procedures with parameterization""",
                "severity": "critical",
                "compliance": ["pci_dss", "soc2"],
            },
            {
                "id": "INPUT-002",
                "title": "XSS Prevention",
                "description": "Verify protection against cross-site scripting",
                "guidance": """Check for:
- Output encoding on all user-controlled data
- Content-Security-Policy header
- HTTPOnly flag on cookies
- React/Vue auto-escaping (dangerouslySetInnerHTML review)
- DOM-based XSS prevention
- Stored XSS prevention""",
                "severity": "high",
                "compliance": ["pci_dss", "soc2"],
            },
            {
                "id": "INPUT-003",
                "title": "CSRF Protection",
                "description": "Verify cross-site request forgery protection",
                "guidance": """Check for:
- CSRF tokens on state-changing requests
- SameSite cookie attribute
- Origin/Referer validation
- Double-submit cookie pattern if applicable
- Token regeneration on login""",
                "severity": "high",
                "compliance": ["soc2"],
            },
            {
                "id": "INPUT-004",
                "title": "File Upload Security",
                "description": "Verify secure file upload handling",
                "guidance": """Check for:
- File type validation (magic bytes, not just extension)
- Maximum file size limits
- Filename sanitization
- Files stored outside web root
- Malware scanning
- No execution permissions on upload directory""",
                "severity": "high",
                "compliance": ["soc2"],
            },
            {
                "id": "INPUT-005",
                "title": "API Input Validation",
                "description": "Verify API endpoint input validation",
                "guidance": """Check for:
- Schema validation (JSON Schema, OpenAPI)
- Type checking on all inputs
- Range/length validation
- Reject unexpected parameters
- Rate limiting per endpoint
- Request size limits""",
                "severity": "medium",
                "compliance": ["soc2"],
            },
        ],
    },
    "infrastructure": {
        "name": "Infrastructure Security",
        "items": [
            {
                "id": "INFRA-001",
                "title": "Security Headers",
                "description": "Verify security headers are properly configured",
                "guidance": """Check for:
- Content-Security-Policy (CSP)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY or SAMEORIGIN
- X-XSS-Protection: 1; mode=block
- Referrer-Policy
- Permissions-Policy
- Strict-Transport-Security (HSTS)""",
                "severity": "medium",
                "compliance": ["soc2"],
            },
            {
                "id": "INFRA-002",
                "title": "Error Handling",
                "description": "Verify errors don't leak sensitive information",
                "guidance": """Check for:
- Generic error messages to users
- No stack traces in production
- Errors logged securely (not to client)
- Custom error pages
- No sensitive data in error responses""",
                "severity": "medium",
                "compliance": ["pci_dss", "soc2"],
            },
            {
                "id": "INFRA-003",
                "title": "Logging & Monitoring",
                "description": "Verify comprehensive security logging",
                "guidance": """Check for:
- Authentication events logged
- Authorization failures logged
- Sensitive data access logged
- Log integrity protection
- Centralized log management
- Real-time alerting for security events
- Log retention meets compliance requirements""",
                "severity": "high",
                "compliance": ["hipaa", "pci_dss", "soc2"],
            },
            {
                "id": "INFRA-004",
                "title": "Secrets Management",
                "description": "Verify secure handling of secrets and credentials",
                "guidance": """Check for:
- No secrets in source code
- Environment variables or secrets manager
- Secrets not in logs
- Regular secret rotation
- Principle of least privilege for secrets access
- Secure secret transmission""",
                "severity": "critical",
                "compliance": ["hipaa", "pci_dss", "soc2"],
            },
            {
                "id": "INFRA-005",
                "title": "Dependency Management",
                "description": "Verify secure dependency management",
                "guidance": """Check for:
- Regular dependency updates
- Known vulnerability scanning
- Lock files in use
- Private registry if applicable
- Dependency review process
- No unnecessary dependencies""",
                "severity": "high",
                "compliance": ["pci_dss", "soc2"],
            },
        ],
    },
    "api_security": {
        "name": "API Security",
        "items": [
            {
                "id": "API-001",
                "title": "API Authentication",
                "description": "Verify API authentication mechanisms",
                "guidance": """Check for:
- Token-based authentication (JWT, OAuth 2.0)
- API keys for service-to-service
- Token expiration and refresh
- Secure token storage
- Token revocation capability""",
                "severity": "high",
                "compliance": ["soc2"],
            },
            {
                "id": "API-002",
                "title": "API Rate Limiting",
                "description": "Verify rate limiting and throttling",
                "guidance": """Check for:
- Rate limits per user/IP
- Graduated rate limiting
- Clear rate limit headers
- Appropriate limits for each endpoint
- DDoS protection""",
                "severity": "medium",
                "compliance": ["soc2"],
            },
            {
                "id": "API-003",
                "title": "API Documentation Security",
                "description": "Verify API documentation doesn't expose sensitive info",
                "guidance": """Check for:
- No sensitive endpoints in public docs
- Example data sanitized
- Authentication required for internal docs
- No real credentials in examples
- Version information controlled""",
                "severity": "low",
                "compliance": [],
            },
            {
                "id": "API-004",
                "title": "CORS Configuration",
                "description": "Verify proper CORS settings",
                "guidance": """Check for:
- No wildcard (*) origins in production
- Credentials only with specific origins
- Allowed methods restricted
- Preflight caching appropriate
- Exposed headers minimized""",
                "severity": "medium",
                "compliance": ["soc2"],
            },
        ],
    },
    "ai_security": {
        "name": "AI/LLM Security",
        "items": [
            {
                "id": "AI-001",
                "title": "Prompt Injection Prevention",
                "description": "Verify protection against prompt injection attacks",
                "guidance": """Check for:
- Input sanitization before LLM calls
- System prompts protected from user manipulation
- Output validation before display
- Rate limiting on AI endpoints
- Jailbreak detection mechanisms""",
                "severity": "high",
                "compliance": [],
            },
            {
                "id": "AI-002",
                "title": "AI Data Privacy",
                "description": "Verify AI doesn't leak sensitive data",
                "guidance": """Check for:
- PII/PHI not sent to external LLMs
- Data anonymization before AI processing
- AI provider data retention policies reviewed
- User consent for AI processing
- AI outputs reviewed for data leakage""",
                "severity": "critical",
                "compliance": ["hipaa", "soc2"],
            },
            {
                "id": "AI-003",
                "title": "AI Output Validation",
                "description": "Verify AI outputs are safe and appropriate",
                "guidance": """Check for:
- Content moderation on AI outputs
- No harmful content generation
- Fact-checking for critical information
- Human review for sensitive decisions
- Bias detection and mitigation""",
                "severity": "medium",
                "compliance": [],
            },
        ],
    },
    "mobile_security": {
        "name": "Mobile/PWA Security",
        "items": [
            {
                "id": "MOB-001",
                "title": "Secure Storage",
                "description": "Verify secure local data storage",
                "guidance": """Check for:
- Sensitive data encrypted in storage
- No sensitive data in LocalStorage (use SessionStorage or encrypted storage)
- Secure cookies with appropriate flags
- IndexedDB encryption if storing sensitive data
- Service worker cache security""",
                "severity": "high",
                "compliance": ["hipaa", "pci_dss"],
            },
            {
                "id": "MOB-002",
                "title": "Certificate Pinning",
                "description": "Verify certificate pinning for mobile apps",
                "guidance": """Check for:
- SSL pinning implemented
- Pin to leaf certificate or public key
- Backup pins configured
- Pin validation on all network requests
- Proper error handling for pin failures""",
                "severity": "medium",
                "compliance": ["pci_dss"],
            },
            {
                "id": "MOB-003",
                "title": "Offline Security",
                "description": "Verify security in offline mode",
                "guidance": """Check for:
- Offline data encryption
- Session validation on reconnect
- Sync conflict handling
- Offline action queue security
- Data purge on logout""",
                "severity": "medium",
                "compliance": ["hipaa"],
            },
        ],
    },
}


class SecurityChecklist:
    """
    Interactive security checklist for manual audits.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.llm = MultiLLMClient()
        self.checklist = self._load_checklist()

    def _load_checklist(self) -> dict:
        """Load the security checklist."""
        return SECURITY_CHECKLIST

    def get_all_items(self) -> list[ChecklistItem]:
        """Get all checklist items as a flat list."""
        items = []
        for category_key, category in self.checklist.items():
            for item_data in category["items"]:
                items.append(ChecklistItem(
                    id=item_data["id"],
                    category=category["name"],
                    title=item_data["title"],
                    description=item_data["description"],
                    guidance=item_data["guidance"],
                    severity=item_data["severity"],
                    compliance=item_data.get("compliance", []),
                ))
        return items

    def get_items_by_category(self, category: str) -> list[ChecklistItem]:
        """Get checklist items for a specific category."""
        if category not in self.checklist:
            return []

        cat_data = self.checklist[category]
        items = []
        for item_data in cat_data["items"]:
            items.append(ChecklistItem(
                id=item_data["id"],
                category=cat_data["name"],
                title=item_data["title"],
                description=item_data["description"],
                guidance=item_data["guidance"],
                severity=item_data["severity"],
                compliance=item_data.get("compliance", []),
            ))
        return items

    def get_items_by_compliance(self, framework: str) -> list[ChecklistItem]:
        """Get checklist items for a specific compliance framework."""
        items = []
        for category in self.checklist.values():
            for item_data in category["items"]:
                if framework.lower() in [c.lower() for c in item_data.get("compliance", [])]:
                    items.append(ChecklistItem(
                        id=item_data["id"],
                        category=category["name"],
                        title=item_data["title"],
                        description=item_data["description"],
                        guidance=item_data["guidance"],
                        severity=item_data["severity"],
                        compliance=item_data.get("compliance", []),
                    ))
        return items

    async def get_help(self, item_id: str, context: str = "") -> str:
        """Get AI-powered help for a checklist item."""
        item = None
        for category in self.checklist.values():
            for item_data in category["items"]:
                if item_data["id"] == item_id:
                    item = item_data
                    break

        if not item:
            return f"Item {item_id} not found."

        prompt = f"""Provide detailed guidance for this security audit check:

Item: {item['title']}
Description: {item['description']}
Severity: {item['severity']}

Base Guidance:
{item['guidance']}

{"Additional Context: " + context if context else ""}

Provide:
1. Step-by-step verification process
2. Common vulnerabilities to look for
3. Tools that can help verify this check
4. Code examples of secure vs insecure implementations
5. Quick remediation steps if issues are found

Be specific and practical."""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.3,
            max_tokens=1500,
        )

        return response.content

    def create_audit(self, project_name: str, auditor: str) -> ChecklistResult:
        """Create a new audit session."""
        return ChecklistResult(
            project_name=project_name,
            auditor=auditor,
            started_at=datetime.utcnow(),
            items=self.get_all_items(),
        )

    def update_item(
        self,
        audit: ChecklistResult,
        item_id: str,
        status: str,
        notes: str = "",
        evidence: str = "",
    ):
        """Update an item's status in an audit."""
        for item in audit.items:
            if item.id == item_id:
                item.status = status
                item.notes = notes
                item.evidence = evidence
                break

    def generate_summary(self, audit: ChecklistResult) -> dict:
        """Generate audit summary."""
        total = len(audit.items)
        passed = sum(1 for i in audit.items if i.status == "pass")
        failed = sum(1 for i in audit.items if i.status == "fail")
        na = sum(1 for i in audit.items if i.status == "na")
        pending = sum(1 for i in audit.items if i.status == "pending")

        # Count by severity
        critical_failed = sum(1 for i in audit.items if i.status == "fail" and i.severity == "critical")
        high_failed = sum(1 for i in audit.items if i.status == "fail" and i.severity == "high")

        # Compliance status
        compliance_status = {}
        for framework in ["hipaa", "pci_dss", "soc2"]:
            framework_items = [i for i in audit.items if framework in i.compliance]
            framework_passed = sum(1 for i in framework_items if i.status == "pass")
            framework_failed = sum(1 for i in framework_items if i.status == "fail")
            compliance_status[framework] = {
                "total": len(framework_items),
                "passed": framework_passed,
                "failed": framework_failed,
                "score": int((framework_passed / len(framework_items) * 100)) if framework_items else 100,
            }

        return {
            "total_items": total,
            "passed": passed,
            "failed": failed,
            "not_applicable": na,
            "pending": pending,
            "completion_percentage": int(((passed + failed + na) / total) * 100) if total else 0,
            "pass_rate": int((passed / (passed + failed)) * 100) if (passed + failed) else 100,
            "critical_failures": critical_failed,
            "high_failures": high_failed,
            "compliance": compliance_status,
            "risk_level": "critical" if critical_failed > 0 else ("high" if high_failed > 0 else "low"),
        }

    async def export_report(
        self,
        audit: ChecklistResult,
        output_path: Path,
        format: str = "html",
    ):
        """Export audit report."""
        audit.finished_at = datetime.utcnow()
        audit.summary = self.generate_summary(audit)

        if format == "html":
            await self._export_html(audit, output_path)
        elif format == "json":
            await self._export_json(audit, output_path)
        elif format == "markdown":
            await self._export_markdown(audit, output_path)

    async def _export_html(self, audit: ChecklistResult, output_path: Path):
        """Export audit as HTML report."""
        from jinja2 import Template

        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - {{ project_name }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; background: #f8f9fa; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .meta { display: flex; gap: 30px; margin-top: 15px; font-size: 0.9em; opacity: 0.9; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
        .stat { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat h2 { margin: 0 0 5px 0; font-size: 2em; }
        .stat.pass { color: #28a745; }
        .stat.fail { color: #dc3545; }
        .category { background: white; border-radius: 8px; margin-bottom: 20px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .category-header { background: #f1f3f5; padding: 15px 20px; font-weight: bold; border-bottom: 1px solid #dee2e6; }
        .item { padding: 15px 20px; border-bottom: 1px solid #f1f3f5; }
        .item:last-child { border-bottom: none; }
        .item-header { display: flex; justify-content: space-between; align-items: center; }
        .item-id { font-family: monospace; color: #6c757d; margin-right: 10px; }
        .status-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }
        .status-pass { background: #d4edda; color: #155724; }
        .status-fail { background: #f8d7da; color: #721c24; }
        .status-pending { background: #fff3cd; color: #856404; }
        .status-na { background: #e9ecef; color: #495057; }
        .severity { font-size: 0.8em; padding: 2px 8px; border-radius: 4px; margin-left: 10px; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #28a745; color: white; }
        .notes { margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 4px; font-size: 0.9em; }
        .compliance { margin-top: 30px; }
        .compliance-framework { display: inline-block; background: white; padding: 15px 25px; border-radius: 8px; margin-right: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .compliance-score { font-size: 1.5em; font-weight: bold; }
        .compliance-pass { color: #28a745; }
        .compliance-warn { color: #ffc107; }
        .compliance-fail { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Audit Report</h1>
            <p>{{ project_name }}</p>
            <div class="meta">
                <span>Auditor: {{ auditor }}</span>
                <span>Date: {{ started_at }}</span>
                <span>Completion: {{ summary.completion_percentage }}%</span>
            </div>
        </div>

        <div class="summary">
            <div class="stat pass">
                <h2>{{ summary.passed }}</h2>
                <p>Passed</p>
            </div>
            <div class="stat fail">
                <h2>{{ summary.failed }}</h2>
                <p>Failed</p>
            </div>
            <div class="stat">
                <h2>{{ summary.not_applicable }}</h2>
                <p>N/A</p>
            </div>
            <div class="stat">
                <h2>{{ summary.pass_rate }}%</h2>
                <p>Pass Rate</p>
            </div>
        </div>

        <div class="compliance">
            <h3>Compliance Status</h3>
            {% for framework, status in summary.compliance.items() %}
            <div class="compliance-framework">
                <div>{{ framework | upper }}</div>
                <div class="compliance-score {{ 'compliance-pass' if status.score >= 80 else ('compliance-warn' if status.score >= 60 else 'compliance-fail') }}">
                    {{ status.score }}%
                </div>
                <small>{{ status.passed }}/{{ status.total }} passed</small>
            </div>
            {% endfor %}
        </div>

        <h2 style="margin-top: 30px;">Detailed Results</h2>

        {% for category, items in items_by_category.items() %}
        <div class="category">
            <div class="category-header">{{ category }}</div>
            {% for item in items %}
            <div class="item">
                <div class="item-header">
                    <div>
                        <span class="item-id">{{ item.id }}</span>
                        <strong>{{ item.title }}</strong>
                        <span class="severity severity-{{ item.severity }}">{{ item.severity }}</span>
                    </div>
                    <span class="status-badge status-{{ item.status }}">{{ item.status | upper }}</span>
                </div>
                <p style="margin: 10px 0 0 0; color: #666;">{{ item.description }}</p>
                {% if item.notes %}
                <div class="notes"><strong>Notes:</strong> {{ item.notes }}</div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """)

        # Group items by category
        items_by_category = {}
        for item in audit.items:
            if item.category not in items_by_category:
                items_by_category[item.category] = []
            items_by_category[item.category].append({
                "id": item.id,
                "title": item.title,
                "description": item.description,
                "severity": item.severity,
                "status": item.status,
                "notes": item.notes,
            })

        html = template.render(
            project_name=audit.project_name,
            auditor=audit.auditor,
            started_at=audit.started_at.strftime("%Y-%m-%d %H:%M"),
            summary=audit.summary,
            items_by_category=items_by_category,
        )

        output_path.write_text(html)

    async def _export_json(self, audit: ChecklistResult, output_path: Path):
        """Export audit as JSON."""
        report = {
            "project_name": audit.project_name,
            "auditor": audit.auditor,
            "started_at": audit.started_at.isoformat(),
            "finished_at": audit.finished_at.isoformat() if audit.finished_at else None,
            "summary": audit.summary,
            "items": [
                {
                    "id": item.id,
                    "category": item.category,
                    "title": item.title,
                    "description": item.description,
                    "severity": item.severity,
                    "compliance": item.compliance,
                    "status": item.status,
                    "notes": item.notes,
                    "evidence": item.evidence,
                }
                for item in audit.items
            ],
        }

        output_path.write_text(json.dumps(report, indent=2))

    async def _export_markdown(self, audit: ChecklistResult, output_path: Path):
        """Export audit as Markdown."""
        lines = [
            f"# Security Audit Report: {audit.project_name}",
            "",
            f"**Auditor:** {audit.auditor}",
            f"**Date:** {audit.started_at.strftime('%Y-%m-%d')}",
            f"**Completion:** {audit.summary['completion_percentage']}%",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Passed | {audit.summary['passed']} |",
            f"| Failed | {audit.summary['failed']} |",
            f"| N/A | {audit.summary['not_applicable']} |",
            f"| Pass Rate | {audit.summary['pass_rate']}% |",
            "",
            "## Compliance",
            "",
        ]

        for framework, status in audit.summary.get("compliance", {}).items():
            lines.append(f"- **{framework.upper()}**: {status['score']}% ({status['passed']}/{status['total']} passed)")

        lines.extend(["", "## Detailed Results", ""])

        current_category = None
        for item in audit.items:
            if item.category != current_category:
                current_category = item.category
                lines.extend([f"### {current_category}", ""])

            status_emoji = {"pass": "", "fail": "", "pending": "", "na": ""}
            lines.append(f"- [{status_emoji.get(item.status, '')}] **{item.id}**: {item.title} ({item.severity})")
            if item.notes:
                lines.append(f"  - Notes: {item.notes}")

        output_path.write_text("\n".join(lines))


def run_interactive_checklist(project_name: str, auditor: str):
    """Run the checklist in interactive CLI mode."""
    import asyncio
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    checklist = SecurityChecklist()
    audit = checklist.create_audit(project_name, auditor)

    console.print(Panel.fit(
        f"[bold blue]Security Audit: {project_name}[/bold blue]\n"
        f"Auditor: {auditor}\n"
        f"Total Items: {len(audit.items)}",
        title="SafeguardAI Security Checklist",
    ))

    # Group by category
    categories = {}
    for item in audit.items:
        if item.category not in categories:
            categories[item.category] = []
        categories[item.category].append(item)

    for category_name, items in categories.items():
        console.print(f"\n[bold cyan]== {category_name} ==[/bold cyan]\n")

        for item in items:
            # Show item
            console.print(f"[bold]{item.id}[/bold]: {item.title}")
            console.print(f"[dim]{item.description}[/dim]")
            console.print(f"[yellow]Severity:[/yellow] {item.severity}")

            if item.compliance:
                console.print(f"[green]Compliance:[/green] {', '.join(item.compliance)}")

            # Show guidance
            if Confirm.ask("Show guidance?", default=False):
                console.print(Panel(item.guidance, title="Guidance"))

            # Get status
            status = Prompt.ask(
                "Status",
                choices=["pass", "fail", "na", "skip"],
                default="skip",
            )

            if status != "skip":
                notes = ""
                if status == "fail":
                    notes = Prompt.ask("Notes (describe the issue)", default="")
                elif status == "pass":
                    notes = Prompt.ask("Evidence/Notes (optional)", default="")

                checklist.update_item(audit, item.id, status, notes)

            console.print("")

    # Generate summary
    audit.summary = checklist.generate_summary(audit)

    # Show summary
    table = Table(title="Audit Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Passed", str(audit.summary["passed"]))
    table.add_row("Failed", str(audit.summary["failed"]))
    table.add_row("N/A", str(audit.summary["not_applicable"]))
    table.add_row("Pass Rate", f"{audit.summary['pass_rate']}%")
    table.add_row("Risk Level", audit.summary["risk_level"])

    console.print(table)

    # Export
    if Confirm.ask("Export report?", default=True):
        format_choice = Prompt.ask("Format", choices=["html", "json", "markdown"], default="html")
        output_file = Path(f"security-audit-{project_name}-{datetime.now().strftime('%Y%m%d')}.{format_choice}")
        asyncio.run(checklist.export_report(audit, output_file, format_choice))
        console.print(f"[green]Report saved to: {output_file}[/green]")
