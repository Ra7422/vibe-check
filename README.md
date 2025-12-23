# SafeguardAI Dev Tools

Reusable AI-powered development tools for automated testing and security analysis. Built with multi-LLM orchestration (Claude, OpenAI, Gemini, Grok) for comprehensive coverage.

## Tools Included

### 1. AI Flow Tester
Automated testing tool that uses multiple LLMs to simulate human behavior and discover issues.

**Features:**
- Natural language test generation
- Multi-LLM orchestration (consensus, routing, adversarial patterns)
- Self-healing selectors with AI-powered recovery
- Visual + DOM discrepancy detection
- User persona simulation (default, tech-naive, power-user, adversarial, mobile, accessibility)
- Cross-platform support (Web, Mobile, PWA)
- Comprehensive HTML/JSON reports

### 2. Security Scanner
Automated security analysis with multi-LLM threat assessment.

**Features:**
- OWASP Top 10 vulnerability detection
- Secret/credential scanning (AWS, GitHub, Stripe, JWT, etc.)
- Dependency vulnerability checks (npm, pip)
- Configuration security analysis
- Multi-LLM consensus for threat assessment
- Compliance checking (HIPAA, PCI DSS, SOC2)
- SARIF output for GitHub/GitLab integration

### 3. Security Checklist
Interactive manual audit tool with comprehensive coverage.

**Features:**
- 30+ security checks organized by category
- Compliance mapping (HIPAA, PCI DSS, SOC2)
- AI-powered guidance and explanations
- Interactive CLI mode
- Export to HTML, JSON, Markdown
- Progress tracking and scoring

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/safeguardAi-dev-tools.git
cd safeguardAi-dev-tools

# Install in development mode
pip install -e .

# Install Playwright browsers
playwright install chromium
```

## Quick Start

```bash
# Initialize configuration in your project
safeguard init

# Run AI Flow Tester against a web app
safeguard test --url https://your-app.com --persona default

# Run Security Scanner on a codebase
safeguard scan --path ./your-project --compliance hipaa,pci_dss

# Run interactive Security Checklist
safeguard check --project "MyApp" --auditor "John Doe"
```

## CLI Commands

### `safeguard test` - AI Flow Testing
```bash
safeguard test --url https://app.com [OPTIONS]

Options:
  --url, -u        Target URL (required)
  --persona, -p    User persona: default, tech-naive, power-user, adversarial, mobile, accessibility
  --headless       Run browser in headless mode (default: true)
  --output, -o     Output report path
  --config, -c     Config file path
```

### `safeguard scan` - Security Scanning
```bash
safeguard scan --path ./project [OPTIONS]

Options:
  --path, -p       Project path to scan (required)
  --checks         Comma-separated: owasp,secrets,dependencies,config
  --compliance     Comma-separated: hipaa,pci_dss,soc2
  --format, -f     Report format: html, json, sarif
  --output, -o     Output report path
```

### `safeguard check` - Security Checklist
```bash
safeguard check --project "Name" [OPTIONS]

Options:
  --project, -p    Project name (required)
  --auditor, -a    Auditor name
  --framework, -f  Focus on: hipaa, pci_dss, soc2
  --output, -o     Output report path
  --format         Report format: html, json, markdown
```

### `safeguard init` - Initialize Config
```bash
safeguard init --path ./project
```

## Configuration

Create a `.safeguard.yaml` in your project root (or run `safeguard init`):

```yaml
project:
  name: "My Project"
  type: "web"  # web, mobile, pwa, api

ai_flow_tester:
  personas:
    - default
    - tech-naive
    - adversarial
  llm_providers:
    primary: gemini-flash
    vision: gemini
    consensus: [claude, openai, gemini]
    adversarial: grok
  playwright:
    headless: true
    timeout_ms: 30000
    video: true

security_scanner:
  checks:
    owasp: true
    secrets: true
    dependencies: true
    config: true
  compliance_frameworks:
    - hipaa
    - pci_dss
  exclude_patterns:
    - node_modules/
    - .git/
    - __pycache__/
```

## Environment Variables

```bash
# LLM API Keys (required)
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export GOOGLE_API_KEY=...
export XAI_API_KEY=...  # For Grok

# Optional
export SAFEGUARD_CONFIG_PATH=.safeguard.yaml
```

## Multi-LLM Orchestration Patterns

The tools use several orchestration patterns:

1. **Router Pattern**: Route queries to the best LLM based on task type
2. **Consensus Pattern**: Query multiple LLMs and require agreement
3. **Adversarial Pattern**: Use one LLM to attack/critique another's output
4. **Specialist Pattern**: Use specific LLMs for their strengths (Gemini for large context, Claude for reasoning, Grok for creative/adversarial)

## Project Structure

```
safeguardAi-dev-tools/
├── ai_flow_tester/           # AI testing tool
│   ├── __init__.py
│   └── src/
│       ├── runner.py         # Main test orchestrator
│       ├── generators.py     # Test journey generation
│       ├── analyzers.py      # Visual + DOM analysis
│       └── selectors.py      # Self-healing selectors
│
├── security_scanner/         # Security scanning tool
│   ├── __init__.py
│   └── src/
│       ├── scanner.py        # Main security scanner
│       └── checklist.py      # Interactive checklist
│
├── shared/                   # Shared utilities
│   └── src/
│       ├── llm_client.py     # Multi-LLM client
│       └── cli.py            # CLI entry point
│
├── pyproject.toml            # Package configuration
├── .safeguard.example.yaml   # Example configuration
└── README.md
```

## User Personas

The AI Flow Tester supports these personas:

| Persona | Description | Behaviors |
|---------|-------------|-----------|
| `default` | Average user | Normal typing, occasional mistakes |
| `tech-naive` | Non-technical user | Slow typing, frequent mistakes, needs help |
| `power-user` | Experienced user | Fast typing, keyboard shortcuts |
| `adversarial` | Security tester | Injection attempts, boundary testing |
| `mobile` | Mobile user | Touch interface, small screen |
| `accessibility` | Assistive tech user | Screen reader, keyboard only |

## Security Checklist Categories

- **Authentication & Authorization**: Password policy, MFA, session management, access control
- **Data Protection**: Encryption at rest/transit, PII handling, PHI protection
- **Input Validation**: SQL injection, XSS, CSRF, file uploads
- **Infrastructure**: Security headers, error handling, logging, secrets management
- **API Security**: Authentication, rate limiting, CORS
- **AI/LLM Security**: Prompt injection, data privacy, output validation
- **Mobile/PWA Security**: Secure storage, certificate pinning, offline security

## Compliance Support

| Framework | Coverage |
|-----------|----------|
| HIPAA | PHI encryption, access logging, audit controls |
| PCI DSS | Cardholder data, vulnerability management, access control |
| SOC2 | Security controls, availability, confidentiality |

## Output Formats

- **HTML**: Rich interactive reports with styling
- **JSON**: Machine-readable for CI/CD integration
- **SARIF**: GitHub/GitLab security tab integration
- **Markdown**: Documentation-friendly format

## License

Internal use only.
