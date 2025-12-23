"""
SafeguardAI CLI - Main entry point for all tools.

Usage:
    safeguard test --url https://app.com --persona default
    safeguard scan --path /path/to/project --output report.html
    safeguard check --path /path/to/project  # Quick security checklist
"""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

app = typer.Typer(
    name="safeguard",
    help="AI-powered testing and security tools",
    add_completion=False,
)
console = Console()


@app.command()
def test(
    url: str = typer.Option(..., "--url", "-u", help="URL of application to test"),
    persona: str = typer.Option("default", "--persona", "-p", help="User persona to simulate"),
    headless: bool = typer.Option(True, "--headless/--headed", help="Run browser headless"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output report path"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
):
    """
    Run AI Flow Tester against a web application.

    Examples:
        safeguard test --url https://myapp.com
        safeguard test --url https://myapp.com --persona tech-naive --headed
    """
    console.print(Panel.fit(
        f"[bold blue]AI Flow Tester[/bold blue]\n"
        f"Target: {url}\n"
        f"Persona: {persona}",
        title="SafeguardAI",
    ))

    # Import here to avoid slow startup
    from ai_flow_tester.src.runner import AIFlowTestRunner

    async def run():
        runner = AIFlowTestRunner(config_path=config)
        results = await runner.run(
            url=url,
            persona=persona,
            headless=headless,
        )

        if output:
            await runner.generate_report(results, output)
            console.print(f"\n[green]Report saved to: {output}[/green]")

        return results

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Running AI Flow Tests...", total=None)
        results = asyncio.run(run())

    # Summary
    passed = sum(1 for r in results.get("steps", []) if r.get("status") == "passed")
    failed = sum(1 for r in results.get("steps", []) if r.get("status") == "failed")

    console.print(f"\n[bold]Results:[/bold] {passed} passed, {failed} failed")

    if failed > 0:
        raise typer.Exit(code=1)


@app.command()
def scan(
    path: Path = typer.Option(".", "--path", "-p", help="Path to project to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output report path"),
    checks: Optional[str] = typer.Option(None, "--checks", help="Comma-separated checks: owasp,secrets,dependencies,config"),
    compliance: Optional[str] = typer.Option(None, "--compliance", help="Compliance frameworks: hipaa,pci_dss,soc2"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, sarif"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
):
    """
    Run Security Scanner on a codebase.

    Examples:
        safeguard scan --path ./my-project
        safeguard scan --path ./my-project --checks secrets,dependencies --output report.html
        safeguard scan --path ./my-project --compliance hipaa,pci_dss
    """
    console.print(Panel.fit(
        f"[bold red]Security Scanner[/bold red]\n"
        f"Target: {path.absolute()}",
        title="SafeguardAI",
    ))

    # Import here to avoid slow startup
    from security_scanner.src.scanner import SecurityScanner

    async def run():
        scanner = SecurityScanner(config_path=config)

        check_list = checks.split(",") if checks else None
        compliance_list = compliance.split(",") if compliance else None

        results = await scanner.scan(
            project_path=path,
            checks=check_list,
            compliance=compliance_list,
        )

        # Generate report
        output_path = output or Path(f"security-report-{scanner.scan_id}.{format}")
        await scanner.generate_report(results, output_path, format=format)
        console.print(f"\n[green]Report saved to: {output_path}[/green]")

        return results

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Scanning for security issues...", total=None)
        results = asyncio.run(run())

    # Summary
    summary = results.summary
    console.print(f"\n[bold]Scan Results:[/bold]")
    console.print(f"  Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")

    by_severity = summary.get("by_severity", {})
    if by_severity.get("critical", 0):
        console.print(f"  [red]Critical: {by_severity['critical']}[/red]")
    if by_severity.get("high", 0):
        console.print(f"  [yellow]High: {by_severity['high']}[/yellow]")
    if by_severity.get("medium", 0):
        console.print(f"  [blue]Medium: {by_severity['medium']}[/blue]")
    if by_severity.get("low", 0):
        console.print(f"  [dim]Low: {by_severity['low']}[/dim]")

    console.print(f"\n  Risk Score: {summary.get('risk_score', 0)}/100")

    if by_severity.get("critical", 0) > 0:
        raise typer.Exit(code=2)
    elif by_severity.get("high", 0) > 0:
        raise typer.Exit(code=1)


@app.command()
def check(
    project: str = typer.Option(..., "--project", "-p", help="Project name"),
    auditor: str = typer.Option("Security Team", "--auditor", "-a", help="Auditor name"),
    framework: Optional[str] = typer.Option(None, "--framework", "-f", help="Compliance framework: hipaa, pci_dss, soc2"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output report path"),
    format: str = typer.Option("html", "--format", help="Report format: html, json, markdown"),
):
    """
    Run interactive security checklist (manual audit guide).

    Examples:
        safeguard check --project "MyApp" --auditor "John Doe"
        safeguard check --project "MyApp" --framework hipaa --output audit.html
    """
    console.print(Panel.fit(
        f"[bold yellow]Security Checklist[/bold yellow]\n"
        f"Project: {project}\n"
        f"Auditor: {auditor}",
        title="SafeguardAI",
    ))

    from security_scanner.src.checklist import SecurityChecklist, run_interactive_checklist

    if framework:
        # Show only framework-specific items
        checklist = SecurityChecklist()
        items = checklist.get_items_by_compliance(framework)
        console.print(f"\n[cyan]Showing {len(items)} items for {framework.upper()} compliance[/cyan]\n")

        for item in items:
            console.print(f"[bold]{item.id}[/bold]: {item.title} [{item.severity}]")
            console.print(f"  {item.description}")
            console.print("")
    else:
        # Run full interactive checklist
        run_interactive_checklist(project, auditor)


@app.command()
def init(
    path: Path = typer.Option(".", "--path", "-p", help="Path to initialize"),
):
    """
    Initialize SafeguardAI config in a project.

    Creates a .safeguard.yaml configuration file.
    """
    config_path = path / ".safeguard.yaml"

    if config_path.exists():
        console.print(f"[yellow]Config already exists at {config_path}[/yellow]")
        raise typer.Exit(code=1)

    default_config = """# SafeguardAI Configuration
project:
  name: "My Project"
  type: "web"  # web, mobile, pwa, api

ai_flow_tester:
  personas:
    - default
    - tech-naive
    - power-user
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
    screenshot_on_failure: true

security_scanner:
  checks:
    - owasp-top-10
    - dependencies
    - secrets
    - config
    - code-quality
  compliance: []  # Add: hipaa, pci, gdpr as needed
  exclude_paths:
    - node_modules
    - .git
    - __pycache__
    - .venv
  severity_threshold: medium  # Fail on medium+ severity
"""

    config_path.write_text(default_config)
    console.print(f"[green]Created config at {config_path}[/green]")


if __name__ == "__main__":
    app()
