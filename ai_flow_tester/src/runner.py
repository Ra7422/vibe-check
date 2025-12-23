"""
AI Flow Test Runner - Main orchestrator for AI-powered testing.

This runner:
1. Loads configuration and personas
2. Uses multi-LLM to generate test journeys
3. Executes tests with Playwright
4. Analyzes results with vision + DOM comparison
5. Generates reports
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from playwright.async_api import async_playwright, Page, Browser

from shared.src.llm_client import MultiLLMClient, LLMProvider
from .generators import JourneyGenerator
from .analyzers import VisualDOMAnalyzer
from .selectors import SmartSelector


@dataclass
class TestStep:
    description: str
    action: str  # click, fill, navigate, wait, assert
    selector: Optional[str] = None
    value: Optional[str] = None
    expected: Optional[str] = None
    delay_ms: int = 500


@dataclass
class StepResult:
    step: TestStep
    status: str  # passed, failed, skipped
    duration_ms: int = 0
    screenshot: Optional[bytes] = None
    error: Optional[str] = None
    analysis: Optional[dict] = None


@dataclass
class TestRunResult:
    url: str
    persona: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    steps: list[StepResult] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    total_cost: float = 0.0


class AIFlowTestRunner:
    """
    Main runner for AI-powered flow testing.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config = self._load_config(config_path)
        self.llm = MultiLLMClient()
        self.generator = JourneyGenerator(self.llm)
        self.analyzer = VisualDOMAnalyzer(self.llm)
        self.selector = SmartSelector(self.llm)

    def _load_config(self, config_path: Optional[Path]) -> dict:
        """Load configuration from file or use defaults."""
        if config_path and config_path.exists():
            import yaml
            return yaml.safe_load(config_path.read_text())

        # Check for .safeguard.yaml in current directory
        default_path = Path(".safeguard.yaml")
        if default_path.exists():
            import yaml
            return yaml.safe_load(default_path.read_text())

        # Default configuration
        return {
            "ai_flow_tester": {
                "playwright": {
                    "headless": True,
                    "timeout_ms": 30000,
                    "video": True,
                    "screenshot_on_failure": True,
                },
                "llm_providers": {
                    "primary": "gemini-flash",
                    "vision": "gemini",
                    "consensus": ["claude", "openai", "gemini"],
                },
            }
        }

    async def run(
        self,
        url: str,
        persona: str = "default",
        headless: bool = True,
        max_steps: int = 50,
    ) -> dict:
        """
        Run AI-powered test against a URL.

        Args:
            url: Target application URL
            persona: User persona to simulate
            headless: Run browser in headless mode
            max_steps: Maximum number of steps to execute

        Returns:
            TestRunResult as dictionary
        """
        result = TestRunResult(
            url=url,
            persona=persona,
            started_at=datetime.utcnow(),
        )

        async with async_playwright() as p:
            # Launch browser
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                record_video_dir="./test-videos" if self.config.get("ai_flow_tester", {}).get("playwright", {}).get("video") else None,
            )
            page = await context.new_page()

            try:
                # Navigate to URL
                await page.goto(url, wait_until="networkidle")

                # Get page context for LLM
                page_context = await self._get_page_context(page)

                # Generate test journey using AI
                journey = await self.generator.generate_journey(
                    page_context=page_context,
                    persona=persona,
                    url=url,
                )

                # Execute each step
                for i, step in enumerate(journey[:max_steps]):
                    step_result = await self._execute_step(page, step)
                    result.steps.append(step_result)

                    # If step failed, optionally try to heal and retry
                    if step_result.status == "failed" and step.selector:
                        healed_selector = await self.selector.heal(
                            original_selector=step.selector,
                            html=await page.content(),
                            description=step.description,
                        )
                        if healed_selector and healed_selector != step.selector:
                            step.selector = healed_selector
                            retry_result = await self._execute_step(page, step)
                            if retry_result.status == "passed":
                                result.steps[-1] = retry_result
                                result.steps[-1].analysis = {"healed": True}

                # Final analysis
                final_screenshot = await page.screenshot()
                final_html = await page.content()
                final_analysis = await self.analyzer.analyze(
                    screenshot=final_screenshot,
                    html=final_html,
                    url=page.url,
                )

                result.summary = {
                    "total_steps": len(result.steps),
                    "passed": sum(1 for s in result.steps if s.status == "passed"),
                    "failed": sum(1 for s in result.steps if s.status == "failed"),
                    "final_analysis": final_analysis,
                }

            except Exception as e:
                result.summary["error"] = str(e)

            finally:
                result.finished_at = datetime.utcnow()
                await browser.close()

        return self._result_to_dict(result)

    async def _get_page_context(self, page: Page) -> dict:
        """Extract page context for LLM analysis."""
        html = await page.content()
        title = await page.title()
        url = page.url

        # Get visible text
        visible_text = await page.evaluate("""
            () => document.body.innerText.substring(0, 5000)
        """)

        # Get interactive elements
        interactive = await page.evaluate("""
            () => {
                const elements = document.querySelectorAll('button, a, input, select, textarea, [role="button"]');
                return Array.from(elements).slice(0, 50).map(el => ({
                    tag: el.tagName,
                    text: el.innerText?.substring(0, 100) || el.value?.substring(0, 100) || '',
                    type: el.type || '',
                    id: el.id || '',
                    class: el.className || '',
                    placeholder: el.placeholder || '',
                }));
            }
        """)

        return {
            "url": url,
            "title": title,
            "html_preview": html[:10000],
            "visible_text": visible_text,
            "interactive_elements": interactive,
        }

    async def _execute_step(self, page: Page, step: TestStep) -> StepResult:
        """Execute a single test step."""
        import time
        start_time = time.time()

        try:
            if step.action == "navigate":
                await page.goto(step.value, wait_until="networkidle")

            elif step.action == "click":
                element = await self._find_element(page, step)
                await element.click()

            elif step.action == "fill":
                element = await self._find_element(page, step)
                await element.fill(step.value or "")

            elif step.action == "wait":
                await page.wait_for_selector(step.selector, timeout=self.config.get("ai_flow_tester", {}).get("playwright", {}).get("timeout_ms", 30000))

            elif step.action == "assert":
                element = await self._find_element(page, step)
                text = await element.text_content()
                assert step.expected in (text or ""), f"Expected '{step.expected}' not found in '{text}'"

            # Wait between steps (simulate human)
            await asyncio.sleep(step.delay_ms / 1000)

            duration_ms = int((time.time() - start_time) * 1000)
            return StepResult(
                step=step,
                status="passed",
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            screenshot = await page.screenshot() if self.config.get("ai_flow_tester", {}).get("playwright", {}).get("screenshot_on_failure") else None

            return StepResult(
                step=step,
                status="failed",
                duration_ms=duration_ms,
                error=str(e),
                screenshot=screenshot,
            )

    async def _find_element(self, page: Page, step: TestStep):
        """Find element using selector or AI-powered smart selector."""
        if step.selector:
            return page.locator(step.selector).first

        # Use AI to find element by description
        return await self.selector.find_by_description(
            page=page,
            description=step.description,
        )

    async def generate_report(self, results: dict, output_path: Path):
        """Generate HTML report from test results."""
        from jinja2 import Template

        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>AI Flow Test Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; }
        .header { margin-bottom: 30px; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; }
        .stat { padding: 20px; border-radius: 8px; background: #f5f5f5; }
        .stat.passed { background: #d4edda; }
        .stat.failed { background: #f8d7da; }
        .step { padding: 15px; margin: 10px 0; border-left: 4px solid #ccc; }
        .step.passed { border-color: #28a745; }
        .step.failed { border-color: #dc3545; background: #fff5f5; }
        .error { color: #dc3545; font-size: 0.9em; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI Flow Test Report</h1>
        <p>URL: {{ url }}</p>
        <p>Persona: {{ persona }}</p>
        <p>Run: {{ started_at }}</p>
    </div>

    <div class="summary">
        <div class="stat passed">
            <h2>{{ summary.passed }}</h2>
            <p>Passed</p>
        </div>
        <div class="stat failed">
            <h2>{{ summary.failed }}</h2>
            <p>Failed</p>
        </div>
        <div class="stat">
            <h2>{{ summary.total_steps }}</h2>
            <p>Total Steps</p>
        </div>
    </div>

    <h2>Steps</h2>
    {% for step in steps %}
    <div class="step {{ step.status }}">
        <strong>{{ step.step.action | upper }}</strong>: {{ step.step.description }}
        <br><small>Duration: {{ step.duration_ms }}ms</small>
        {% if step.error %}
        <div class="error">{{ step.error }}</div>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>
        """)

        html = template.render(**results)
        output_path.write_text(html)

    def _result_to_dict(self, result: TestRunResult) -> dict:
        """Convert TestRunResult to dictionary."""
        return {
            "url": result.url,
            "persona": result.persona,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "steps": [
                {
                    "step": {
                        "description": s.step.description,
                        "action": s.step.action,
                        "selector": s.step.selector,
                        "value": s.step.value,
                    },
                    "status": s.status,
                    "duration_ms": s.duration_ms,
                    "error": s.error,
                    "analysis": s.analysis,
                }
                for s in result.steps
            ],
            "summary": result.summary,
            "total_cost": result.total_cost,
        }
