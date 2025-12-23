#!/usr/bin/env python3
"""
Meedi8 Production Flow Tester

Tests critical user flows on the production site using Playwright.
Reports broken flows, UX issues, and accessibility problems.
"""

import asyncio
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from pathlib import Path

try:
    from playwright.async_api import async_playwright, Page, expect
except ImportError:
    print("Installing playwright...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "playwright", "-q"])
    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"])
    from playwright.async_api import async_playwright, Page, expect


@dataclass
class FlowResult:
    name: str
    status: str  # passed, failed, skipped
    duration_ms: int = 0
    steps_passed: int = 0
    steps_total: int = 0
    error: Optional[str] = None
    screenshot_path: Optional[str] = None
    notes: list = field(default_factory=list)


@dataclass
class FlowTestReport:
    url: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    flows: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


class Meedi8FlowTester:
    """Test critical flows on Meedi8 production."""

    def __init__(self, base_url: str = "https://meedi8.com"):
        self.base_url = base_url.rstrip("/")
        self.screenshots_dir = Path("./flow-test-screenshots")
        self.screenshots_dir.mkdir(exist_ok=True)

    async def run_all_flows(self, headless: bool = True) -> FlowTestReport:
        """Run all flow tests."""
        report = FlowTestReport(
            url=self.base_url,
            started_at=datetime.utcnow(),
        )

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            )

            # Run each flow test
            flows = [
                ("Landing Page Load", self.test_landing_page),
                ("Navigation Menu", self.test_navigation),
                ("Login Page Access", self.test_login_page),
                ("Signup Page Access", self.test_signup_page),
                ("Pricing Page", self.test_pricing_page),
                ("FAQ Page", self.test_faq_page),
                ("Community Page", self.test_community_page),
                ("Mobile Responsiveness", self.test_mobile_responsive),
                ("OAuth Buttons Present", self.test_oauth_buttons),
                ("Form Validation", self.test_form_validation),
                ("Error Handling", self.test_error_handling),
                ("Page Load Performance", self.test_performance),
            ]

            for flow_name, flow_func in flows:
                print(f"\n{'='*60}")
                print(f"Testing: {flow_name}")
                print('='*60)

                page = await context.new_page()
                result = await self._run_flow(page, flow_name, flow_func)
                report.flows.append(result)
                await page.close()

                # Print result
                status_icon = "✅" if result.status == "passed" else "❌" if result.status == "failed" else "⚠️"
                print(f"{status_icon} {flow_name}: {result.status.upper()}")
                if result.error:
                    print(f"   Error: {result.error}")
                for note in result.notes:
                    print(f"   Note: {note}")

            await browser.close()

        report.finished_at = datetime.utcnow()
        report.summary = {
            "total": len(report.flows),
            "passed": sum(1 for f in report.flows if f.status == "passed"),
            "failed": sum(1 for f in report.flows if f.status == "failed"),
            "skipped": sum(1 for f in report.flows if f.status == "skipped"),
        }

        return report

    async def _run_flow(self, page: Page, name: str, func) -> FlowResult:
        """Execute a single flow test with error handling."""
        import time
        start = time.time()
        result = FlowResult(name=name, status="passed", steps_total=1)

        try:
            await func(page, result)
            result.status = "passed" if not result.error else "failed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            # Take screenshot on failure
            try:
                screenshot_path = self.screenshots_dir / f"{name.replace(' ', '_').lower()}_error.png"
                await page.screenshot(path=str(screenshot_path))
                result.screenshot_path = str(screenshot_path)
            except:
                pass

        result.duration_ms = int((time.time() - start) * 1000)
        return result

    # ==================== FLOW TESTS ====================

    async def test_landing_page(self, page: Page, result: FlowResult):
        """Test landing page loads correctly."""
        result.steps_total = 5

        # Navigate to home
        response = await page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(2000)  # Wait for React to render
        result.steps_passed += 1

        # Check response status
        if response.status != 200:
            result.error = f"Landing page returned status {response.status}"
            return

        result.steps_passed += 1

        # Check for logo
        logo = page.locator("img[alt*='logo' i], img[alt*='meedi' i], svg[class*='logo' i]").first
        if await logo.count() == 0:
            result.notes.append("Logo not found or not properly labeled")
        else:
            result.steps_passed += 1

        # Check for main heading
        h1 = page.locator("h1").first
        if await h1.count() > 0:
            heading_text = await h1.text_content()
            result.notes.append(f"Main heading: '{heading_text[:50]}...'")
            result.steps_passed += 1
        else:
            result.notes.append("No H1 heading found - SEO issue")

        # Check for CTA buttons
        cta_buttons = page.locator("a[href*='signup'], a[href*='login'], button:has-text('Start'), button:has-text('Get Started')")
        cta_count = await cta_buttons.count()
        if cta_count > 0:
            result.steps_passed += 1
            result.notes.append(f"Found {cta_count} CTA buttons")
        else:
            result.notes.append("No clear CTA buttons found")

    async def test_navigation(self, page: Page, result: FlowResult):
        """Test main navigation works."""
        result.steps_total = 4

        await page.goto(self.base_url, wait_until="domcontentloaded")
        result.steps_passed += 1

        # Look for navigation elements
        nav = page.locator("nav, header, [role='navigation']").first
        if await nav.count() == 0:
            result.notes.append("No semantic navigation element found")

        # Check for common nav links
        nav_links = ["pricing", "faq", "community", "login", "signup", "about"]
        found_links = []

        for link in nav_links:
            locator = page.locator(f"a[href*='{link}' i]")
            if await locator.count() > 0:
                found_links.append(link)

        result.notes.append(f"Nav links found: {', '.join(found_links)}")
        result.steps_passed += 1

        # Test clicking a nav link
        if "faq" in found_links:
            await page.click(f"a[href*='faq' i]")
            await page.wait_for_load_state("networkidle")
            if "faq" in page.url.lower():
                result.steps_passed += 1
            else:
                result.notes.append("FAQ link didn't navigate correctly")

        result.steps_passed += 1

    async def test_login_page(self, page: Page, result: FlowResult):
        """Test login page functionality."""
        result.steps_total = 6

        await page.goto(f"{self.base_url}/login", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check page loaded
        if page.url and "login" in page.url.lower():
            result.steps_passed += 1
        else:
            result.notes.append(f"Redirected to: {page.url}")

        # Check for email field
        email_field = page.locator("input[type='email'], input[name='email'], input[placeholder*='email' i]").first
        if await email_field.count() > 0:
            result.steps_passed += 1
        else:
            result.error = "Email input field not found"
            return

        # Check for password field
        password_field = page.locator("input[type='password']").first
        if await password_field.count() > 0:
            result.steps_passed += 1
        else:
            result.error = "Password input field not found"
            return

        # Check for submit button
        submit_btn = page.locator("button[type='submit'], button:has-text('Login'), button:has-text('Sign in')").first
        if await submit_btn.count() > 0:
            result.steps_passed += 1
        else:
            result.notes.append("Submit button not clearly identified")

        # Check for signup link
        signup_link = page.locator("a[href*='signup'], a:has-text('Sign up'), a:has-text('Create account')")
        if await signup_link.count() > 0:
            result.steps_passed += 1
        else:
            result.notes.append("No signup link on login page")

    async def test_signup_page(self, page: Page, result: FlowResult):
        """Test signup page functionality."""
        result.steps_total = 6

        await page.goto(f"{self.base_url}/signup", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check for name field
        name_field = page.locator("input[name='name'], input[placeholder*='name' i]").first
        if await name_field.count() > 0:
            result.steps_passed += 1
        else:
            result.notes.append("Name field not found")

        # Check for email field
        email_field = page.locator("input[type='email'], input[name='email']").first
        if await email_field.count() > 0:
            result.steps_passed += 1
        else:
            result.error = "Email field not found on signup"
            return

        # Check for password field
        password_field = page.locator("input[type='password']").first
        if await password_field.count() > 0:
            result.steps_passed += 1
        else:
            result.error = "Password field not found on signup"
            return

        # Check for terms checkbox or link
        terms = page.locator("input[type='checkbox'], a[href*='terms'], a:has-text('Terms')")
        if await terms.count() > 0:
            result.steps_passed += 1
        else:
            result.notes.append("Terms acceptance not found")

        # Check for OAuth options
        oauth = page.locator("[class*='google'], [class*='facebook'], [class*='telegram'], button:has-text('Google')")
        if await oauth.count() > 0:
            result.steps_passed += 1
            result.notes.append("OAuth signup options present")
        else:
            result.notes.append("No OAuth signup options visible")

    async def test_pricing_page(self, page: Page, result: FlowResult):
        """Test pricing page."""
        result.steps_total = 4

        await page.goto(f"{self.base_url}/pricing", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check for pricing tiers
        pricing_cards = page.locator("[class*='pricing'], [class*='plan'], [class*='tier']")
        card_count = await pricing_cards.count()

        if card_count > 0:
            result.steps_passed += 1
            result.notes.append(f"Found {card_count} pricing cards/tiers")
        else:
            result.notes.append("No pricing cards found with standard classes")

        # Check for price amounts
        prices = page.locator("text=/\\$\\d+/")
        price_count = await prices.count()
        if price_count > 0:
            result.steps_passed += 1
            result.notes.append(f"Found {price_count} price elements")

        # Check for CTA buttons
        cta = page.locator("button:has-text('Subscribe'), button:has-text('Get'), a:has-text('Start')")
        if await cta.count() > 0:
            result.steps_passed += 1

    async def test_faq_page(self, page: Page, result: FlowResult):
        """Test FAQ page."""
        result.steps_total = 3

        await page.goto(f"{self.base_url}/faq", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check for FAQ items
        faq_items = page.locator("[class*='faq'], [class*='accordion'], details, [class*='question']")
        faq_count = await faq_items.count()

        if faq_count > 0:
            result.steps_passed += 1
            result.notes.append(f"Found {faq_count} FAQ items")
        else:
            result.notes.append("FAQ items not found with standard selectors")

        # Check for expandable items
        expandable = page.locator("details, [aria-expanded], button[class*='expand'], [class*='accordion']")
        if await expandable.count() > 0:
            result.steps_passed += 1
            result.notes.append("Expandable FAQ items present")

    async def test_community_page(self, page: Page, result: FlowResult):
        """Test community page."""
        result.steps_total = 3

        await page.goto(f"{self.base_url}/community", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check page loaded
        title = await page.title()
        result.notes.append(f"Page title: {title}")
        result.steps_passed += 1

        # Check for community content
        content = page.locator("[class*='story'], [class*='post'], [class*='card'], article")
        content_count = await content.count()
        if content_count > 0:
            result.steps_passed += 1
            result.notes.append(f"Found {content_count} content items")

    async def test_mobile_responsive(self, page: Page, result: FlowResult):
        """Test mobile responsiveness."""
        result.steps_total = 4

        # Set mobile viewport
        await page.set_viewport_size({"width": 375, "height": 812})  # iPhone X
        await page.goto(self.base_url, wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check for hamburger menu or mobile nav
        mobile_menu = page.locator("[class*='hamburger'], [class*='mobile-menu'], button[aria-label*='menu' i], [class*='menu-toggle']")
        if await mobile_menu.count() > 0:
            result.steps_passed += 1
            result.notes.append("Mobile menu found")
        else:
            result.notes.append("No mobile menu toggle found")

        # Check content is visible
        main_content = page.locator("main, [role='main'], .content, #root > div")
        if await main_content.count() > 0:
            box = await main_content.first.bounding_box()
            if box and box["width"] <= 375:
                result.steps_passed += 1
                result.notes.append("Content fits mobile width")
            else:
                result.notes.append("Content may overflow mobile viewport")

        result.steps_passed += 1

    async def test_oauth_buttons(self, page: Page, result: FlowResult):
        """Test OAuth buttons are present and styled."""
        result.steps_total = 4

        await page.goto(f"{self.base_url}/login", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check for Google OAuth
        google = page.locator("[class*='google' i], button:has-text('Google'), [data-provider='google']")
        if await google.count() > 0:
            result.steps_passed += 1
            result.notes.append("Google OAuth button present")
        else:
            result.notes.append("Google OAuth button not found")

        # Check for Facebook OAuth
        facebook = page.locator("[class*='facebook' i], button:has-text('Facebook'), [data-provider='facebook']")
        if await facebook.count() > 0:
            result.steps_passed += 1
            result.notes.append("Facebook OAuth button present")
        else:
            result.notes.append("Facebook OAuth button not found")

        # Check for Telegram OAuth
        telegram = page.locator("[class*='telegram' i], button:has-text('Telegram'), [data-provider='telegram']")
        if await telegram.count() > 0:
            result.steps_passed += 1
            result.notes.append("Telegram OAuth button present")
        else:
            result.notes.append("Telegram OAuth button not found")

    async def test_form_validation(self, page: Page, result: FlowResult):
        """Test form validation on login."""
        result.steps_total = 4

        await page.goto(f"{self.base_url}/login", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Try to submit empty form
        submit = page.locator("button[type='submit'], button:has-text('Login'), button:has-text('Sign in')").first
        if await submit.count() > 0:
            await submit.click()
            await page.wait_for_timeout(1000)
            result.steps_passed += 1

            # Check for validation message
            validation = page.locator("[class*='error'], [class*='invalid'], [role='alert'], .validation-message")
            if await validation.count() > 0:
                result.steps_passed += 1
                result.notes.append("Form validation working")
            else:
                result.notes.append("No validation message shown for empty form")

        # Try invalid email
        email_field = page.locator("input[type='email'], input[name='email']").first
        if await email_field.count() > 0:
            await email_field.fill("invalid-email")
            await email_field.blur()
            await page.wait_for_timeout(500)
            result.steps_passed += 1

    async def test_error_handling(self, page: Page, result: FlowResult):
        """Test 404 and error pages."""
        result.steps_total = 2

        # Test 404 page
        response = await page.goto(f"{self.base_url}/nonexistent-page-12345", wait_until="domcontentloaded")
        result.steps_passed += 1

        # Check for 404 handling
        page_content = await page.content()
        if "404" in page_content or "not found" in page_content.lower():
            result.steps_passed += 1
            result.notes.append("404 page properly handled")
        else:
            result.notes.append(f"404 page returned status {response.status}")

    async def test_performance(self, page: Page, result: FlowResult):
        """Test page load performance."""
        result.steps_total = 3

        # Measure load time
        import time
        start = time.time()
        await page.goto(self.base_url, wait_until="domcontentloaded")
        load_time = (time.time() - start) * 1000

        result.steps_passed += 1
        result.notes.append(f"Page load time: {load_time:.0f}ms")

        if load_time < 3000:
            result.steps_passed += 1
            result.notes.append("Good: Under 3 second load time")
        elif load_time < 5000:
            result.notes.append("Warning: Load time between 3-5 seconds")
        else:
            result.notes.append("Slow: Load time over 5 seconds")

        # Check for large images
        images = await page.evaluate("""
            () => {
                const imgs = document.querySelectorAll('img');
                let largeImages = 0;
                imgs.forEach(img => {
                    if (img.naturalWidth > 2000) largeImages++;
                });
                return { total: imgs.length, large: largeImages };
            }
        """)
        result.notes.append(f"Images: {images['total']} total, {images['large']} oversized")
        result.steps_passed += 1


def print_report(report: FlowTestReport):
    """Print formatted test report."""
    print("\n" + "="*70)
    print("  MEEDI8 FLOW TEST REPORT")
    print("="*70)
    print(f"\nURL: {report.url}")
    print(f"Started: {report.started_at}")
    print(f"Finished: {report.finished_at}")
    print(f"Duration: {(report.finished_at - report.started_at).total_seconds():.1f}s")

    print(f"\n{'─'*70}")
    print("SUMMARY")
    print(f"{'─'*70}")
    print(f"  Total Flows: {report.summary['total']}")
    print(f"  ✅ Passed:   {report.summary['passed']}")
    print(f"  ❌ Failed:   {report.summary['failed']}")
    print(f"  ⚠️  Skipped:  {report.summary['skipped']}")

    # Failed flows
    failed = [f for f in report.flows if f.status == "failed"]
    if failed:
        print(f"\n{'─'*70}")
        print("FAILED FLOWS")
        print(f"{'─'*70}")
        for f in failed:
            print(f"\n  ❌ {f.name}")
            print(f"     Error: {f.error}")
            if f.screenshot_path:
                print(f"     Screenshot: {f.screenshot_path}")

    # All flow details
    print(f"\n{'─'*70}")
    print("ALL FLOW DETAILS")
    print(f"{'─'*70}")
    for f in report.flows:
        icon = "✅" if f.status == "passed" else "❌" if f.status == "failed" else "⚠️"
        print(f"\n  {icon} {f.name} ({f.duration_ms}ms)")
        print(f"     Steps: {f.steps_passed}/{f.steps_total}")
        for note in f.notes:
            print(f"     • {note}")

    print("\n" + "="*70)


def generate_markdown_report(report: FlowTestReport) -> str:
    """Generate markdown report for adding to production_test.md."""
    lines = [
        "## Flow Test Results",
        "",
        f"**Test Date:** {report.started_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"**Target URL:** {report.url}",
        f"**Duration:** {(report.finished_at - report.started_at).total_seconds():.1f} seconds",
        "",
        "### Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total Flows | {report.summary['total']} |",
        f"| Passed | {report.summary['passed']} |",
        f"| Failed | {report.summary['failed']} |",
        f"| Skipped | {report.summary['skipped']} |",
        "",
    ]

    # Failed flows section
    failed = [f for f in report.flows if f.status == "failed"]
    if failed:
        lines.append("### Failed Flows (Requires Attention)")
        lines.append("")
        lines.append("| Flow | Error | Action | Done? |")
        lines.append("|------|-------|--------|-------|")
        for f in failed:
            error_short = (f.error or "Unknown")[:50]
            lines.append(f"| {f.name} | {error_short} | Investigate | [ ] |")
        lines.append("")

    # All flows table
    lines.append("### All Flow Results")
    lines.append("")
    lines.append("| # | Flow | Status | Duration | Notes |")
    lines.append("|---|------|--------|----------|-------|")
    for i, f in enumerate(report.flows, 1):
        status_icon = "PASS" if f.status == "passed" else "FAIL" if f.status == "failed" else "SKIP"
        notes_short = "; ".join(f.notes[:2])[:60] if f.notes else "-"
        lines.append(f"| {i} | {f.name} | {status_icon} | {f.duration_ms}ms | {notes_short} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    return "\n".join(lines)


async def main():
    """Main entry point."""
    url = sys.argv[1] if len(sys.argv) > 1 else "https://meedi8.com"
    headless = "--headed" not in sys.argv

    print(f"\n🧪 Starting Meedi8 Flow Tests")
    print(f"   Target: {url}")
    print(f"   Mode: {'Headless' if headless else 'Headed'}")

    tester = Meedi8FlowTester(url)
    report = await tester.run_all_flows(headless=headless)

    print_report(report)

    # Save JSON report
    json_path = Path("./flow_test_results.json")
    with open(json_path, "w") as f:
        json.dump({
            "url": report.url,
            "started_at": report.started_at.isoformat(),
            "finished_at": report.finished_at.isoformat(),
            "summary": report.summary,
            "flows": [
                {
                    "name": fl.name,
                    "status": fl.status,
                    "duration_ms": fl.duration_ms,
                    "steps_passed": fl.steps_passed,
                    "steps_total": fl.steps_total,
                    "error": fl.error,
                    "notes": fl.notes,
                }
                for fl in report.flows
            ]
        }, f, indent=2)
    print(f"\n📄 JSON report saved to: {json_path}")

    # Generate markdown for production_test.md
    md_content = generate_markdown_report(report)
    md_path = Path("./flow_test_report.md")
    with open(md_path, "w") as f:
        f.write(md_content)
    print(f"📄 Markdown report saved to: {md_path}")

    # Exit with error code if any tests failed
    if report.summary["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
