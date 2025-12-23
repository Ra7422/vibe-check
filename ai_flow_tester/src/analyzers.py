"""
Visual + DOM Analyzer - Combines vision AI with DOM analysis to find issues.

Features:
- Screenshot analysis with vision LLMs
- DOM structure analysis
- Visual-DOM discrepancy detection
- Accessibility issue detection
- UX problem identification
"""

import base64
from dataclasses import dataclass
from typing import Optional

from shared.src.llm_client import MultiLLMClient, LLMProvider


@dataclass
class AnalysisResult:
    url: str
    visual_issues: list[dict]
    dom_issues: list[dict]
    discrepancies: list[dict]
    accessibility_issues: list[dict]
    ux_suggestions: list[dict]
    overall_score: int  # 0-100


class VisualDOMAnalyzer:
    """
    Combines vision-based and DOM-based analysis for comprehensive testing.
    """

    def __init__(self, llm_client: MultiLLMClient):
        self.llm = llm_client

    async def analyze(
        self,
        screenshot: bytes,
        html: str,
        url: str,
    ) -> dict:
        """
        Perform comprehensive visual and DOM analysis.

        Args:
            screenshot: PNG screenshot bytes
            html: Page HTML content
            url: Current page URL

        Returns:
            AnalysisResult as dictionary
        """
        # Run analyses in parallel
        import asyncio

        visual_task = self._analyze_visual(screenshot)
        dom_task = self._analyze_dom(html)

        visual_result, dom_result = await asyncio.gather(visual_task, dom_task)

        # Find discrepancies between visual and DOM
        discrepancies = await self._find_discrepancies(visual_result, dom_result)

        # Check accessibility
        accessibility = await self._check_accessibility(html)

        # Get UX suggestions
        ux = await self._get_ux_suggestions(screenshot, html)

        # Calculate overall score
        score = self._calculate_score(
            visual_result, dom_result, discrepancies, accessibility
        )

        return {
            "url": url,
            "visual_issues": visual_result.get("issues", []),
            "dom_issues": dom_result.get("issues", []),
            "discrepancies": discrepancies,
            "accessibility_issues": accessibility,
            "ux_suggestions": ux,
            "overall_score": score,
        }

    async def _analyze_visual(self, screenshot: bytes) -> dict:
        """Analyze screenshot with vision LLM."""
        # Note: This is a simplified version - in production, you'd use
        # the actual vision API of each provider

        # For now, we'll describe what we would analyze
        prompt = """Analyze this UI for visual issues:

1. Layout problems (overlapping elements, misalignment)
2. Text readability (contrast, size, truncation)
3. Visual hierarchy issues
4. Missing or broken images
5. Responsive design problems
6. Color accessibility

List any issues found with severity (high/medium/low)."""

        # In production, this would use vision API:
        # response = await self.llm.query_with_vision(screenshot, prompt)

        # Placeholder response
        return {
            "issues": [],
            "summary": "Visual analysis placeholder - integrate vision API",
        }

    async def _analyze_dom(self, html: str) -> dict:
        """Analyze DOM structure for issues."""
        # Truncate HTML if too long
        html_preview = html[:30000] if len(html) > 30000 else html

        prompt = f"""Analyze this HTML for structural issues:

```html
{html_preview}
```

Check for:
1. Missing or incorrect semantic tags
2. Form accessibility (labels, ARIA)
3. Interactive elements without proper attributes
4. Broken links or missing hrefs
5. Missing alt text on images
6. Improper heading hierarchy
7. Hidden elements that should be visible
8. Z-index stacking issues

Output as JSON:
{{
  "issues": [
    {{"type": "...", "element": "...", "description": "...", "severity": "high|medium|low"}}
  ]
}}"""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.3,
        )

        try:
            import json
            import re
            json_match = re.search(r'\{[\s\S]*\}', response.content)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        return {"issues": []}

    async def _find_discrepancies(
        self,
        visual_result: dict,
        dom_result: dict,
    ) -> list[dict]:
        """Find discrepancies between what's visible and what's in DOM."""
        prompt = f"""Compare these two analyses and find discrepancies:

VISUAL ANALYSIS (what user sees):
{visual_result}

DOM ANALYSIS (what code contains):
{dom_result}

Find issues where:
1. Elements exist in DOM but aren't visible
2. Interactive elements look clickable but aren't
3. Hidden content that should be visible
4. Overlay/modal issues blocking content
5. CSS hiding content unexpectedly

Output as JSON array of discrepancies."""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.3,
        )

        try:
            import json
            import re
            json_match = re.search(r'\[[\s\S]*\]', response.content)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        return []

    async def _check_accessibility(self, html: str) -> list[dict]:
        """Check for accessibility issues."""
        html_preview = html[:20000]

        prompt = f"""Check this HTML for accessibility (WCAG) issues:

```html
{html_preview}
```

Check:
1. Images without alt text
2. Form inputs without labels
3. Missing ARIA attributes
4. Color contrast issues (check inline styles)
5. Keyboard navigation issues
6. Focus indicators
7. Heading structure
8. Link text quality

Output as JSON array:
[{{"issue": "...", "element": "...", "wcag_criterion": "...", "severity": "..."}}]"""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.2,
        )

        try:
            import json
            import re
            json_match = re.search(r'\[[\s\S]*\]', response.content)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        return []

    async def _get_ux_suggestions(
        self,
        screenshot: bytes,
        html: str,
    ) -> list[dict]:
        """Get UX improvement suggestions."""
        html_preview = html[:10000]

        prompt = f"""Analyze this page for UX improvements:

HTML Preview:
{html_preview}

Suggest improvements for:
1. User flow optimization
2. Call-to-action clarity
3. Form usability
4. Error messaging
5. Loading states
6. Empty states
7. Mobile responsiveness
8. Information architecture

Output as JSON array:
[{{"area": "...", "suggestion": "...", "priority": "high|medium|low"}}]"""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.GEMINI_FLASH,
            temperature=0.5,
        )

        try:
            import json
            import re
            json_match = re.search(r'\[[\s\S]*\]', response.content)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        return []

    def _calculate_score(
        self,
        visual: dict,
        dom: dict,
        discrepancies: list,
        accessibility: list,
    ) -> int:
        """Calculate overall quality score (0-100)."""
        score = 100

        # Deduct for issues
        for issue in visual.get("issues", []):
            if issue.get("severity") == "high":
                score -= 10
            elif issue.get("severity") == "medium":
                score -= 5
            else:
                score -= 2

        for issue in dom.get("issues", []):
            if issue.get("severity") == "high":
                score -= 10
            elif issue.get("severity") == "medium":
                score -= 5
            else:
                score -= 2

        for disc in discrepancies:
            score -= 8

        for acc in accessibility:
            if acc.get("severity") == "high":
                score -= 15
            elif acc.get("severity") == "medium":
                score -= 8
            else:
                score -= 3

        return max(0, score)
