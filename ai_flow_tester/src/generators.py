"""
Journey Generator - Uses multi-LLM to generate realistic test journeys.

Features:
- Natural language test generation
- User persona simulation
- Edge case discovery
- Adversarial test generation
"""

import json
import re
from dataclasses import dataclass
from typing import Optional

from shared.src.llm_client import MultiLLMClient, LLMProvider


@dataclass
class TestStep:
    description: str
    action: str
    selector: Optional[str] = None
    value: Optional[str] = None
    expected: Optional[str] = None
    delay_ms: int = 500


# User personas for simulation
PERSONAS = {
    "default": {
        "name": "Average User",
        "description": "Regular user with moderate tech skills",
        "behaviors": {
            "typing_speed": "normal",
            "mistakes": "occasional",
            "patience": "moderate",
        },
    },
    "tech-naive": {
        "name": "Tech-Naive User",
        "description": "User with limited tech experience (e.g., elderly, first-time user)",
        "behaviors": {
            "typing_speed": "slow",
            "mistakes": "frequent",
            "patience": "low",
            "back_button": "frequent",
            "help_seeking": "high",
        },
    },
    "power-user": {
        "name": "Power User",
        "description": "Experienced user who uses keyboard shortcuts and works quickly",
        "behaviors": {
            "typing_speed": "fast",
            "mistakes": "rare",
            "patience": "low",
            "keyboard_shortcuts": "always",
            "multi_tab": "frequent",
        },
    },
    "adversarial": {
        "name": "Adversarial User",
        "description": "User actively trying to break or exploit the application",
        "behaviors": {
            "injection_attempts": True,
            "boundary_testing": True,
            "unexpected_navigation": True,
            "rapid_clicking": True,
        },
    },
    "mobile": {
        "name": "Mobile User",
        "description": "User on a mobile device with touch interface",
        "behaviors": {
            "touch_interface": True,
            "small_screen": True,
            "slow_connection": "possible",
            "interruptions": "frequent",
        },
    },
    "accessibility": {
        "name": "Accessibility User",
        "description": "User relying on screen readers or keyboard navigation",
        "behaviors": {
            "screen_reader": True,
            "keyboard_only": True,
            "high_contrast": True,
            "no_mouse": True,
        },
    },
}


class JourneyGenerator:
    """
    Generates test journeys using multiple LLMs.
    """

    def __init__(self, llm_client: MultiLLMClient):
        self.llm = llm_client

    async def generate_journey(
        self,
        page_context: dict,
        persona: str = "default",
        url: str = "",
        max_steps: int = 20,
    ) -> list[TestStep]:
        """
        Generate a complete test journey for a persona.

        Args:
            page_context: Current page state (HTML, elements, etc.)
            persona: User persona to simulate
            url: Target URL
            max_steps: Maximum steps to generate

        Returns:
            List of TestStep objects
        """
        persona_config = PERSONAS.get(persona, PERSONAS["default"])

        # Use Gemini for initial analysis (large context)
        analysis_prompt = f"""Analyze this web application and identify testable user flows.

URL: {url}
Page Title: {page_context.get('title', '')}
Visible Text Preview: {page_context.get('visible_text', '')[:2000]}

Interactive Elements:
{json.dumps(page_context.get('interactive_elements', [])[:30], indent=2)}

Identify:
1. Primary user flows (main functionality)
2. Secondary flows (settings, profile, etc.)
3. Error states to test
4. Edge cases

Output as JSON list of flow names and descriptions."""

        flows = await self.llm.query(
            analysis_prompt,
            provider=LLMProvider.GEMINI_FLASH,
        )

        # Use Claude to generate detailed steps with persona behavior
        generation_prompt = f"""Generate a realistic test journey for this user persona.

PERSONA: {persona_config['name']}
Description: {persona_config['description']}
Behaviors: {json.dumps(persona_config['behaviors'], indent=2)}

APPLICATION ANALYSIS:
{flows.content}

INTERACTIVE ELEMENTS:
{json.dumps(page_context.get('interactive_elements', [])[:20], indent=2)}

Generate {max_steps} test steps that simulate this persona realistically.
Include:
- Natural delays and hesitations
- Realistic mistakes (for appropriate personas)
- Exploration behavior
- Error recovery attempts

Output as JSON array with this structure:
[
  {{
    "description": "What the user is trying to do",
    "action": "click|fill|navigate|wait|assert",
    "selector": "CSS selector or null",
    "value": "Input value if filling form, or null",
    "expected": "Expected result for assertions, or null",
    "delay_ms": 500
  }}
]

IMPORTANT: Use realistic CSS selectors based on the elements provided.
For text input, use realistic values appropriate for the persona."""

        steps_response = await self.llm.query(
            generation_prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.7,
        )

        # Parse the response
        steps = self._parse_steps(steps_response.content)

        return steps

    async def generate_edge_cases(
        self,
        page_context: dict,
        existing_steps: list[TestStep],
    ) -> list[TestStep]:
        """
        Generate additional edge case tests using adversarial thinking.
        Uses Grok for creative/adversarial scenarios.
        """
        prompt = f"""You are a chaos engineer. Based on these test steps:
{json.dumps([s.description for s in existing_steps[:10]], indent=2)}

And these interactive elements:
{json.dumps(page_context.get('interactive_elements', [])[:15], indent=2)}

Generate edge cases that would break the application:
1. Boundary values (empty, very long, special characters)
2. Race conditions (rapid clicking, double submit)
3. Invalid state transitions
4. Unexpected navigation patterns
5. Network interruption scenarios

Output as JSON array of test steps."""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.GROK,
            temperature=0.9,
        )

        return self._parse_steps(response.content)

    async def generate_from_description(
        self,
        description: str,
        page_context: dict,
    ) -> list[TestStep]:
        """
        Generate test steps from a natural language description.

        Example: "Test the login flow with invalid credentials"
        """
        prompt = f"""Convert this test description into executable test steps:

Description: {description}

Available elements:
{json.dumps(page_context.get('interactive_elements', [])[:20], indent=2)}

Output as JSON array of test steps with:
- description: What this step does
- action: click|fill|navigate|wait|assert
- selector: CSS selector
- value: Input value if needed
- expected: Expected result for assertions
- delay_ms: Delay after step"""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
        )

        return self._parse_steps(response.content)

    def _parse_steps(self, content: str) -> list[TestStep]:
        """Parse LLM response into TestStep objects."""
        # Try to extract JSON from response
        try:
            # Find JSON array in response
            json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                steps_data = json.loads(json_match.group())
            else:
                return []

            steps = []
            for step_data in steps_data:
                if isinstance(step_data, dict):
                    steps.append(TestStep(
                        description=step_data.get("description", "Unknown step"),
                        action=step_data.get("action", "click"),
                        selector=step_data.get("selector"),
                        value=step_data.get("value"),
                        expected=step_data.get("expected"),
                        delay_ms=step_data.get("delay_ms", 500),
                    ))

            return steps

        except json.JSONDecodeError:
            return []
