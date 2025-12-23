"""
Smart Selector - AI-powered element selection with self-healing.

Features:
- AI-generated robust selectors
- Self-healing when selectors break
- Multiple fallback strategies
- Element fingerprinting
"""

import json
import re
from dataclasses import dataclass
from typing import Optional

from playwright.async_api import Page, Locator

from shared.src.llm_client import MultiLLMClient, LLMProvider


@dataclass
class ElementFingerprint:
    """Stores multiple attributes for element identification."""
    original_selector: str
    tag: str
    text: Optional[str]
    id: Optional[str]
    classes: list[str]
    aria_label: Optional[str]
    placeholder: Optional[str]
    data_testid: Optional[str]
    role: Optional[str]
    position: dict  # relative position info


class SmartSelector:
    """
    AI-powered element selection with self-healing capabilities.
    """

    def __init__(self, llm_client: MultiLLMClient):
        self.llm = llm_client
        self.selector_cache: dict[str, str] = {}
        self.fingerprints: dict[str, ElementFingerprint] = {}

    async def find_by_description(
        self,
        page: Page,
        description: str,
    ) -> Locator:
        """
        Find an element by natural language description.

        Args:
            page: Playwright page
            description: Natural language description (e.g., "the login button")

        Returns:
            Playwright Locator
        """
        # Check cache first
        if description in self.selector_cache:
            try:
                locator = page.locator(self.selector_cache[description])
                if await locator.count() > 0:
                    return locator.first
            except:
                pass

        # Get page context
        html = await page.content()
        html_preview = html[:20000]

        # Ask AI to find the element
        prompt = f"""Find the CSS selector for: "{description}"

HTML:
```html
{html_preview}
```

Return the most robust selector. Prefer:
1. data-testid attributes
2. id attributes
3. aria-label
4. role + unique text
5. Semantic element + class

Return ONLY the CSS selector, nothing else."""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.1,
            max_tokens=100,
        )

        selector = response.content.strip().strip('"').strip("'")

        # Validate selector works
        try:
            locator = page.locator(selector)
            if await locator.count() > 0:
                self.selector_cache[description] = selector
                return locator.first
        except:
            pass

        # Fallback: try common patterns
        fallback_patterns = [
            f"text={description}",
            f"role=button[name='{description}']",
            f"[aria-label*='{description}' i]",
        ]

        for pattern in fallback_patterns:
            try:
                locator = page.locator(pattern)
                if await locator.count() > 0:
                    return locator.first
            except:
                pass

        raise ValueError(f"Could not find element: {description}")

    async def heal(
        self,
        original_selector: str,
        html: str,
        description: str,
    ) -> Optional[str]:
        """
        Heal a broken selector by finding the element again.

        Args:
            original_selector: The selector that stopped working
            html: Current page HTML
            description: What the element should be

        Returns:
            New selector or None if can't heal
        """
        html_preview = html[:25000]

        prompt = f"""A CSS selector broke. Find a new one.

Original selector: {original_selector}
Element description: {description}

Current HTML:
```html
{html_preview}
```

The element might have:
- Changed its ID or classes
- Moved to a different parent
- Changed its text slightly

Find the same element with a new selector.
Return ONLY the new CSS selector."""

        response = await self.llm.query(
            prompt,
            provider=LLMProvider.CLAUDE,
            temperature=0.2,
            max_tokens=100,
        )

        new_selector = response.content.strip().strip('"').strip("'")

        # Validate it's different and looks like a selector
        if new_selector and new_selector != original_selector:
            # Basic validation that it looks like a CSS selector
            if re.match(r'^[\w\[\]#.=\-_"\'\s:()>+~*,@]+$', new_selector):
                return new_selector

        return None

    async def create_fingerprint(
        self,
        page: Page,
        selector: str,
    ) -> ElementFingerprint:
        """
        Create a fingerprint of an element for later identification.
        """
        element_info = await page.evaluate(f"""
            (selector) => {{
                const el = document.querySelector(selector);
                if (!el) return null;

                const rect = el.getBoundingClientRect();

                return {{
                    tag: el.tagName.toLowerCase(),
                    text: el.innerText?.substring(0, 100),
                    id: el.id || null,
                    classes: Array.from(el.classList),
                    ariaLabel: el.getAttribute('aria-label'),
                    placeholder: el.placeholder || null,
                    dataTestid: el.getAttribute('data-testid'),
                    role: el.getAttribute('role'),
                    position: {{
                        top: rect.top,
                        left: rect.left,
                        width: rect.width,
                        height: rect.height
                    }}
                }};
            }}
        """, selector)

        if not element_info:
            raise ValueError(f"Element not found: {selector}")

        fingerprint = ElementFingerprint(
            original_selector=selector,
            tag=element_info["tag"],
            text=element_info.get("text"),
            id=element_info.get("id"),
            classes=element_info.get("classes", []),
            aria_label=element_info.get("ariaLabel"),
            placeholder=element_info.get("placeholder"),
            data_testid=element_info.get("dataTestid"),
            role=element_info.get("role"),
            position=element_info.get("position", {}),
        )

        self.fingerprints[selector] = fingerprint
        return fingerprint

    async def find_by_fingerprint(
        self,
        page: Page,
        fingerprint: ElementFingerprint,
    ) -> Optional[str]:
        """
        Find an element using its fingerprint when original selector breaks.
        """
        # Build candidate selectors from fingerprint
        candidates = []

        if fingerprint.data_testid:
            candidates.append(f'[data-testid="{fingerprint.data_testid}"]')

        if fingerprint.id:
            candidates.append(f'#{fingerprint.id}')

        if fingerprint.aria_label:
            candidates.append(f'[aria-label="{fingerprint.aria_label}"]')

        if fingerprint.role and fingerprint.text:
            candidates.append(f'[role="{fingerprint.role}"]:has-text("{fingerprint.text[:50]}")')

        if fingerprint.tag and fingerprint.classes:
            class_selector = '.'.join(fingerprint.classes[:3])
            candidates.append(f'{fingerprint.tag}.{class_selector}')

        # Try each candidate
        for selector in candidates:
            try:
                locator = page.locator(selector)
                if await locator.count() == 1:  # Unique match
                    return selector
            except:
                pass

        # If no unique match, use AI to find it
        return await self.heal(
            original_selector=fingerprint.original_selector,
            html=await page.content(),
            description=f"{fingerprint.tag} with text '{fingerprint.text}'",
        )

    def get_selector_strategies(self, element_info: dict) -> list[str]:
        """
        Generate multiple selector strategies for an element.
        Returns selectors in order of robustness.
        """
        strategies = []

        # Most robust: data-testid
        if element_info.get("dataTestid"):
            strategies.append(f'[data-testid="{element_info["dataTestid"]}"]')

        # ID (if not auto-generated looking)
        if element_info.get("id") and not re.match(r'^[a-z]+[-_]?\d+', element_info["id"]):
            strategies.append(f'#{element_info["id"]}')

        # ARIA label
        if element_info.get("ariaLabel"):
            strategies.append(f'[aria-label="{element_info["ariaLabel"]}"]')

        # Role + name
        if element_info.get("role"):
            if element_info.get("text"):
                strategies.append(f'[role="{element_info["role"]}"]:has-text("{element_info["text"][:30]}")')
            else:
                strategies.append(f'[role="{element_info["role"]}"]')

        # Tag + stable classes
        stable_classes = [c for c in element_info.get("classes", [])
                         if not re.match(r'^[a-z]+[-_]?\d+', c) and len(c) > 3]
        if stable_classes and element_info.get("tag"):
            strategies.append(f'{element_info["tag"]}.{".".join(stable_classes[:2])}')

        # Text content (last resort)
        if element_info.get("text"):
            strategies.append(f'text="{element_info["text"][:50]}"')

        return strategies
