"""
Multi-LLM Client - Unified interface for Claude, OpenAI, Gemini, and Grok.

Supports multiple orchestration patterns:
- Router: Route by complexity to appropriate model
- Consensus: Get agreement from multiple models
- Specialist: Use each model for its strength
- Adversarial: Red team / blue team testing
"""

import asyncio
import hashlib
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import anthropic
import google.generativeai as genai
import openai


class LLMProvider(Enum):
    CLAUDE = "claude"
    OPENAI = "openai"
    GEMINI = "gemini"
    GEMINI_FLASH = "gemini-flash"
    GROK = "grok"


@dataclass
class LLMResponse:
    content: str
    provider: LLMProvider
    model: str
    tokens_used: int
    cost_estimate: float


class MultiLLMClient:
    """
    Unified client for multiple LLM providers with orchestration patterns.
    """

    # Cost per 1M tokens (input, output)
    PRICING = {
        LLMProvider.CLAUDE: (3.0, 15.0),  # Sonnet
        LLMProvider.OPENAI: (5.0, 15.0),  # GPT-4o
        LLMProvider.GEMINI: (1.25, 5.0),  # Pro
        LLMProvider.GEMINI_FLASH: (0.075, 0.30),
        LLMProvider.GROK: (5.0, 15.0),
    }

    def __init__(self):
        # Initialize clients
        self.claude = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.openai_client = openai.OpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )

        # Gemini
        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        self.gemini = genai.GenerativeModel("gemini-2.0-flash-exp")
        self.gemini_flash = genai.GenerativeModel("gemini-2.0-flash-exp")

        # Grok (OpenAI-compatible API)
        self.grok = openai.OpenAI(
            base_url="https://api.x.ai/v1",
            api_key=os.getenv("XAI_API_KEY")
        )

    async def query(
        self,
        prompt: str,
        provider: LLMProvider = LLMProvider.GEMINI_FLASH,
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Query a specific LLM provider."""

        if provider == LLMProvider.CLAUDE:
            return await self._query_claude(prompt, system_prompt, temperature, max_tokens)
        elif provider == LLMProvider.OPENAI:
            return await self._query_openai(prompt, system_prompt, temperature, max_tokens)
        elif provider in (LLMProvider.GEMINI, LLMProvider.GEMINI_FLASH):
            return await self._query_gemini(prompt, system_prompt, temperature, max_tokens, provider)
        elif provider == LLMProvider.GROK:
            return await self._query_grok(prompt, system_prompt, temperature, max_tokens)
        else:
            raise ValueError(f"Unknown provider: {provider}")

    async def query_all(
        self,
        prompt: str,
        providers: list[LLMProvider] = None,
        system_prompt: str = "",
    ) -> dict[LLMProvider, LLMResponse]:
        """Query multiple providers in parallel."""

        providers = providers or [
            LLMProvider.CLAUDE,
            LLMProvider.OPENAI,
            LLMProvider.GEMINI,
        ]

        tasks = [
            self.query(prompt, provider, system_prompt)
            for provider in providers
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            provider: result
            for provider, result in zip(providers, results)
            if not isinstance(result, Exception)
        }

    async def consensus(
        self,
        prompt: str,
        providers: list[LLMProvider] = None,
        require_agreement: int = 2,
        system_prompt: str = "",
    ) -> dict[str, Any]:
        """
        Get consensus from multiple models.
        Useful for high-stakes decisions like security analysis.
        """

        results = await self.query_all(prompt, providers, system_prompt)

        # Extract answers (assuming structured response)
        answers = {}
        for provider, response in results.items():
            answers[provider] = response.content

        return {
            "responses": answers,
            "providers_queried": len(results),
            "agreement_threshold": require_agreement,
        }

    async def route_by_complexity(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> LLMResponse:
        """
        Route to appropriate model based on task complexity.
        Uses cheap model to classify, then routes accordingly.
        """

        # Classify complexity using fast/cheap model
        classification_prompt = f"""Rate the complexity of this task from 1-10:
1-3: Simple lookup, single step, straightforward
4-6: Moderate reasoning, multiple considerations
7-10: Complex analysis, requires deep expertise

Task: {prompt[:500]}

Respond with just a number."""

        classification = await self.query(
            classification_prompt,
            provider=LLMProvider.GEMINI_FLASH,
            temperature=0.1,
            max_tokens=10,
        )

        try:
            complexity = int(classification.content.strip())
        except ValueError:
            complexity = 5  # Default to medium

        # Route based on complexity
        if complexity <= 3:
            provider = LLMProvider.GEMINI_FLASH
        elif complexity <= 6:
            provider = LLMProvider.CLAUDE
        else:
            # Complex: Use consensus
            consensus_result = await self.consensus(prompt, system_prompt=system_prompt)
            # Return Claude's response as primary
            return LLMResponse(
                content=consensus_result["responses"].get(LLMProvider.CLAUDE, ""),
                provider=LLMProvider.CLAUDE,
                model="consensus",
                tokens_used=0,
                cost_estimate=0,
            )

        return await self.query(prompt, provider, system_prompt)

    async def adversarial(
        self,
        target_description: str,
        defender: LLMProvider = LLMProvider.CLAUDE,
        attacker: LLMProvider = LLMProvider.GROK,
    ) -> dict[str, str]:
        """
        Red team / blue team testing.
        Defender generates safe behavior, attacker tries to break it.
        """

        # Defender: Generate safe test cases
        defender_prompt = f"""You are a quality assurance engineer.
Generate safe, comprehensive test cases for this application:
{target_description}

Focus on:
- Happy path scenarios
- Edge cases
- Error handling
- User experience"""

        defender_response = await self.query(defender_prompt, defender)

        # Attacker: Try to break it
        attacker_prompt = f"""You are a penetration tester and chaos engineer.
The application has these test cases:
{defender_response.content}

Generate adversarial test cases that:
- Find edge cases the defender missed
- Test security vulnerabilities
- Stress test error handling
- Find ways to break or abuse the system

Be creative and think like an attacker."""

        attacker_response = await self.query(attacker_prompt, attacker)

        return {
            "defender_tests": defender_response.content,
            "attacker_tests": attacker_response.content,
        }

    # Private methods for each provider

    async def _query_claude(
        self, prompt: str, system_prompt: str, temperature: float, max_tokens: int
    ) -> LLMResponse:
        """Query Anthropic Claude."""

        message = self.claude.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            system=system_prompt if system_prompt else None,
            messages=[{"role": "user", "content": prompt}],
        )

        tokens = message.usage.input_tokens + message.usage.output_tokens
        cost = self._estimate_cost(LLMProvider.CLAUDE, message.usage.input_tokens, message.usage.output_tokens)

        return LLMResponse(
            content=message.content[0].text,
            provider=LLMProvider.CLAUDE,
            model="claude-sonnet-4",
            tokens_used=tokens,
            cost_estimate=cost,
        )

    async def _query_openai(
        self, prompt: str, system_prompt: str, temperature: float, max_tokens: int
    ) -> LLMResponse:
        """Query OpenAI GPT-4."""

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.openai_client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        tokens = response.usage.total_tokens
        cost = self._estimate_cost(
            LLMProvider.OPENAI,
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
        )

        return LLMResponse(
            content=response.choices[0].message.content,
            provider=LLMProvider.OPENAI,
            model="gpt-4o",
            tokens_used=tokens,
            cost_estimate=cost,
        )

    async def _query_gemini(
        self, prompt: str, system_prompt: str, temperature: float, max_tokens: int, provider: LLMProvider
    ) -> LLMResponse:
        """Query Google Gemini."""

        model = self.gemini_flash if provider == LLMProvider.GEMINI_FLASH else self.gemini

        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

        response = model.generate_content(
            full_prompt,
            generation_config=genai.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            ),
        )

        # Estimate tokens (Gemini doesn't always return usage)
        tokens = len(prompt.split()) * 1.3 + len(response.text.split()) * 1.3
        cost = self._estimate_cost(provider, int(tokens * 0.6), int(tokens * 0.4))

        return LLMResponse(
            content=response.text,
            provider=provider,
            model="gemini-2.0-flash",
            tokens_used=int(tokens),
            cost_estimate=cost,
        )

    async def _query_grok(
        self, prompt: str, system_prompt: str, temperature: float, max_tokens: int
    ) -> LLMResponse:
        """Query xAI Grok."""

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.grok.chat.completions.create(
            model="grok-2-latest",
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        tokens = response.usage.total_tokens if response.usage else 0
        cost = self._estimate_cost(
            LLMProvider.GROK,
            response.usage.prompt_tokens if response.usage else 0,
            response.usage.completion_tokens if response.usage else 0,
        )

        return LLMResponse(
            content=response.choices[0].message.content,
            provider=LLMProvider.GROK,
            model="grok-2",
            tokens_used=tokens,
            cost_estimate=cost,
        )

    def _estimate_cost(self, provider: LLMProvider, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD."""
        input_price, output_price = self.PRICING.get(provider, (0, 0))
        return (input_tokens * input_price + output_tokens * output_price) / 1_000_000
