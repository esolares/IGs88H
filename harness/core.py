"""
Core Agent Harness

Wraps an LLM (Claude) with:
- Tool registration and dispatch
- The agentic loop (model → tool calls → tool results → model → ...)
- Structured result extraction
- Token/turn budgets
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import anthropic

logger = logging.getLogger(__name__)


@dataclass
class ToolDef:
    """A registered tool definition."""
    name: str
    description: str
    input_schema: dict
    handler: Callable[..., Any]


class ToolRegistry:
    """Register and dispatch tools with JSON schemas for the model."""

    def __init__(self):
        self._tools: dict[str, ToolDef] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict,
        handler: Callable[..., Any],
    ) -> "ToolRegistry":
        self._tools[name] = ToolDef(name, description, input_schema, handler)
        return self  # chainable

    def dispatch(self, name: str, args: dict) -> Any:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name].handler(**args)

    @property
    def schemas(self) -> list[dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in self._tools.values()
        ]

    @property
    def names(self) -> list[str]:
        return list(self._tools.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._tools


@dataclass
class HarnessResult:
    """Structured result from an agent harness run."""
    text: str
    tool_calls: list[dict] = field(default_factory=list)
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    turns: int = 0
    stop_reason: str = ""


class AgentHarness:
    """
    Wraps a Claude model with tools and runs the agentic loop.

    The loop:
      1. Send messages + tools to the model
      2. If model returns tool_use blocks, dispatch them
      3. Send tool_results back
      4. Repeat until end_turn or budget exhausted
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        system: str = "You are a precise code analysis agent.",
        tools: Optional[ToolRegistry] = None,
        max_turns: int = 25,
        max_tokens: int = 4096,
        client: Optional[anthropic.Anthropic] = None,
    ):
        self.client = client or anthropic.Anthropic()
        self.model = model
        self.system = system
        self.tools = tools or ToolRegistry()
        self.max_turns = max_turns
        self.max_tokens = max_tokens

    def run(self, prompt: str, context: Optional[dict] = None) -> HarnessResult:
        """
        Execute a task through the agentic loop.

        Args:
            prompt: The task instruction for the agent.
            context: Optional dict of context data (e.g., parent node results,
                     code snippet, dependency info). Serialized and prepended.

        Returns:
            HarnessResult with the final text, tool call log, and token usage.
        """
        # Build initial message
        user_content = ""
        if context:
            user_content += f"<context>\n{json.dumps(context, indent=2)}\n</context>\n\n"
        user_content += prompt

        messages = [{"role": "user", "content": user_content}]
        all_tool_calls = []
        total_input = 0
        total_output = 0

        for turn in range(self.max_turns):
            kwargs = dict(
                model=self.model,
                max_tokens=self.max_tokens,
                system=self.system,
                messages=messages,
            )
            if self.tools.schemas:
                kwargs["tools"] = self.tools.schemas

            response = self.client.messages.create(**kwargs)

            total_input += response.usage.input_tokens
            total_output += response.usage.output_tokens

            # Check if done
            if response.stop_reason == "end_turn":
                text = self._extract_text(response)
                return HarnessResult(
                    text=text,
                    tool_calls=all_tool_calls,
                    total_input_tokens=total_input,
                    total_output_tokens=total_output,
                    turns=turn + 1,
                    stop_reason="end_turn",
                )

            # Process tool calls
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    logger.info(f"Tool call: {block.name}({json.dumps(block.input)[:200]})")
                    try:
                        result = self.tools.dispatch(block.name, block.input)
                        result_str = json.dumps(result) if not isinstance(result, str) else result
                    except Exception as e:
                        result_str = json.dumps({"error": str(e)})
                        logger.warning(f"Tool error: {block.name} → {e}")

                    all_tool_calls.append({
                        "tool": block.name,
                        "input": block.input,
                        "output_preview": result_str[:500],
                    })
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str,
                    })

            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            else:
                # No tool calls and not end_turn — model might be stuck
                text = self._extract_text(response)
                return HarnessResult(
                    text=text,
                    tool_calls=all_tool_calls,
                    total_input_tokens=total_input,
                    total_output_tokens=total_output,
                    turns=turn + 1,
                    stop_reason=response.stop_reason,
                )

        # Budget exhausted
        return HarnessResult(
            text="[max turns exceeded]",
            tool_calls=all_tool_calls,
            total_input_tokens=total_input,
            total_output_tokens=total_output,
            turns=self.max_turns,
            stop_reason="max_turns",
        )

    @staticmethod
    def _extract_text(response) -> str:
        return "\n".join(
            block.text for block in response.content if block.type == "text"
        )
