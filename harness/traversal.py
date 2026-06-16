"""
Recursive Graph Traversal Engine

The orchestrator that:
  1. Walks the code knowledge graph (bottom-up by default)
  2. At each leaf node, sends ONLY that node's code to the LLM
  3. At each parent node, sends the node's code + children's analysis results
  4. The LLM has NO tools — it is a pure analysis function
  5. All traversal decisions are made by this engine, not the LLM
"""

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import os

import anthropic

from .core import AgentHarness, ToolRegistry
from .codegraph import CodeGraph, GraphNode, NodeType

_OPENAI_PREFIXES = ("gpt-", "o1", "o3", "o4", "chatgpt-")

logger = logging.getLogger(__name__)


class TraversalStrategy(Enum):
    DFS = "dfs"
    BFS = "bfs"
    BOTTOM_UP = "bottom_up"     # leaves first (post-order) — DEFAULT
    BY_TYPE = "by_type"          # all functions, then classes, then modules


@dataclass
class NodeResult:
    """Result of analyzing a single node."""
    node_id: str
    node_name: str
    node_type: str
    file_path: str
    analysis: str
    children_results: list[str] = field(default_factory=list)
    tokens_used: int = 0
    duration_s: float = 0.0
    depth: int = 0
    error: str | None = None


@dataclass
class TraversalReport:
    """Aggregated results from a full graph traversal."""
    results: dict[str, NodeResult] = field(default_factory=dict)
    traversal_order: list[str] = field(default_factory=list)
    total_tokens: int = 0
    total_duration_s: float = 0.0
    nodes_visited: int = 0
    nodes_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "nodes_visited": self.nodes_visited,
                "nodes_skipped": self.nodes_skipped,
                "total_tokens": self.total_tokens,
                "total_duration_s": round(self.total_duration_s, 2),
                "errors": len(self.errors),
            },
            "traversal_order": self.traversal_order,
            "results": {
                nid: {
                    "name": r.node_name,
                    "type": r.node_type,
                    "file": r.file_path,
                    "depth": r.depth,
                    "analysis": r.analysis,
                    "tokens": r.tokens_used,
                    "duration_s": round(r.duration_s, 2),
                    "error": r.error,
                }
                for nid, r in self.results.items()
            },
        }

    def save(self, path: str):
        from pathlib import Path
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2))


# ── Task Factories ───────────────────────────────────────────
# A task factory takes a GraphNode + optional context and returns
# the prompt string for the agent. Built-in factories below;
# you can write your own.

def analyze_task(node: GraphNode, context: dict | None = None) -> str:
    """Default analysis task: summarize what the code does, find issues, assess efficiency."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = "\n\nChild node analyses:\n"
        for cid, analysis in context["children_analyses"].items():
            children_section += f"\n--- {cid} ---\n{analysis[:1000]}\n"

    return f"""Analyze this {node.node_type.value}: `{node.name}`

File: {node.file_path} (lines {node.line_start}-{node.line_end})

```
{node.code}
```
{children_section}
Provide:
1. What this {node.node_type.value} does (1-2 sentences)
2. Input/output contract (parameters, return type, side effects)
3. Potential bugs, edge cases, or code smells
4. Complexity assessment (time/space)
5. Efficiency: unnecessary copies, redundant iterations, avoidable allocations,
   algorithmic waste (e.g. O(n²) where O(n) is possible), repeated computation
   that should be cached
6. Test suggestions (key scenarios to cover)

Be concise and precise. Output structured JSON."""


def test_gen_task(node: GraphNode, context: dict | None = None) -> str:
    """Generate unit tests for a node."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = f"\nContext from child analyses: {json.dumps(context['children_analyses'])}"

    return f"""Generate unit tests for `{node.name}` ({node.node_type.value}).

File: {node.file_path}
```
{node.code}
```
{children_section}

Write pytest-style tests covering:
- Happy path
- Edge cases (empty input, None, boundary values)
- Error conditions
Return only the test code."""


def dependency_audit_task(node: GraphNode, context: dict | None = None) -> str:
    """Audit dependencies and coupling for a node."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = f"\nChild dependency audits: {json.dumps(context['children_analyses'])}"

    return f"""Audit the dependencies of `{node.name}`.

```
{node.code}
```
{children_section}

Identify:
1. Direct dependencies (imports, calls)
2. Coupling level (tight/loose)
3. Whether this could be extracted/refactored
4. Circular dependency risks
Return structured JSON."""


def _detect_language(file_path: str) -> str:
    """Detect language from file extension for style-guide-aware prompts."""
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return {
        "py": "Python (PEP 8, PEP 257)",
        "js": "JavaScript (Airbnb / Google style)",
        "ts": "TypeScript (Airbnb / Google style)",
        "java": "Java (Google Java Style)",
        "go": "Go (Effective Go, go vet)",
        "rs": "Rust (Rust API Guidelines)",
        "c": "C (CERT C, MISRA where applicable)",
        "h": "C/C++ (CERT C/C++, Google C++ Style)",
        "cpp": "C++ (Google C++ Style, C++ Core Guidelines)",
        "cc": "C++ (Google C++ Style, C++ Core Guidelines)",
        "cxx": "C++ (Google C++ Style, C++ Core Guidelines)",
        "hpp": "C++ (Google C++ Style, C++ Core Guidelines)",
        "rb": "Ruby (Ruby Style Guide)",
        "php": "PHP (PSR-12)",
    }.get(ext, "general")


def dataflow_task(node: GraphNode, context: dict | None = None) -> str:
    """Trace data flow through a node: inputs, transformations, outputs, taint paths."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = "\n\nData flow from called functions:\n"
        for cid, analysis in context["children_analyses"].items():
            children_section += f"\n--- {cid} ---\n{analysis[:1000]}\n"

    return f"""Trace data flow through this {node.node_type.value}: `{node.name}`

File: {node.file_path} (lines {node.line_start}-{node.line_end})

```
{node.code}
```
{children_section}
Analyze:
1. Data sources: where does data enter? (parameters, globals, file reads, env vars,
   user input, network). Tag each as TRUSTED or UNTRUSTED.
2. Transformations: how is data modified, filtered, validated, or sanitized?
   Note where validation is missing.
3. Data sinks: where does data leave? (return values, writes, API calls, logs, DB queries).
   Flag sinks that receive untrusted data without sanitization.
4. Taint paths: trace each untrusted source to each sink. Does it pass through
   a sanitizer? If not, report the full path: source → [transforms] → sink.
5. Dead assignments: variables assigned but never read.
6. Unused parameters: function parameters that are never referenced in the body.
7. Shadowed variables: inner scope names that hide outer scope names.

Output structured JSON with severity for each finding (CRITICAL/HIGH/MEDIUM/LOW)."""


def practices_task(node: GraphNode, context: dict | None = None) -> str:
    """Check coding best practices and style conventions."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = "\n\nPractice notes from called functions:\n"
        for cid, analysis in context["children_analyses"].items():
            children_section += f"\n--- {cid} ---\n{analysis[:800]}\n"

    lang = _detect_language(node.file_path)

    return f"""Review coding practices for this {node.node_type.value}: `{node.name}`

Language: {lang}
File: {node.file_path} (lines {node.line_start}-{node.line_end})

```
{node.code}
```
{children_section}
Evaluate against {lang} conventions and general best practices:

1. Naming: are variable, function, parameter, and class names clear, consistent,
   and idiomatic for {lang}? Flag abbreviations, misleading names, inconsistent
   casing within the same scope.
2. Error handling: are exceptions/errors caught at the right granularity? Are bare
   except/catch blocks used? Are errors silently swallowed? Is cleanup (finally/defer/
   context managers) used where needed?
3. Logging & observability: is there appropriate logging for debugging and monitoring?
   Are sensitive values (passwords, tokens, PII) leaked into logs?
4. Documentation: are public interfaces documented? Are complex algorithms explained?
   Are docstrings/comments accurate (not stale)?
5. Magic values: are there unexplained numeric literals or string constants that should
   be named constants?
6. Consistency: does the style within this node match the surrounding codebase
   (based on child analyses if available)?

Output structured JSON. For each finding include the specific line(s), the convention
violated, and a concrete fix. Severity: HIGH (will cause bugs/confusion), MEDIUM
(maintainability concern), LOW (style nit)."""


def oop_task(node: GraphNode, context: dict | None = None) -> str:
    """Check object-oriented design principles and scoping."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = "\n\nOOP analyses from contained/called members:\n"
        for cid, analysis in context["children_analyses"].items():
            children_section += f"\n--- {cid} ---\n{analysis[:1000]}\n"

    node_kind = node.node_type.value

    return f"""Evaluate object-oriented design for this {node_kind}: `{node.name}`

File: {node.file_path} (lines {node.line_start}-{node.line_end})

```
{node.code}
```
{children_section}
{"This is a function, not a class member. Evaluate whether it SHOULD be:" if node_kind == "function" else "Evaluate this " + node_kind + " against OOP principles:"}

1. Single Responsibility (SRP): does this {node_kind} have one clear purpose, or does
   it handle multiple unrelated concerns? If a class, does each method belong here?
2. Open/Closed: is this designed so behavior can be extended without modifying the
   source? Are there switch/if-chains on type that should be polymorphism?
3. Liskov Substitution: if this inherits from a base class, could it replace the
   parent without breaking callers? Does it violate the parent's contract?
4. Interface Segregation: does this depend on interfaces/ABCs it only partially uses?
   Does it expose methods that most callers don't need?
5. Dependency Inversion: does this depend on concrete classes where it should depend
   on abstractions? Are dependencies injected or hardcoded?
6. Encapsulation: are internal details exposed that should be private? Are there
   public mutable fields that should have accessors? Is state modified from outside?
7. Scoping: are variables defined at broader scope than needed? Are there module-level
   globals that should be instance attributes? Are closures capturing mutable state?
{"8. Misplaced logic: does this function operate on data that suggests it belongs as a method on a class? Does it take an object and primarily manipulate its internals?" if node_kind == "function" else "8. God class: does this class have too many responsibilities, too many methods, or too many instance variables?"}

Output structured JSON. For each finding include the SOLID principle violated,
severity (HIGH/MEDIUM/LOW), and a concrete refactoring suggestion."""


def duplication_task(node: GraphNode, context: dict | None = None) -> str:
    """Detect code duplication within a node and across its children."""
    children_section = ""
    has_children = context and context.get("children_analyses")
    if has_children:
        children_section = "\n\nCode from child nodes (look for duplication ACROSS these):\n"
        for cid, analysis in context["children_analyses"].items():
            children_section += f"\n--- {cid} ---\n{analysis[:1500]}\n"

    cross_section = """
5. Cross-node duplication: compare the child analyses above. Are there repeated
   patterns, similar logic blocks, or near-identical implementations across siblings?
   For each pair, specify which children are duplicated and what the shared logic is.
6. Extract opportunity: for each duplication found, suggest a shared abstraction
   (helper function, base class method, utility, decorator/mixin) and where it should live.
""" if has_children else ""

    return f"""Detect code duplication in this {node.node_type.value}: `{node.name}`

File: {node.file_path} (lines {node.line_start}-{node.line_end})

```
{node.code}
```
{children_section}
Analyze:
1. Internal duplication: are there repeated code blocks, copy-pasted logic, or
   near-identical branches within this {node.node_type.value}? Specify the line ranges
   of each duplicate pair.
2. Boilerplate: is there repetitive setup/teardown/validation that could be factored
   out (decorator, context manager, base class)?
3. Structural duplication: are there parallel if/elif/match chains or loops that
   follow the same pattern with minor variations?
4. Repeated expressions: are there identical expressions computed multiple times
   that should be assigned to a variable?
{cross_section}
Output structured JSON. For each finding include:
- type: "internal", "boilerplate", "structural", "expression", or "cross_node"
- locations: file(s) and line range(s)
- severity: HIGH (exact or near-exact copy), MEDIUM (structural similarity),
  LOW (minor repetition)
- suggestion: specific refactoring to eliminate the duplication"""


# ── Traversal Engine ─────────────────────────────────────────

class GraphTraversal:
    """
    Orchestrator-driven traversal engine.

    Walks the CodeGraph and sends each node's code to the LLM as a
    single API call. The LLM has NO tools and NO ability to traverse
    the graph — all traversal decisions are made here.

    Bottom-up (default): leaves are analyzed first, their results are
    passed as context to parent nodes, bubbling up to the roots.
    """

    def __init__(
        self,
        graph: CodeGraph,
        model: str = "claude-sonnet-4-6",
        system_prompt: str = (
            "You are a precise code analysis agent. "
            "Analyze ONLY the code provided. "
            "You may use tools to test or verify your findings. "
            "Output structured JSON."
        ),
        strategy: TraversalStrategy = TraversalStrategy.BOTTOM_UP,
        max_depth: int = 10,
        max_tokens: int = 4096,
        node_filter: Callable[[GraphNode], bool] | None = None,
        parallel: int = 1,
        client: anthropic.Anthropic | None = None,
        analysis_tools: ToolRegistry | None = None,
        max_agent_turns: int = 3,
        deep_analysis: bool = False,
        # Kept for backwards compat
        base_tools: ToolRegistry | None = None,
    ):
        self.graph = graph
        self.model = model
        self.system_prompt = system_prompt
        self.strategy = strategy
        self.max_depth = max_depth
        self.max_tokens = max_tokens
        self.node_filter = node_filter or (lambda n: True)
        self.parallel = parallel
        self.analysis_tools = analysis_tools or base_tools or ToolRegistry()
        self.max_agent_turns = max_agent_turns
        self.deep_analysis = deep_analysis

        self._is_gemini = model.startswith("gemini")
        self._is_openai = model.startswith(_OPENAI_PREFIXES)
        if self._is_gemini:
            from google import genai
            api_key = os.environ.get("GEMINI_API_KEY", "")
            self._gemini = genai.Client(vertexai=True, api_key=api_key)
            self._openai = None
            self.client = None
        elif self._is_openai:
            from openai import OpenAI
            self._openai = OpenAI()
            self._gemini = None
            self.client = None
        else:
            self._gemini = None
            self._openai = None
            self.client = client or anthropic.Anthropic()

        self._report = TraversalReport()
        self._visited: set[str] = set()

    def traverse(
        self,
        root_ids: list[str] | None = None,
        task_factory: Callable[[GraphNode, dict | None], str] = analyze_task,
    ) -> TraversalReport:
        self._report = TraversalReport()
        self._visited = set()

        if root_ids:
            roots = [self.graph.get_node(rid) for rid in root_ids
                     if self.graph.get_node(rid)]
        else:
            roots = self.graph.get_roots()
            if not roots:
                roots = self.graph.get_by_type(NodeType.MODULE)
            if not roots:
                roots = list(self.graph.nodes.values())

        logger.info(f"Starting traversal: {len(roots)} root(s), "
                    f"strategy={self.strategy.value}, max_depth={self.max_depth}")

        start = time.time()

        if self.strategy == TraversalStrategy.BOTTOM_UP:
            self._bottom_up(roots, task_factory)
        elif self.strategy == TraversalStrategy.DFS:
            for root in roots:
                self._dfs(root, task_factory, depth=0)
        elif self.strategy == TraversalStrategy.BFS:
            self._bfs(roots, task_factory)
        elif self.strategy == TraversalStrategy.BY_TYPE:
            self._by_type(task_factory)

        self._report.total_duration_s = time.time() - start
        self._report.nodes_visited = len(self._report.results)

        logger.info(f"Traversal complete: {self._report.nodes_visited} nodes, "
                    f"{self._report.total_tokens} tokens, "
                    f"{self._report.total_duration_s:.1f}s")

        return self._report

    # ── Core: single LLM call per node ──────────────────────

    def _analyze_node(
        self,
        node: GraphNode,
        task_factory: Callable,
        depth: int,
        context: dict | None = None,
    ) -> NodeResult:
        """Analyze one node. Routes to Gemini or Anthropic based on model."""
        start = time.time()
        logger.info(f"{'  ' * depth}Analyzing [{node.node_type.value}] {node.name}")

        prompt = task_factory(node, context)

        try:
            if self._is_gemini:
                text, tokens = self._call_gemini_with_verification(prompt, node.code or "")
            elif self._is_openai:
                text, tokens = self._call_openai_with_verification(prompt, node.code or "")
            else:
                text, tokens = self._call_anthropic_with_verification(
                    prompt, node.code or ""
                )

            self._report.total_tokens += tokens

            return NodeResult(
                node_id=node.id,
                node_name=node.name,
                node_type=node.node_type.value,
                file_path=node.file_path,
                analysis=text,
                tokens_used=tokens,
                duration_s=time.time() - start,
                depth=depth,
            )
        except Exception as e:
            logger.error(f"Error analyzing {node.name}: {e}")
            self._report.errors.append(f"{node.name}: {e}")
            return NodeResult(
                node_id=node.id,
                node_name=node.name,
                node_type=node.node_type.value,
                file_path=node.file_path,
                analysis="",
                duration_s=time.time() - start,
                depth=depth,
                error=str(e),
            )

    # ── Static analysis (server-side, no LLM) ─────────────────

    @staticmethod
    def _run_static_analysis(code: str) -> dict:
        """Pattern-based static analysis. Runs locally, no API call."""
        issues = []
        lines = code.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if "eval(" in line or "exec(" in line:
                issues.append({"line": i, "issue": "Dangerous eval/exec usage", "severity": "error"})
            if "import *" in line:
                issues.append({"line": i, "issue": "Wildcard import", "severity": "warning"})
            if "shell=True" in line:
                issues.append({"line": i, "issue": "subprocess with shell=True", "severity": "error"})
            if "pickle.load" in line or "pickle.loads" in line:
                issues.append({"line": i, "issue": "Unsafe pickle deserialization", "severity": "error"})
            if "cursor.execute" in line and ("+" in line or "%" in line or ".format(" in line):
                issues.append({"line": i, "issue": "Possible SQL injection (string concat/format in query)", "severity": "error"})
            if "os.system(" in line or "subprocess.call(" in line:
                issues.append({"line": i, "issue": "Command execution", "severity": "warning"})
            if "open(" in line and ("w" in line or "a" in line):
                issues.append({"line": i, "issue": "File write operation", "severity": "info"})
            if "password" in line.lower() and ("=" in line or ":" in line) and not line.strip().startswith("#"):
                issues.append({"line": i, "issue": "Possible hardcoded password", "severity": "warning"})
            if "TODO" in line or "FIXME" in line or "HACK" in line:
                issues.append({"line": i, "issue": f"Marker: {stripped[:80]}", "severity": "info"})
        return {"issues": issues, "total": len(issues)}

    # ── Anthropic backend ─────────────────────────────────────

    def _call_anthropic(self, prompt: str) -> tuple[str, int]:
        """Single Anthropic API call."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self.system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "\n".join(
            block.text for block in response.content if block.type == "text"
        )
        tokens = response.usage.input_tokens + response.usage.output_tokens
        return text, tokens

    def _call_anthropic_with_verification(self, prompt: str, code: str) -> tuple[str, int]:
        """Multi-pass Anthropic: static hints + analysis, verification, optional deep analysis."""
        static = self._run_static_analysis(code)
        static_section = ""
        if static["issues"]:
            static_section = "\n\nServer-side static analysis found these patterns — investigate each:\n"
            for issue in static["issues"]:
                static_section += f"  Line {issue['line']}: [{issue['severity']}] {issue['issue']}\n"

        # Pass 1: analysis with static hints
        enhanced_prompt = prompt + static_section
        text1, tokens1 = self._call_anthropic(enhanced_prompt)

        # Pass 2: verification
        verify_prompt = f"""You previously analyzed this code and produced the findings below.

Your analysis:
{text1}

Original code context:
{code}

Static analysis flags:
{static_section or "None"}

Now do a VERIFICATION pass:
1. For each finding, confirm it is real — provide a proof-of-concept or exploitation scenario
2. Check for findings you MISSED — look specifically for:
   - SQL injection (string concatenation/formatting in queries)
   - XSS (unsanitized output to HTML)
   - Path traversal (user input in file paths)
   - Command injection (user input in shell commands)
   - SSRF, XXE, deserialization, race conditions
   - Authentication/authorization bypass
   - Sensitive data exposure
3. Rate each finding with a severity justification
4. Add CWE identifiers for each finding

Return the COMPLETE updated findings as structured JSON, merging confirmed original findings with any new ones discovered."""

        text2, tokens2 = self._call_anthropic(verify_prompt)

        if not self.deep_analysis:
            combined = f"{text1}\n\n--- VERIFICATION PASS ---\n\n{text2}"
            return combined, tokens1 + tokens2

        # Pass 3: deep analysis
        deep_prompt = f"""Previous analysis found these vulnerabilities:
{text2}

Original code:
{code}

Do a DEEP ANALYSIS pass for vulnerability classes that automated tools commonly miss:
1. Eval/exec injection (CWE-95) — distinct from command injection (CWE-78).
   exec()/eval() with external input is code injection, not shell injection.
2. HTTP header injection (CWE-113) — CRLF characters in send_header()/set_header().
3. HTTP parameter pollution (CWE-235) — duplicate query parameters handled inconsistently.
4. Missing security headers (CWE-1021) — X-Frame-Options, CSP frame-ancestors, HSTS,
   X-Content-Type-Options. Absence = clickjacking/sniffing risk.
5. Execution after redirect (CWE-698) — code continues after send_response(3xx)
   without return. The redirect does NOT stop handler execution.
6. Timing/side-channel — string comparison of secrets without constant-time compare.
7. Log injection (CWE-117) — user input written to logs without sanitization.

Rules:
- Report ONLY new findings not already covered in the previous analysis.
- Each finding needs: specific code line, CWE, exploitation scenario, severity.
- If no additional findings exist, return an empty JSON array [].
- Do NOT repeat findings from the previous passes."""

        text3, tokens3 = self._call_anthropic(deep_prompt)

        combined = f"{text1}\n\n--- VERIFICATION PASS ---\n\n{text2}\n\n--- DEEP ANALYSIS PASS ---\n\n{text3}"
        return combined, tokens1 + tokens2 + tokens3

    # ── Gemini backend ────────────────────────────────────────

    def _call_gemini(self, prompt: str, max_retries: int = 5) -> tuple[str, int]:
        """Single Gemini API call with retry on transient errors."""
        full_prompt = f"{self.system_prompt}\n\n{prompt}"
        for attempt in range(max_retries):
            try:
                response = self._gemini.models.generate_content(
                    model=self.model,
                    contents=full_prompt,
                )
                text = response.text or ""
                usage = response.usage_metadata
                tokens = (usage.prompt_token_count or 0) + (usage.candidates_token_count or 0)
                return text, tokens
            except Exception as e:
                err_str = str(e)
                if ("503" in err_str or "429" in err_str or "UNAVAILABLE" in err_str) and attempt < max_retries - 1:
                    wait = 2 ** attempt * 5
                    logger.warning(f"Gemini transient error (attempt {attempt+1}/{max_retries}), retrying in {wait}s: {err_str[:100]}")
                    time.sleep(wait)
                    continue
                raise

    def _call_gemini_with_verification(self, prompt: str, code: str) -> tuple[str, int]:
        """Two-pass Gemini: analyze with static hints, then verify findings."""
        # Pass 1: static analysis hints + initial analysis
        static = self._run_static_analysis(code)
        static_section = ""
        if static["issues"]:
            static_section = "\n\nServer-side static analysis found these patterns — investigate each:\n"
            for issue in static["issues"]:
                static_section += f"  Line {issue['line']}: [{issue['severity']}] {issue['issue']}\n"

        enhanced_prompt = prompt + static_section
        text1, tokens1 = self._call_gemini(enhanced_prompt)

        # Pass 2: verification — review findings, find what was missed
        verify_prompt = f"""You previously analyzed this code and produced the findings below.

Your analysis:
{text1}

Original code context:
{code}

Static analysis flags:
{static_section or "None"}

Now do a VERIFICATION pass:
1. For each finding, confirm it is real — provide a proof-of-concept or exploitation scenario
2. Check for findings you MISSED — look specifically for:
   - SQL injection (string concatenation/formatting in queries)
   - XSS (unsanitized output to HTML)
   - Path traversal (user input in file paths)
   - Command injection (user input in shell commands)
   - SSRF, XXE, deserialization, race conditions
   - Authentication/authorization bypass
   - Sensitive data exposure
3. Rate each finding with a severity justification
4. Add CWE identifiers for each finding

Return the COMPLETE updated findings as structured JSON, merging confirmed original findings with any new ones discovered."""

        text2, tokens2 = self._call_gemini(verify_prompt)

        if not self.deep_analysis:
            combined = f"{text1}\n\n--- VERIFICATION PASS ---\n\n{text2}"
            return combined, tokens1 + tokens2

        # Pass 3: targeted deep-dive for commonly missed vulnerability classes
        deep_prompt = f"""Previous analysis found these vulnerabilities:
{text2}

Original code:
{code}

Do a DEEP ANALYSIS pass for vulnerability classes that automated tools commonly miss:
1. Eval/exec injection (CWE-95) — distinct from command injection (CWE-78).
   exec()/eval() with external input is code injection, not shell injection.
2. HTTP header injection (CWE-113) — CRLF characters in send_header()/set_header().
3. HTTP parameter pollution (CWE-235) — duplicate query parameters handled inconsistently.
4. Missing security headers (CWE-1021) — X-Frame-Options, CSP frame-ancestors, HSTS,
   X-Content-Type-Options. Absence = clickjacking/sniffing risk.
5. Execution after redirect (CWE-698) — code continues after send_response(3xx)
   without return. The redirect does NOT stop handler execution.
6. Timing/side-channel — string comparison of secrets without constant-time compare.
7. Log injection (CWE-117) — user input written to logs without sanitization.

Rules:
- Report ONLY new findings not already covered in the previous analysis.
- Each finding needs: specific code line, CWE, exploitation scenario, severity.
- If no additional findings exist, return an empty JSON array [].
- Do NOT repeat findings from the previous passes."""

        text3, tokens3 = self._call_gemini(deep_prompt)

        combined = f"{text1}\n\n--- VERIFICATION PASS ---\n\n{text2}\n\n--- DEEP ANALYSIS PASS ---\n\n{text3}"
        return combined, tokens1 + tokens2 + tokens3

    # ── OpenAI backend (experimental, untested) ────────────────

    def _call_openai(self, prompt: str, max_retries: int = 5) -> tuple[str, int]:
        """Single OpenAI API call with retry on transient errors."""
        for attempt in range(max_retries):
            try:
                response = self._openai.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                )
                text = response.choices[0].message.content or ""
                usage = response.usage
                tokens = (usage.prompt_tokens or 0) + (usage.completion_tokens or 0)
                return text, tokens
            except Exception as e:
                err_str = str(e)
                if ("429" in err_str or "503" in err_str or "server_error" in err_str) and attempt < max_retries - 1:
                    wait = 2 ** attempt * 5
                    logger.warning(f"OpenAI transient error (attempt {attempt+1}/{max_retries}), retrying in {wait}s: {err_str[:100]}")
                    time.sleep(wait)
                    continue
                raise

    def _call_openai_with_verification(self, prompt: str, code: str) -> tuple[str, int]:
        """Multi-pass OpenAI: static hints + analysis, verification, optional deep analysis."""
        static = self._run_static_analysis(code)
        static_section = ""
        if static["issues"]:
            static_section = "\n\nServer-side static analysis found these patterns — investigate each:\n"
            for issue in static["issues"]:
                static_section += f"  Line {issue['line']}: [{issue['severity']}] {issue['issue']}\n"

        # Pass 1: analysis with static hints
        enhanced_prompt = prompt + static_section
        text1, tokens1 = self._call_openai(enhanced_prompt)

        # Pass 2: verification
        verify_prompt = f"""You previously analyzed this code and produced the findings below.

Your analysis:
{text1}

Original code context:
{code}

Static analysis flags:
{static_section or "None"}

Now do a VERIFICATION pass:
1. For each finding, confirm it is real — provide a proof-of-concept or exploitation scenario
2. Check for findings you MISSED — look specifically for:
   - SQL injection (string concatenation/formatting in queries)
   - XSS (unsanitized output to HTML)
   - Path traversal (user input in file paths)
   - Command injection (user input in shell commands)
   - SSRF, XXE, deserialization, race conditions
   - Authentication/authorization bypass
   - Sensitive data exposure
3. Rate each finding with a severity justification
4. Add CWE identifiers for each finding

Return the COMPLETE updated findings as structured JSON, merging confirmed original findings with any new ones discovered."""

        text2, tokens2 = self._call_openai(verify_prompt)

        if not self.deep_analysis:
            combined = f"{text1}\n\n--- VERIFICATION PASS ---\n\n{text2}"
            return combined, tokens1 + tokens2

        # Pass 3: deep analysis
        deep_prompt = f"""Previous analysis found these vulnerabilities:
{text2}

Original code:
{code}

Do a DEEP ANALYSIS pass for vulnerability classes that automated tools commonly miss:
1. Eval/exec injection (CWE-95) — distinct from command injection (CWE-78).
   exec()/eval() with external input is code injection, not shell injection.
2. HTTP header injection (CWE-113) — CRLF characters in send_header()/set_header().
3. HTTP parameter pollution (CWE-235) — duplicate query parameters handled inconsistently.
4. Missing security headers (CWE-1021) — X-Frame-Options, CSP frame-ancestors, HSTS,
   X-Content-Type-Options. Absence = clickjacking/sniffing risk.
5. Execution after redirect (CWE-698) — code continues after send_response(3xx)
   without return. The redirect does NOT stop handler execution.
6. Timing/side-channel — string comparison of secrets without constant-time compare.
7. Log injection (CWE-117) — user input written to logs without sanitization.

Rules:
- Report ONLY new findings not already covered in the previous analysis.
- Each finding needs: specific code line, CWE, exploitation scenario, severity.
- If no additional findings exist, return an empty JSON array [].
- Do NOT repeat findings from the previous passes."""

        text3, tokens3 = self._call_openai(deep_prompt)

        combined = f"{text1}\n\n--- VERIFICATION PASS ---\n\n{text2}\n\n--- DEEP ANALYSIS PASS ---\n\n{text3}"
        return combined, tokens1 + tokens2 + tokens3

    # ── Strategy: Bottom-Up (default) ────────────────────────

    def _bottom_up(self, roots: list[GraphNode], task_factory: Callable):
        """Post-order: analyze leaves first, bubble results up to parents."""
        for root in roots:
            self._post_order(root, task_factory, depth=0)

    def _post_order(self, node: GraphNode, task_factory: Callable, depth: int):
        if node.id in self._visited or depth > self.max_depth:
            self._report.nodes_skipped += 1
            return
        if not self.node_filter(node):
            self._report.nodes_skipped += 1
            return
        self._visited.add(node.id)

        children = self.graph.get_children(node.id)
        for child in children:
            self._post_order(child, task_factory, depth + 1)

        children_analyses = {
            c.id: self._report.results[c.id].analysis[:1000]
            for c in children
            if c.id in self._report.results and not self._report.results[c.id].error
        }
        context = {"children_analyses": children_analyses} if children_analyses else None

        result = self._analyze_node(node, task_factory, depth, context)
        result.children_results = [c.id for c in children]
        self._report.results[node.id] = result
        self._report.traversal_order.append(node.id)

    # ── Strategy: DFS (top-down) ─────────────────────────────

    def _dfs(self, node: GraphNode, task_factory: Callable, depth: int):
        """Top-down DFS: analyze parent first, then children."""
        if node.id in self._visited or depth > self.max_depth:
            self._report.nodes_skipped += 1
            return
        if not self.node_filter(node):
            self._report.nodes_skipped += 1
            return
        self._visited.add(node.id)

        result = self._analyze_node(node, task_factory, depth)
        self._report.results[node.id] = result
        self._report.traversal_order.append(node.id)

        children = self.graph.get_children(node.id)
        for child in children:
            self._dfs(child, task_factory, depth + 1)
            result.children_results.append(child.id)

    # ── Strategy: BFS ────────────────────────────────────────

    def _bfs(self, roots: list[GraphNode], task_factory: Callable):
        from collections import deque
        queue = deque([(root, 0) for root in roots])

        while queue:
            batch = []
            while queue and len(batch) < self.parallel:
                node, depth = queue.popleft()
                if node.id in self._visited or depth > self.max_depth:
                    self._report.nodes_skipped += 1
                    continue
                if not self.node_filter(node):
                    self._report.nodes_skipped += 1
                    continue
                batch.append((node, depth))

            if self.parallel > 1 and len(batch) > 1:
                results = self._parallel_analyze(batch, task_factory)
            else:
                results = []
                for node, depth in batch:
                    results.append((node, depth,
                                    self._analyze_node(node, task_factory, depth)))

            for node, depth, result in results:
                self._visited.add(node.id)
                self._report.results[node.id] = result
                self._report.traversal_order.append(node.id)

                for child in self.graph.get_children(node.id):
                    queue.append((child, depth + 1))
                    result.children_results.append(child.id)

    # ── Strategy: By Type ────────────────────────────────────

    def _by_type(self, task_factory: Callable):
        type_order = [NodeType.FUNCTION, NodeType.METHOD, NodeType.CLASS, NodeType.MODULE]
        for ntype in type_order:
            nodes = self.graph.get_by_type(ntype)
            for node in nodes:
                if node.id in self._visited or not self.node_filter(node):
                    self._report.nodes_skipped += 1
                    continue
                self._visited.add(node.id)
                result = self._analyze_node(node, task_factory, depth=0)
                self._report.results[node.id] = result
                self._report.traversal_order.append(node.id)

    # ── Parallel helper ──────────────────────────────────────

    def _parallel_analyze(self, batch, task_factory) -> list:
        results = []
        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            futures = {
                executor.submit(
                    self._analyze_node, node, task_factory, depth
                ): (node, depth)
                for node, depth in batch
            }
            for future in as_completed(futures):
                node, depth = futures[future]
                result = future.result()
                results.append((node, depth, result))
        return results
