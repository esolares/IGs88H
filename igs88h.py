#!/usr/bin/env python3
"""
IGs88H — Integrative Graph Search Bug Bounty Hunter

CLI entry point. Indexes a codebase with Graphify (or built-in AST),
runs orchestrator-driven traversal with LLM analysis, and exports results.

Usage:
  python igs88h.py /path/to/your/codebase --task security --model gemini-2.5-flash
  python igs88h.py --graph /path/to/graph.json --task analyze
"""

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

# Add parent dir so we can import the harness package
sys.path.insert(0, str(Path(__file__).parent))

from harness import (
    AgentHarness,
    ToolRegistry,
    CodeGraph,
    GraphTraversal,
    TraversalStrategy,
    NodeType,
    analyze_task,
    test_gen_task,
    dependency_audit_task,
    dataflow_task,
    practices_task,
    oop_task,
    duplication_task,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ── Step 1: Index a Codebase ─────────────────────────────────

def index_with_graphify(codebase_path: str) -> CodeGraph:
    """
    Run Graphify to index a codebase, then load the resulting graph.

    This calls `graphify` via subprocess. If Graphify isn't
    installed, falls back to a built-in AST indexer.
    """
    codebase = Path(codebase_path).resolve()
    graph_path = codebase / "graphify-out" / "graph.json"

    if graph_path.exists():
        logger.info(f"Found existing graph at {graph_path}")
        return CodeGraph.from_json(graph_path)

    # Try running Graphify CLI (update = code-only, no LLM key needed)
    try:
        logger.info(f"Indexing {codebase} with Graphify...")
        subprocess.run(
            ["graphify", "update", str(codebase), "--no-cluster"],
            check=True,
            capture_output=True,
            text=True,
        )
        return CodeGraph.from_json(graph_path)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logger.warning(f"Graphify CLI not available ({e}), using synthetic graph")
        return build_synthetic_graph(codebase)


def build_synthetic_graph(codebase: Path) -> CodeGraph:
    """
    Build a simple graph by scanning Python files with AST.
    Fallback when Graphify isn't installed.
    """
    import ast

    data = {"nodes": [], "edges": []}
    py_files = list(codebase.rglob("*.py"))

    for py_file in py_files[:50]:  # cap for demo
        rel_path = str(py_file.relative_to(codebase))
        try:
            source = py_file.read_text()
            tree = ast.parse(source)
        except Exception:
            continue

        module_id = rel_path.replace("/", ".").replace(".py", "")
        data["nodes"].append({
            "id": module_id,
            "name": module_id,
            "type": "module",
            "file": rel_path,
            "code": "",  # module-level code omitted for brevity
        })

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_id = f"{module_id}.{node.name}"
                code_lines = source.splitlines()[node.lineno - 1 : node.end_lineno]
                data["nodes"].append({
                    "id": func_id,
                    "name": node.name,
                    "type": "function",
                    "file": rel_path,
                    "line_start": node.lineno,
                    "line_end": node.end_lineno or node.lineno,
                    "code": "\n".join(code_lines),
                    "signature": f"def {node.name}({ast.dump(node.args) if hasattr(node, 'args') else ''})",
                    "docstring": ast.get_docstring(node) or "",
                })
                data["edges"].append({
                    "source": module_id,
                    "target": func_id,
                    "type": "contains",
                })

            elif isinstance(node, ast.ClassDef):
                cls_id = f"{module_id}.{node.name}"
                code_lines = source.splitlines()[node.lineno - 1 : node.end_lineno]
                data["nodes"].append({
                    "id": cls_id,
                    "name": node.name,
                    "type": "class",
                    "file": rel_path,
                    "line_start": node.lineno,
                    "line_end": node.end_lineno or node.lineno,
                    "code": "\n".join(code_lines),
                    "docstring": ast.get_docstring(node) or "",
                })
                data["edges"].append({
                    "source": module_id,
                    "target": cls_id,
                    "type": "contains",
                })

                # Methods inside classes
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_id = f"{cls_id}.{item.name}"
                        method_lines = source.splitlines()[item.lineno - 1 : item.end_lineno]
                        data["nodes"].append({
                            "id": method_id,
                            "name": item.name,
                            "type": "method",
                            "file": rel_path,
                            "line_start": item.lineno,
                            "line_end": item.end_lineno or item.lineno,
                            "code": "\n".join(method_lines),
                            "docstring": ast.get_docstring(item) or "",
                        })
                        data["edges"].append({
                            "source": cls_id,
                            "target": method_id,
                            "type": "contains",
                        })

    return CodeGraph.from_dict(data)


# ── Step 2: Analysis Tools (no traversal) ────────────────────

def build_analysis_tools() -> ToolRegistry:
    """
    Tools the LLM can use to verify its analysis.
    These do NOT include file reading or graph traversal —
    the orchestrator handles all traversal.
    """
    tools = ToolRegistry()

    def static_analysis(code: str) -> dict:
        """Run basic static analysis on a code snippet."""
        issues = []
        lines = code.splitlines()
        for i, line in enumerate(lines, 1):
            if len(line) > 120:
                issues.append({"line": i, "issue": "Line too long", "severity": "warning"})
            if "TODO" in line or "FIXME" in line or "HACK" in line:
                issues.append({"line": i, "issue": f"Found marker: {line.strip()[:80]}", "severity": "info"})
            if "eval(" in line or "exec(" in line:
                issues.append({"line": i, "issue": "Dangerous eval/exec usage", "severity": "error"})
            if "import *" in line:
                issues.append({"line": i, "issue": "Wildcard import", "severity": "warning"})
            if "shell=True" in line:
                issues.append({"line": i, "issue": "subprocess with shell=True", "severity": "error"})
            if "pickle.load" in line or "pickle.loads" in line:
                issues.append({"line": i, "issue": "Unsafe pickle deserialization", "severity": "error"})
        return {"issues": issues, "total": len(issues)}

    tools.register(
        "static_analysis",
        "Run basic static analysis checks on the code snippet provided in your prompt.",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Code to analyze"},
            },
            "required": ["code"],
        },
        static_analysis,
    )

    return tools


# ── Step 3: Custom Task Factories ────────────────────────────

def security_audit_task(node, context=None):
    """Custom task: security-focused analysis."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = "\n\nFindings from called functions:\n"
        for cid, analysis in context["children_analyses"].items():
            children_section += f"\n--- {cid} ---\n{analysis[:800]}\n"

    return f"""Security audit for `{node.name}` ({node.node_type.value}).

File: {node.file_path}

```
{node.code}
```
{children_section}
Check for:
1. Input validation gaps (unsanitized user input, SQL injection, path traversal)
2. Authentication/authorization issues
3. Sensitive data exposure (hardcoded secrets, logging PII)
4. Unsafe deserialization
5. Race conditions or TOCTOU issues

Rate severity: CRITICAL / HIGH / MEDIUM / LOW / NONE
Return structured JSON with findings."""


def refactor_suggestion_task(node, context=None):
    """Custom task: suggest refactoring improvements."""
    children_section = ""
    if context and context.get("children_analyses"):
        children_section = "\n\nRefactoring notes from called functions:\n"
        for cid, analysis in context["children_analyses"].items():
            children_section += f"\n--- {cid} ---\n{analysis[:800]}\n"

    return f"""Suggest refactoring improvements for `{node.name}`.

File: {node.file_path}

```
{node.code}
```
{children_section}
Consider:
1. Single Responsibility — does this do too many things?
2. Extract Method — any blocks that should be separate functions?
3. Naming — are names clear and consistent?
4. Dead code — anything unreachable or unused?
5. Design patterns — any applicable patterns?

Return structured JSON with specific, actionable suggestions."""


# ── Main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recursive code analysis with Agent Harness + Graphify"
    )
    parser.add_argument(
        "codebase",
        nargs="?",
        default=".",
        help="Path to codebase to analyze",
    )
    parser.add_argument(
        "--graph",
        help="Path to existing graph.json (skip indexing)",
    )
    parser.add_argument(
        "--strategy",
        choices=["dfs", "bfs", "bottom_up", "by_type"],
        default="dfs",
        help="Traversal strategy (default: dfs)",
    )
    parser.add_argument(
        "--task",
        choices=["analyze", "test_gen", "deps", "security", "refactor",
                 "dataflow", "practices", "oop", "duplication"],
        default="analyze",
        help="Analysis task to run at each node (default: analyze)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum traversal depth (default: 5)",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Model to use (e.g. claude-sonnet-4-6, gemini-2.5-flash, gpt-4o)",
    )
    parser.add_argument(
        "--filter-type",
        choices=["function", "class", "method", "module"],
        help="Only analyze nodes of this type",
    )
    parser.add_argument(
        "--root",
        action="append",
        help="Start traversal from these node IDs (repeatable)",
    )
    parser.add_argument(
        "--output",
        default="analysis_report.json",
        help="Output file for results (default: analysis_report.json)",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of parallel agents for BFS (default: 1)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load graph and show plan without running agents",
    )
    parser.add_argument(
        "--deep-analysis",
        action="store_true",
        help="Enable deep analysis (3-pass): adds a targeted pass for commonly "
             "missed vulnerability classes (CWE-95, CWE-113, CWE-698, etc.). "
             "Increases token usage ~20-50%% but significantly improves recall.",
    )

    args = parser.parse_args()

    # Load or build graph
    if args.graph:
        graph = CodeGraph.from_json(args.graph)
    else:
        graph = index_with_graphify(args.codebase)

    print(f"\n📊 {graph.summary()}")

    # Pick task factory
    task_factories = {
        "analyze": analyze_task,
        "test_gen": test_gen_task,
        "deps": dependency_audit_task,
        "security": security_audit_task,
        "refactor": refactor_suggestion_task,
        "dataflow": dataflow_task,
        "practices": practices_task,
        "oop": oop_task,
        "duplication": duplication_task,
    }
    task = task_factories[args.task]

    # Node filter
    node_filter = None
    if args.filter_type:
        target_type = NodeType(args.filter_type)
        node_filter = lambda n: n.node_type == target_type

    # Dry run: just show the plan
    if args.dry_run:
        roots = args.root or [n.id for n in graph.get_roots()[:5]]
        print(f"\n🔍 Would traverse from: {roots}")
        print(f"   Strategy: {args.strategy}")
        print(f"   Task: {args.task}")
        print(f"   Max depth: {args.max_depth}")
        if node_filter:
            print(f"   Filter: {args.filter_type} only")

        # Show reachable nodes
        for rid in roots[:3]:
            subgraph = graph.get_subgraph(rid, args.max_depth)
            print(f"\n   From {rid}: {len(subgraph)} reachable nodes")
            for n in subgraph[:10]:
                print(f"     [{n.node_type.value:8s}] {n.name}")
            if len(subgraph) > 10:
                print(f"     ... and {len(subgraph) - 10} more")
        return

    # Analysis-only tools (static_analysis — no execution, no file reading)
    # Gemini and OpenAI use single calls — no tool loop needed
    from harness.traversal import _OPENAI_PREFIXES
    needs_tools = not args.model.startswith("gemini") and not args.model.startswith(_OPENAI_PREFIXES)
    analysis_tools = build_analysis_tools() if needs_tools else None

    # Configure traversal
    strategy = TraversalStrategy(args.strategy)
    traversal = GraphTraversal(
        graph=graph,
        model=args.model,
        strategy=strategy,
        max_depth=args.max_depth,
        node_filter=node_filter,
        parallel=args.parallel,
        analysis_tools=analysis_tools,
        max_agent_turns=3,
        deep_analysis=args.deep_analysis,
    )

    # Run
    depth_label = "deep (3-pass)" if args.deep_analysis else "standard (2-pass)"
    print(f"\n🚀 Starting {args.strategy.upper()} traversal with '{args.task}' task...")
    print(f"   Model: {args.model}")
    print(f"   Analysis: {depth_label}")
    print(f"   Max depth: {args.max_depth}")
    print(f"   Parallel: {args.parallel}\n")

    report = traversal.traverse(
        root_ids=args.root,
        task_factory=task,
    )

    # Results
    print(f"\n{'='*60}")
    print(f"✅ Traversal complete!")
    print(f"   Nodes analyzed: {report.nodes_visited}")
    print(f"   Nodes skipped:  {report.nodes_skipped}")
    print(f"   Total tokens:   {report.total_tokens:,}")
    print(f"   Duration:       {report.total_duration_s:.1f}s")
    if report.errors:
        print(f"   Errors:         {len(report.errors)}")
        for err in report.errors[:5]:
            print(f"     ⚠ {err}")

    # Save
    report.save(args.output)
    print(f"\n📄 Report saved to {args.output}")

    # Quick preview
    print(f"\n{'─'*60}")
    print("Top results:\n")
    for nid in report.traversal_order[:5]:
        r = report.results[nid]
        print(f"  [{r.node_type:8s}] {r.node_name}")
        print(f"  File: {r.file_path}")
        preview = r.analysis[:200].replace("\n", " ")
        print(f"  Analysis: {preview}...")
        print()


if __name__ == "__main__":
    main()
