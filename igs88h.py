#!/usr/bin/env python3
"""
IGs88H — Integrative Graph Search Bug Bounty Hunter

CLI entry point. Indexes a codebase with Graphify (or built-in AST),
runs orchestrator-driven traversal with LLM analysis, and exports results.

Usage:
  python igs88h.py /path/to/your/codebase --task security --model gemini-3.5-flash
  python igs88h.py /path/to/your/codebase --task security --model claude-sonnet-5-5
  python igs88h.py /path/to/your/codebase --task security   # default model from models.json
  python igs88h.py /path/to/your/codebase --task security --local --model llama3
  python igs88h.py /path/to/your/codebase --local --model codellama --api-url http://localhost:8080/v1
  python igs88h.py --graph /path/to/graph.json --task analyze

  # CWE post-classification (enriches findings with MITRE CWE mappings)
  python igs88h.py /path/to/project --task security --model gemini-3.5-flash \
      --classify-cwes --cwe-model gemma4:12b-it-qat
  python igs88h.py --classify-report results/report.json --cwe-model gemma4:12b-it-qat
  python igs88h.py --classify-report results/report.json --cwe-mode single --cwe-model gemma4
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
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

    Graphify requires files to be git-tracked. If the target directory
    contains untracked files (e.g. test datasets that aren't committed),
    we copy to a temporary git repo, run graphify there, and bring the
    graph back.
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
        if graph_path.exists():
            data = json.loads(graph_path.read_text())
            if data.get("nodes"):
                return CodeGraph.from_json(graph_path)
            logger.info("Graphify produced empty graph (files likely not git-tracked)")
    except FileNotFoundError:
        logger.warning("Graphify CLI not installed, using synthetic graph")
        return build_synthetic_graph(codebase)
    except subprocess.CalledProcessError:
        pass

    # Graphify produced no nodes — likely because files aren't git-tracked.
    # Copy to a temp dir with its own git repo and retry.
    logger.info("Retrying graphify in isolated git repo...")
    try:
        graph = _graphify_in_temp_repo(codebase)
        if graph:
            return graph
    except Exception as e:
        logger.warning(f"Graphify temp-repo fallback failed: {e}")

    logger.warning("Falling back to synthetic graph")
    return build_synthetic_graph(codebase)


def _graphify_in_temp_repo(codebase: Path) -> CodeGraph | None:
    """Copy codebase to a temp dir with git init, run graphify, return the graph."""
    with tempfile.TemporaryDirectory(prefix="igs88h-graphify-") as tmp:
        tmp_path = Path(tmp) / "src"
        shutil.copytree(codebase, tmp_path, ignore=shutil.ignore_patterns(
            "graphify-out", ".git", "__pycache__", "*.pyc",
        ))

        subprocess.run(
            ["git", "init"], cwd=tmp_path,
            capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "add", "."], cwd=tmp_path,
            capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "init", "--allow-empty"],
            cwd=tmp_path, capture_output=True, check=True,
            env={**os.environ, "GIT_AUTHOR_NAME": "igs88h",
                 "GIT_AUTHOR_EMAIL": "igs88h@local",
                 "GIT_COMMITTER_NAME": "igs88h",
                 "GIT_COMMITTER_EMAIL": "igs88h@local"},
        )

        result = subprocess.run(
            ["graphify", "extract", str(tmp_path), "--no-cluster"],
            capture_output=True, text=True,
        )
        logger.info(f"Graphify (temp repo): {result.stdout.strip()}")
        if result.returncode != 0:
            logger.warning(f"Graphify extract failed: {result.stderr.strip()}")
            return None

        tmp_graph = tmp_path / "graphify-out" / "graph.json"
        if not tmp_graph.exists():
            return None

        # Copy graph back to original location
        dest = codebase / "graphify-out"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp_graph, dest / "graph.json")
        logger.info(f"Graphify graph saved to {dest / 'graph.json'}")

        return CodeGraph.from_json(dest / "graph.json")


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


# ── CWE Post-Classification ─────────────────────────────────

def classify_report_cwes(report_data: dict, cwe_mode: str = "2stage",
                         cwe_model: str = "gemma4:12b-it-qat",
                         cwe_api_url: str = "http://localhost:11434/v1") -> dict:
    """Post-process a report to add CWE classifications to all findings.

    Extracts findings from each node's analysis text, runs the CWE classifier,
    and enriches the report with classified CWE mappings.

    Args:
        report_data: Report dict (from TraversalReport.to_dict() or loaded JSON).
        cwe_mode: "2stage" (category→CWE, default) or "single" (full taxonomy).
        cwe_model: Model name for the classifier (Ollama or OpenAI-compatible).
        cwe_api_url: API endpoint for the classifier model.

    Returns:
        Enriched report_data with cwe_classification added to each node and summary.
    """
    sys.path.insert(0, str(Path(__file__).parent / "examples" / "datasets"))
    from score_reports import (
        extract_findings_from_node,
        classify_cwes_2stage,
        classify_cwes_single_stage,
        classify_cwes_db_search,
        classify_cwes_embedding,
    )
    from harness.cwe_db import CWEDatabase

    cwe_db = CWEDatabase.load()
    logger.info(f"CWE Database: {len(cwe_db.entries)} entries (v{cwe_db.version})")

    total_findings = 0
    all_cwes = set()
    nodes_with_findings = 0
    start = time.time()

    results = report_data.get("results", {})
    for nid, node_result in results.items():
        analysis = node_result.get("analysis", "")
        if not analysis:
            continue

        findings = extract_findings_from_node(analysis, mode="inferred")
        if not findings:
            continue

        logger.info(f"  Classifying {len(findings)} findings in {node_result.get('name', nid)}")

        if cwe_mode == "single":
            classified = classify_cwes_single_stage(
                findings, cwe_db, cwe_model, cwe_api_url)
        elif cwe_mode == "db_search":
            classified = classify_cwes_db_search(findings, cwe_db)
        elif cwe_mode == "embedding":
            classified = classify_cwes_embedding(
                findings, cwe_db, model=cwe_model, api_url=cwe_api_url)
        else:
            classified = classify_cwes_2stage(
                findings, cwe_db, cwe_model, cwe_api_url)

        enriched = []
        for f in classified:
            classified_cwes = sorted(f.get("llm_cwes", set()))
            original_cwes = sorted(f.get("cwes", set()))
            all_cwes.update(classified_cwes)
            entry = {
                "name": f.get("name", ""),
                "severity": f.get("severity", ""),
                "original_cwes": original_cwes,
                "classified_cwes": classified_cwes,
            }
            if "cwe_category" in f:
                entry["category"] = f["cwe_category"]
            enriched.append(entry)

        total_findings += len(enriched)
        nodes_with_findings += 1
        node_result["cwe_classification"] = {"findings": enriched}

    duration = time.time() - start
    report_data.setdefault("summary", {})["cwe_classification"] = {
        "method": cwe_mode,
        "model": cwe_model,
        "total_findings_classified": total_findings,
        "nodes_with_findings": nodes_with_findings,
        "unique_cwes": sorted(all_cwes),
        "classification_duration_s": round(duration, 2),
    }

    logger.info(f"CWE classification: {total_findings} findings, "
                f"{len(all_cwes)} unique CWEs, {duration:.1f}s")
    return report_data


MODELS_CONFIG = Path(__file__).parent / "models.json"


def load_models_config(path: Path = MODELS_CONFIG) -> dict:
    """Read the model registry (default model, benchmark matrix, prices)."""
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as e:
        raise SystemExit(f"Model registry not found: {path}. "
                         "Pass --model explicitly or restore models.json.") from e
    except json.JSONDecodeError as e:
        raise SystemExit(f"{path} is not valid JSON: {e}") from e


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
        default=None,
        help="Model to use (e.g. claude-sonnet-5-5, claude-opus-5-5, gemini-3.5-flash, "
             "gpt-4o). Default: 'default_model' in models.json",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=4096,
        help="Max output tokens per LLM call (default: 4096). On Claude 5.x models "
             "thinking tokens count against this limit; truncated calls are counted "
             "in the report summary",
    )
    parser.add_argument(
        "--effort",
        choices=["low", "medium", "high", "xhigh", "max"],
        default=None,
        help="Anthropic only: output_config.effort. Default: not sent (model default; "
             "claude-opus-5-5 defaults to medium, others to high)",
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
    parser.add_argument(
        "--local",
        action="store_true",
        help="Use a local LLM via OpenAI-compatible API (Ollama, llama.cpp, etc.)",
    )
    parser.add_argument(
        "--api-url",
        help="Custom API URL for local LLM (default: http://localhost:11434/v1 for Ollama)",
    )
    parser.add_argument(
        "--classify-cwes",
        action="store_true",
        help="Run CWE post-classification on findings after analysis",
    )
    parser.add_argument(
        "--classify-report",
        metavar="PATH",
        help="Post-hoc: classify CWEs in an existing report.json (skips scan)",
    )
    parser.add_argument(
        "--cwe-mode",
        choices=["2stage", "single", "db_search", "embedding"],
        default="2stage",
        help="CWE classification strategy (default: 2stage). "
             "db_search and embedding require no LLM classifier calls.",
    )
    parser.add_argument(
        "--cwe-model",
        help="Model for CWE classifier (default: --model value). "
             "For embedding mode, defaults to nomic-embed-text:latest.",
    )
    parser.add_argument(
        "--cwe-api-url",
        help="API URL for CWE classifier (default: --api-url or Ollama default)",
    )

    args = parser.parse_args()

    if args.model is None:
        args.model = load_models_config()["default_model"]

    # Resolve CWE classifier settings
    from harness.traversal import _OPENAI_PREFIXES, _DEFAULT_LOCAL_URL
    if args.effort and (args.local or args.model.startswith("gemini")
                        or args.model.startswith(_OPENAI_PREFIXES)):
        parser.error("--effort applies to Anthropic models only")
    if args.cwe_model:
        cwe_model = args.cwe_model
    elif args.cwe_mode == "embedding":
        cwe_model = "nomic-embed-text:latest"
    else:
        cwe_model = args.model
    cwe_api_url = args.cwe_api_url or args.api_url or _DEFAULT_LOCAL_URL

    # ── Post-hoc classification mode ──
    if args.classify_report:
        report_path = Path(args.classify_report)
        if not report_path.exists():
            print(f"Error: report not found: {report_path}")
            sys.exit(1)

        print(f"\n🔬 Post-hoc CWE classification")
        print(f"   Report:  {report_path}")
        print(f"   Mode:    {args.cwe_mode}")
        print(f"   Model:   {cwe_model}")
        print(f"   API URL: {cwe_api_url}\n")

        report_data = json.loads(report_path.read_text())
        report_data = classify_report_cwes(
            report_data, args.cwe_mode, cwe_model, cwe_api_url)

        out = args.output if args.output != "analysis_report.json" else str(
            report_path.parent / f"{report_path.stem}-classified.json")
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(report_data, indent=2))

        cwe_info = report_data["summary"]["cwe_classification"]
        print(f"\n{'='*60}")
        print(f"✅ CWE classification complete!")
        print(f"   Findings classified: {cwe_info['total_findings_classified']}")
        print(f"   Unique CWEs:         {len(cwe_info['unique_cwes'])}")
        print(f"   Duration:            {cwe_info['classification_duration_s']:.1f}s")
        print(f"\n📄 Enriched report saved to {out}")
        return

    # ── Normal scan mode ──

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
    # Gemini, OpenAI, and local models use single calls — no tool loop needed
    needs_tools = (not args.local
                   and not args.model.startswith("gemini")
                   and not args.model.startswith(_OPENAI_PREFIXES))
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
        local=args.local,
        api_url=args.api_url,
        max_tokens=args.max_tokens,
        effort=args.effort,
    )

    # Run
    depth_label = "deep (3-pass)" if args.deep_analysis else "standard (2-pass)"
    print(f"\n🚀 Starting {args.strategy.upper()} traversal with '{args.task}' task...")
    if args.local:
        url = args.api_url or _DEFAULT_LOCAL_URL
        print(f"   Model: {args.model} (local @ {url})")
    else:
        print(f"   Model: {args.model}")
    print(f"   Analysis: {depth_label}")
    print(f"   Max tokens: {args.max_tokens}" + (f" | Effort: {args.effort}" if args.effort else ""))
    print(f"   Max depth: {args.max_depth}")
    print(f"   Parallel: {args.parallel}")
    if args.classify_cwes:
        print(f"   CWE classify: {args.cwe_mode} (model: {cwe_model})")
    print()

    report = traversal.traverse(
        root_ids=args.root,
        task_factory=task,
    )

    # Results
    print(f"\n{'='*60}")
    print(f"✅ Traversal complete!")
    print(f"   Nodes analyzed: {report.nodes_visited}")
    print(f"   Nodes skipped:  {report.nodes_skipped}")
    print(f"   Total tokens:   {report.total_tokens:,} "
          f"(input {report.total_input_tokens:,} / output {report.total_output_tokens:,})")
    print(f"   LLM calls:      {sum(report.stop_reason_counts.values())} "
          f"(truncated {report.truncated_calls}, refused {report.refused_calls})")
    print(f"   Duration:       {report.total_duration_s:.1f}s")
    if report.errors:
        print(f"   Errors:         {len(report.errors)}")
        for err in report.errors[:5]:
            print(f"     ⚠ {err}")

    report_data = report.to_dict()

    # CWE post-classification (inline mode)
    if args.classify_cwes:
        print(f"\n🔬 Running CWE post-classification ({args.cwe_mode})...")
        report_data = classify_report_cwes(
            report_data, args.cwe_mode, cwe_model, cwe_api_url)
        cwe_info = report_data["summary"]["cwe_classification"]
        print(f"   Findings classified: {cwe_info['total_findings_classified']}")
        print(f"   Unique CWEs:         {len(cwe_info['unique_cwes'])}")
        print(f"   Duration:            {cwe_info['classification_duration_s']:.1f}s")

    # Save
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report_data, indent=2))
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
        if args.classify_cwes and nid in report_data["results"]:
            cwe_cls = report_data["results"][nid].get("cwe_classification", {})
            if cwe_cls.get("findings"):
                cwes = set()
                for f in cwe_cls["findings"]:
                    cwes.update(f.get("classified_cwes", []))
                if cwes:
                    print(f"  CWEs: {', '.join(sorted(cwes))}")
        print()


if __name__ == "__main__":
    main()
