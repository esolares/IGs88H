#!/usr/bin/env python3
"""
Build graph.json fixtures from test datasets.

Parses vulnerable code as TEXT via ast.parse() — never executes it.
Outputs graph.json files that can be loaded by CodeGraph.from_json().

Usage:
    python examples/build_test_graphs.py                  # build all three
    python examples/build_test_graphs.py securityeval     # build one
    python examples/build_test_graphs.py dsvw
    python examples/build_test_graphs.py dsvpwa
"""

import ast
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DATASETS_DIR = Path(__file__).parent / "datasets"


def parse_functions_from_source(source: str, file_path: str) -> tuple[list[dict], list[dict]]:
    """Extract function/class nodes from Python source using AST only. Never executes code."""
    nodes = []
    edges = []
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        logger.warning(f"SyntaxError in {file_path}: {e}")
        return nodes, edges

    module_id = file_path.replace("/", ".").replace(".py", "")
    nodes.append({
        "id": module_id,
        "name": module_id,
        "type": "module",
        "file": file_path,
        "code": "",
    })

    lines = source.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_id = f"{module_id}.{node.name}"
            code_lines = lines[node.lineno - 1 : node.end_lineno] if node.end_lineno else []
            nodes.append({
                "id": func_id,
                "name": node.name,
                "type": "function",
                "file": file_path,
                "line_start": node.lineno,
                "line_end": node.end_lineno or node.lineno,
                "code": "\n".join(code_lines),
                "docstring": ast.get_docstring(node) or "",
            })
            edges.append({"source": module_id, "target": func_id, "type": "contains"})

            # Find calls to other functions
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee = _get_call_name(child)
                    if callee:
                        callee_id = f"{module_id}.{callee}"
                        edges.append({"source": func_id, "target": callee_id, "type": "calls"})

        elif isinstance(node, ast.ClassDef):
            cls_id = f"{module_id}.{node.name}"
            code_lines = lines[node.lineno - 1 : node.end_lineno] if node.end_lineno else []
            nodes.append({
                "id": cls_id,
                "name": node.name,
                "type": "class",
                "file": file_path,
                "line_start": node.lineno,
                "line_end": node.end_lineno or node.lineno,
                "code": "\n".join(code_lines),
                "docstring": ast.get_docstring(node) or "",
            })
            edges.append({"source": module_id, "target": cls_id, "type": "contains"})

            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_id = f"{cls_id}.{item.name}"
                    method_lines = lines[item.lineno - 1 : item.end_lineno] if item.end_lineno else []
                    nodes.append({
                        "id": method_id,
                        "name": item.name,
                        "type": "method",
                        "file": file_path,
                        "line_start": item.lineno,
                        "line_end": item.end_lineno or item.lineno,
                        "code": "\n".join(method_lines),
                        "docstring": ast.get_docstring(item) or "",
                    })
                    edges.append({"source": cls_id, "target": method_id, "type": "contains"})

    return nodes, edges


def _get_call_name(call_node: ast.Call) -> str | None:
    """Extract function name from a Call node."""
    if isinstance(call_node.func, ast.Name):
        return call_node.func.id
    if isinstance(call_node.func, ast.Attribute):
        return call_node.func.attr
    return None


def build_securityeval():
    """Build graph.json from SecurityEval JSONL — one node per vulnerable snippet."""
    dataset_path = DATASETS_DIR / "securityeval" / "dataset.jsonl"
    if not dataset_path.exists():
        logger.error(f"Missing {dataset_path}")
        return

    nodes = []
    edges = []
    samples = []

    with open(dataset_path) as f:
        for line in f:
            samples.append(json.loads(line))

    logger.info(f"SecurityEval: {len(samples)} samples")

    for sample in samples:
        sample_id = sample["ID"].replace(".py", "")
        cwe = sample_id.split("_")[0]
        code = sample["Insecure_code"]

        file_nodes, file_edges = parse_functions_from_source(code, f"securityeval/{sample['ID']}")

        if not file_nodes:
            nodes.append({
                "id": sample_id,
                "name": sample_id,
                "type": "module",
                "file": f"securityeval/{sample['ID']}",
                "code": code,
                "metadata": {"cwe": cwe},
            })
        else:
            for n in file_nodes:
                n["metadata"] = {"cwe": cwe, "sample_id": sample["ID"]}
            nodes.extend(file_nodes)
            edges.extend(file_edges)

    # Deduplicate edges
    seen = set()
    unique_edges = []
    for e in edges:
        key = (e["source"], e["target"], e["type"])
        if key not in seen:
            seen.add(key)
            unique_edges.append(e)

    graph = {"nodes": nodes, "edges": unique_edges}
    out_path = DATASETS_DIR / "securityeval" / "graph.json"
    out_path.write_text(json.dumps(graph, indent=2))
    logger.info(f"  → {out_path}: {len(nodes)} nodes, {len(unique_edges)} edges")


def build_dsvw():
    """Build graph.json from DSVW single-file app."""
    source_path = DATASETS_DIR / "dsvw" / "dsvw.py"
    if not source_path.exists():
        logger.error(f"Missing {source_path}")
        return

    source = source_path.read_text()
    nodes, edges = parse_functions_from_source(source, "dsvw/dsvw.py")

    # Deduplicate
    seen = set()
    unique_edges = []
    for e in edges:
        key = (e["source"], e["target"], e["type"])
        if key not in seen:
            seen.add(key)
            unique_edges.append(e)

    graph = {"nodes": nodes, "edges": unique_edges}
    out_path = DATASETS_DIR / "dsvw" / "graph.json"
    out_path.write_text(json.dumps(graph, indent=2))
    logger.info(f"DSVW → {out_path}: {len(nodes)} nodes, {len(unique_edges)} edges")


def build_dsvpwa():
    """Build graph.json from DSVPWA multi-file app."""
    dsvpwa_dir = DATASETS_DIR / "dsvpwa"
    py_files = ["dsvpwa.py", "server.py", "handlers.py", "attacks.py"]

    all_nodes = []
    all_edges = []

    for filename in py_files:
        filepath = dsvpwa_dir / filename
        if not filepath.exists():
            logger.warning(f"Missing {filepath}")
            continue

        source = filepath.read_text()
        nodes, edges = parse_functions_from_source(source, f"dsvpwa/{filename}")
        all_nodes.extend(nodes)
        all_edges.extend(edges)

    # Add cross-module import edges by scanning for import statements
    module_map = {n["id"]: n for n in all_nodes if n["type"] == "module"}
    for node in all_nodes:
        if node["type"] == "module" and node["code"] == "":
            filepath = dsvpwa_dir / node["file"].replace("dsvpwa/", "")
            if filepath.exists():
                try:
                    tree = ast.parse(filepath.read_text())
                    for stmt in ast.walk(tree):
                        if isinstance(stmt, ast.ImportFrom) and stmt.module:
                            target_id = f"dsvpwa.{stmt.module.split('.')[-1]}"
                            if target_id in module_map and target_id != node["id"]:
                                all_edges.append({
                                    "source": node["id"],
                                    "target": target_id,
                                    "type": "imports",
                                })
                except SyntaxError:
                    pass

    # Deduplicate
    seen = set()
    unique_edges = []
    for e in all_edges:
        key = (e["source"], e["target"], e["type"])
        if key not in seen:
            seen.add(key)
            unique_edges.append(e)

    graph = {"nodes": all_nodes, "edges": unique_edges}
    out_path = dsvpwa_dir / "graph.json"
    out_path.write_text(json.dumps(graph, indent=2))
    logger.info(f"DSVPWA → {out_path}: {len(all_nodes)} nodes, {len(unique_edges)} edges")


BUILDERS = {
    "securityeval": build_securityeval,
    "dsvw": build_dsvw,
    "dsvpwa": build_dsvpwa,
}

if __name__ == "__main__":
    targets = sys.argv[1:] or list(BUILDERS.keys())
    for target in targets:
        if target in BUILDERS:
            BUILDERS[target]()
        else:
            logger.error(f"Unknown dataset: {target}. Choose from: {list(BUILDERS.keys())}")
