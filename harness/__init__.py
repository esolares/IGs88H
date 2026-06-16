"""
Recursive Agent Harness for Code Knowledge Graph Traversal

Usage:
    from harness import AgentHarness, ToolRegistry, CodeGraph, GraphTraversal

    # Load a CodeGraph knowledge graph
    graph = CodeGraph.from_json("path/to/graph.json")

    # Set up traversal with analysis
    traversal = GraphTraversal(graph, model="claude-sonnet-4-6")
    report = traversal.traverse()

    # Save results
    report.save("analysis_report.json")
"""

from .core import AgentHarness, ToolRegistry, HarnessResult
from .codegraph import CodeGraph, GraphNode, GraphEdge, NodeType, EdgeType
from .traversal import (
    GraphTraversal,
    TraversalStrategy,
    TraversalReport,
    NodeResult,
    analyze_task,
    test_gen_task,
    dependency_audit_task,
    dataflow_task,
    practices_task,
    oop_task,
    duplication_task,
)

__all__ = [
    "AgentHarness",
    "ToolRegistry",
    "HarnessResult",
    "CodeGraph",
    "GraphNode",
    "GraphEdge",
    "NodeType",
    "EdgeType",
    "GraphTraversal",
    "TraversalStrategy",
    "TraversalReport",
    "NodeResult",
    "analyze_task",
    "test_gen_task",
    "dependency_audit_task",
    "dataflow_task",
    "practices_task",
    "oop_task",
    "duplication_task",
]
