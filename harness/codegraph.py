"""
Code Knowledge Graph Adapter

Loads a code knowledge graph (graph.json) from Graphify or other sources.
Provides node/edge queries, neighbor traversal, and code extraction.

Graph contents:
  - Symbols (functions, classes, methods, modules)
  - Relationships (calls, imports, inherits, contains)
  - Code content per symbol

This adapter normalizes multiple graph formats and provides a clean
query API for the traversal engine.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class NodeType(Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    UNKNOWN = "unknown"


class EdgeType(Enum):
    CALLS = "calls"
    IMPORTS = "imports"
    INHERITS = "inherits"
    CONTAINS = "contains"
    REFERENCES = "references"
    UNKNOWN = "unknown"


@dataclass
class GraphNode:
    """A node in the code knowledge graph."""
    id: str
    name: str
    node_type: NodeType
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code: str = ""
    docstring: str = ""
    signature: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        if self.file_path:
            return f"{self.file_path}::{self.name}"
        return self.name


@dataclass
class GraphEdge:
    """An edge (relationship) in the code knowledge graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: dict = field(default_factory=dict)


class CodeGraph:
    """
    Load and query a code knowledge graph.

    Supports multiple graph formats:
      - Graphify (safishamsi/graphify): graph.json with nodes/edges
      - Symbols format: graph.json with symbols + relationships
      - Custom: any JSON with nodes[] and edges[]

    The adapter normalizes all formats into GraphNode/GraphEdge objects.
    """

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[str]] = {}    # outgoing: id -> [target_ids]
        self._reverse_adj: dict[str, list[str]] = {}   # incoming: id -> [source_ids]
        self._base_path: Path | None = None            # codebase root for reading source files

    # ── Loading ──────────────────────────────────────────────

    @classmethod
    def from_json(cls, path: str | Path, base_path: str | Path | None = None) -> "CodeGraph":
        """Load a knowledge graph from a JSON file."""
        path = Path(path)
        with open(path) as f:
            data = json.load(f)

        graph = cls()
        # Infer codebase root: if graph is at <codebase>/graphify-out/graph.json, root is <codebase>
        if base_path:
            graph._base_path = Path(base_path).resolve()
        elif path.parent.name == "graphify-out":
            graph._base_path = path.parent.parent.resolve()

        # Auto-detect format
        if "symbols" in data:
            graph._load_codegraph_format(data)
        elif "nodes" in data and ("edges" in data or "links" in data):
            graph._load_generic_format(data)
        else:
            # Try flat symbol list
            graph._load_flat_format(data)

        graph._build_adjacency()
        graph._load_missing_code()
        logger.info(f"Loaded graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        return graph

    @classmethod
    def from_dict(cls, data: dict) -> "CodeGraph":
        """Load from an already-parsed dict."""
        graph = cls()
        if "symbols" in data:
            graph._load_codegraph_format(data)
        elif "nodes" in data and ("edges" in data or "links" in data):
            graph._load_generic_format(data)
        elif "nodes" in data:
            graph._load_generic_format(data)
        else:
            graph._load_flat_format(data)
        graph._build_adjacency()
        return graph

    def _load_codegraph_format(self, data: dict):
        """Parse CodeGraph's native format (symbols + call_graph + imports)."""
        for sym in data.get("symbols", []):
            node_type = self._parse_node_type(sym.get("kind", "unknown"))
            self.nodes[sym["id"]] = GraphNode(
                id=sym["id"],
                name=sym.get("name", sym["id"]),
                node_type=node_type,
                file_path=sym.get("file", ""),
                line_start=sym.get("line_start", 0),
                line_end=sym.get("line_end", 0),
                code=sym.get("code", ""),
                docstring=sym.get("docstring", ""),
                signature=sym.get("signature", ""),
                metadata={k: v for k, v in sym.items()
                          if k not in ("id", "name", "kind", "file", "line_start",
                                       "line_end", "code", "docstring", "signature")},
            )

        for rel in data.get("relationships", data.get("call_graph", [])):
            edge_type = self._parse_edge_type(rel.get("type", "calls"))
            self.edges.append(GraphEdge(
                source_id=rel.get("source", rel.get("caller", "")),
                target_id=rel.get("target", rel.get("callee", "")),
                edge_type=edge_type,
                metadata=rel.get("metadata", {}),
            ))

    @staticmethod
    def _parse_source_location(loc: str) -> int:
        """Parse Graphify source_location like 'L47' or 'L47-L89' into a line number."""
        if not loc:
            return 0
        loc = loc.strip()
        if loc.startswith("L"):
            try:
                return int(loc[1:].split("-")[0].split(":")[0])
            except ValueError:
                pass
        return 0

    def _load_generic_format(self, data: dict):
        """Parse generic nodes/edges format. Also handles Graphify (links, label, source_file)."""
        for n in data.get("nodes", []):
            nid = n.get("id", n.get("name", ""))
            line_start = n.get("line_start", n.get("start_line", 0))
            if not line_start and "source_location" in n:
                line_start = self._parse_source_location(n["source_location"])
            self.nodes[nid] = GraphNode(
                id=nid,
                name=n.get("name", n.get("label", nid)),
                node_type=self._parse_node_type(
                    n.get("type", n.get("kind", n.get("file_type", "unknown")))),
                file_path=n.get("file", n.get("file_path", n.get("source_file", ""))),
                line_start=line_start,
                line_end=n.get("line_end", n.get("end_line", 0)),
                code=n.get("code", n.get("source", "")),
                docstring=n.get("docstring", ""),
                signature=n.get("signature", ""),
                metadata={k: v for k, v in n.items()
                          if k not in ("id", "name", "label", "type", "kind", "file_type",
                                       "file", "file_path", "source_file", "line_start",
                                       "line_end", "code", "source", "docstring", "signature")},
            )
        for e in data.get("edges", data.get("links", [])):
            self.edges.append(GraphEdge(
                source_id=e.get("source", e.get("from", "")),
                target_id=e.get("target", e.get("to", "")),
                edge_type=self._parse_edge_type(
                    e.get("type", e.get("relation", "unknown"))),
                metadata={k: v for k, v in e.items()
                          if k not in ("source", "target", "from", "to", "type", "relation")},
            ))

    def _load_flat_format(self, data: dict):
        """Handle flat key-value or list formats."""
        if isinstance(data, list):
            for i, item in enumerate(data):
                nid = item.get("id", str(i))
                self.nodes[nid] = GraphNode(
                    id=nid,
                    name=item.get("name", nid),
                    node_type=self._parse_node_type(item.get("type", "unknown")),
                    code=item.get("code", ""),
                    file_path=item.get("file", ""),
                )

    def _build_adjacency(self):
        """Build adjacency lists from edges."""
        self._adjacency = {nid: [] for nid in self.nodes}
        self._reverse_adj = {nid: [] for nid in self.nodes}
        for edge in self.edges:
            if edge.source_id in self.nodes and edge.target_id in self.nodes:
                self._adjacency[edge.source_id].append(edge.target_id)
                self._reverse_adj[edge.target_id].append(edge.source_id)

    def _load_missing_code(self):
        """Read source files from disk for nodes that have file_path but no code."""
        if not self._base_path:
            return
        file_cache: dict[str, list[str]] = {}
        for node in self.nodes.values():
            if node.code or not node.file_path:
                continue
            if node.file_path not in file_cache:
                full = self._base_path / node.file_path
                try:
                    file_cache[node.file_path] = full.read_text(errors="replace").splitlines()
                except OSError:
                    file_cache[node.file_path] = []
            lines = file_cache[node.file_path]
            if not lines:
                continue
            if node.line_start > 0 and node.line_end >= node.line_start:
                node.code = "\n".join(lines[node.line_start - 1 : node.line_end])
            elif node.line_start > 0:
                node.code = "\n".join(lines[node.line_start - 1 : node.line_start + 50])
            else:
                node.code = "\n".join(lines)

    # ── Queries ──────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def get_children(self, node_id: str) -> list[GraphNode]:
        """Get outgoing neighbors (callees, contained symbols, etc.)."""
        return [self.nodes[nid] for nid in self._adjacency.get(node_id, [])
                if nid in self.nodes]

    def get_parents(self, node_id: str) -> list[GraphNode]:
        """Get incoming neighbors (callers, containers, etc.)."""
        return [self.nodes[nid] for nid in self._reverse_adj.get(node_id, [])
                if nid in self.nodes]

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        """Get all outgoing edges from a node."""
        return [e for e in self.edges if e.source_id == node_id]

    def get_edges_to(self, node_id: str) -> list[GraphEdge]:
        """Get all incoming edges to a node."""
        return [e for e in self.edges if e.target_id == node_id]

    def get_roots(self) -> list[GraphNode]:
        """Get nodes with no incoming edges (entry points)."""
        return [self.nodes[nid] for nid in self.nodes
                if not self._reverse_adj.get(nid)]

    def get_leaves(self) -> list[GraphNode]:
        """Get nodes with no outgoing edges (leaf functions)."""
        return [self.nodes[nid] for nid in self.nodes
                if not self._adjacency.get(nid)]

    def get_by_type(self, node_type: NodeType) -> list[GraphNode]:
        """Get all nodes of a given type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_by_file(self, file_path: str) -> list[GraphNode]:
        """Get all nodes in a specific file."""
        return [n for n in self.nodes.values() if n.file_path == file_path]

    def get_subgraph(self, root_id: str, max_depth: int = 3) -> list[GraphNode]:
        """BFS to get all reachable nodes within depth."""
        visited = set()
        queue = [(root_id, 0)]
        result = []
        while queue:
            nid, depth = queue.pop(0)
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            if nid in self.nodes:
                result.append(self.nodes[nid])
                for child_id in self._adjacency.get(nid, []):
                    queue.append((child_id, depth + 1))
        return result

    def files(self) -> list[str]:
        """List all unique file paths in the graph."""
        return sorted(set(n.file_path for n in self.nodes.values() if n.file_path))

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _parse_node_type(kind: str) -> NodeType:
        mapping = {
            "module": NodeType.MODULE,
            "class": NodeType.CLASS,
            "function": NodeType.FUNCTION,
            "func": NodeType.FUNCTION,
            "method": NodeType.METHOD,
            "variable": NodeType.VARIABLE,
            "var": NodeType.VARIABLE,
        }
        return mapping.get(kind.lower(), NodeType.UNKNOWN)

    @staticmethod
    def _parse_edge_type(rel: str) -> EdgeType:
        mapping = {
            "calls": EdgeType.CALLS,
            "call": EdgeType.CALLS,
            "imports": EdgeType.IMPORTS,
            "import": EdgeType.IMPORTS,
            "inherits": EdgeType.INHERITS,
            "extends": EdgeType.INHERITS,
            "contains": EdgeType.CONTAINS,
            "references": EdgeType.REFERENCES,
            "ref": EdgeType.REFERENCES,
        }
        return mapping.get(rel.lower(), EdgeType.UNKNOWN)

    def summary(self) -> str:
        type_counts = {}
        for n in self.nodes.values():
            type_counts[n.node_type.value] = type_counts.get(n.node_type.value, 0) + 1
        return (
            f"CodeGraph: {len(self.nodes)} nodes, {len(self.edges)} edges, "
            f"{len(self.files())} files | {type_counts}"
        )
