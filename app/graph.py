"""Dependency graph primitives.

Node identity is the CycloneDX ``bom-ref``.  Because bom-refs are unique, the
same package name at two versions is two independent nodes that are checked
separately.

All traversals maintain an explicit ``seen`` set, so dependency cycles
terminate, never emit duplicate paths, and never hide reachable components.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .cyclonedx import canonical_hash


@dataclass
class Graph:
    roots: list[str]
    nodes: dict[str, dict[str, Any]]
    adj: dict[str, list[str]]

    @classmethod
    def from_normalized(cls, normalized: dict[str, Any]) -> Graph:
        return cls(
            roots=list(normalized.get("roots", [])),
            nodes=dict(normalized.get("components", {})),
            adj={k: list(v) for k, v in normalized.get("edges", {}).items()},
        )

    def children(self, ref: str) -> list[str]:
        return self.adj.get(ref, [])

    # -- branch model -------------------------------------------------------

    def branches(self) -> list[dict[str, str | None]]:
        """Enumerate incremental dependency branches.

        With a single root, every direct child arc is one branch keyed by the
        child ref (stable across root version bumps); the root's own license is
        the ``__root_self__`` branch.  With several roots the root ref is
        prefixed to keep keys unambiguous.
        """
        branches: list[dict[str, str | None]] = []
        multi = len(self.roots) > 1
        for root in self.roots:
            self_key = f"__root_self__::{root}" if multi else "__root_self__"
            branches.append(
                {"branch_key": self_key, "kind": "self", "root_ref": root,
                 "child_ref": None}
            )
            for child in self.children(root):
                if child == root:
                    # Root self-loop introduces no separate component branch.
                    continue
                key = f"{root}::{child}" if multi else child
                branches.append(
                    {"branch_key": key, "kind": "arc", "root_ref": root,
                     "child_ref": child}
                )
        return branches

    def branch_closure(self, root_ref: str, child_ref: str | None) -> set[str]:
        """Reachable refs inside a branch, never passing back through root.

        Blocking the root keeps cycles that point back at the product from
        expanding the branch into sibling branches and makes the closure a
        precise change-detection boundary.
        """
        if child_ref is None:
            return {root_ref}
        seen: set[str] = {child_ref}
        blocked = {root_ref}
        stack = [child_ref]
        while stack:
            current = stack.pop()
            for nxt in self.children(current):
                if nxt in blocked or nxt in seen:
                    continue
                seen.add(nxt)
                stack.append(nxt)
        return seen

    def branch_signature(self, refs: Iterable[str]) -> str:
        """Content hash of component payloads + all outgoing edges for refs."""
        refset = set(refs)
        payload = {
            "nodes": {ref: self.nodes.get(ref) for ref in sorted(refset)},
            "edges": [
                [src, dst]
                for src in sorted(refset)
                for dst in self.children(src)
            ],
        }
        return canonical_hash(payload)

    # -- path search --------------------------------------------------------

    def branch_paths(
        self, root_ref: str, child_ref: str
    ) -> dict[str, list[str]]:
        """Shortest *relative* path child -> ... -> target for every reachable.

        BFS with a visited map: cycles terminate and each target gets exactly
        one shortest parent chain.  The root is blocked so reconstructed
        paths never repeat it.
        """
        parent: dict[str, str | None] = {child_ref: None}
        queue: deque[str] = deque([child_ref])
        while queue:
            current = queue.popleft()
            for nxt in self.children(current):
                if nxt == root_ref or nxt in parent:
                    continue
                parent[nxt] = current
                queue.append(nxt)

        paths: dict[str, list[str]] = {}
        for target in parent:
            chain: list[str] = []
            cur: str | None = target
            while cur is not None:
                chain.append(cur)
                cur = parent[cur]
            chain.reverse()
            paths[target] = chain
        return paths

    def shortest_paths_from_roots(self) -> dict[str, list[str]]:
        """Independent multi-source BFS oracle for globally shortest paths."""
        parent: dict[str, tuple[str, ...] | None] = {}
        queue: deque[str] = deque()
        for root in self.roots:
            if root not in parent:
                parent[root] = None
                queue.append(root)
        while queue:
            current = queue.popleft()
            for nxt in self.children(current):
                if nxt in parent:
                    continue
                parent[nxt] = (current,)  # marker; reconstruction below
                queue.append(nxt)

        paths: dict[str, list[str]] = {}
        for target in parent:
            chain: list[str] = []
            cur: str | None = target
            seen: set[str] = set()
            while cur is not None:
                if cur in seen:  # defensive; BFS parent tree cannot cycle
                    break
                seen.add(cur)
                chain.append(cur)
                marker = parent[cur]
                cur = marker[0] if isinstance(marker, tuple) else None
            chain.reverse()
            paths[target] = chain
        return paths


def diff_normalized(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Structural diff between two normalized SBOMs (for impact reporting)."""
    old_nodes: dict[str, Any] = old.get("components", {})
    new_nodes: dict[str, Any] = new.get("components", {})
    old_edges: dict[str, list[str]] = old.get("edges", {})
    new_edges: dict[str, list[str]] = new.get("edges", {})

    added = sorted(set(new_nodes) - set(old_nodes))
    removed = sorted(set(old_nodes) - set(new_nodes))
    changed: list[dict[str, Any]] = []
    edge_changed: list[str] = []

    for ref in sorted(set(old_nodes) & set(new_nodes)):
        before = old_nodes[ref]
        after = new_nodes[ref]
        fields = []
        for field_name in ("name", "version", "purl", "type", "licenses"):
            if before.get(field_name) != after.get(field_name):
                fields.append(field_name)
        if fields:
            changed.append({"ref": ref, "fields": fields})
        if sorted(old_edges.get(ref, [])) != sorted(new_edges.get(ref, [])):
            edge_changed.append(ref)

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "edge_changed": edge_changed,
        "touched_refs": sorted(
            set(added)
            | set(removed)
            | {c["ref"] for c in changed}
            | set(edge_changed)
        ),
    }


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
