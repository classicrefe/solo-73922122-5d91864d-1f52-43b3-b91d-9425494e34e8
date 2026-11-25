"""Lenient CycloneDX SBOM parser (JSON and XML) -> normalized graph model.

The normalized model is plain JSON-serializable data::

    {
      "format": "CycloneDX-JSON" | "CycloneDX-XML",
      "spec_version": "1.5",
      "roots": ["app@1.0.0"],
      "components": {bom_ref: {...}},
      "edges": {bom_ref: [child_ref, ...]},
      "warnings": [{"code": ..., "message": ...}]
    }

Hard errors (unparseable document, duplicate bom-ref) raise
:class:`SBOMParseError`.  Dangling dependency references produce placeholder
nodes plus warnings instead of being dropped, so paths are never silently
truncated.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import defusedxml.ElementTree as ET


class SBOMParseError(ValueError):
    """The supplied document is not a usable CycloneDX SBOM."""


@dataclass
class ParsedSBOM:
    normalized: dict[str, Any]
    original_text: str
    declared_format: str  # json | xml

    @property
    def content_hash(self) -> str:
        return canonical_hash(self.normalized)


def canonical_hash(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Shared normalization
# ---------------------------------------------------------------------------


def _norm_licenses(raw_licenses: Any) -> list[dict[str, str]]:
    claims: list[dict[str, str]] = []
    if not isinstance(raw_licenses, list):
        return claims
    for entry in raw_licenses:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str):
            claims.append({"kind": "expression", "value": entry["expression"].strip()})
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            if isinstance(lic.get("id"), str):
                claims.append({"kind": "id", "value": lic["id"].strip()})
            elif isinstance(lic.get("name"), str):
                claims.append({"kind": "name", "value": lic["name"].strip()})
        # Some documents use a flat {"id": ...} / {"name": ...} entry.
        elif isinstance(entry.get("id"), str):
            claims.append({"kind": "id", "value": entry["id"].strip()})
        elif isinstance(entry.get("name"), str):
            claims.append({"kind": "name", "value": entry["name"].strip()})
    return claims


def _component_dict(
    *,
    ref: str,
    name: str | None,
    version: str | None,
    purl: str | None,
    cdx_type: str | None,
    licenses: list[dict[str, str]],
    supplier: str | None = None,
) -> dict[str, Any]:
    return {
        "bom_ref": ref,
        "type": cdx_type or "library",
        "name": name or ref,
        "version": version,
        "purl": purl,
        "supplier": supplier,
        "licenses": licenses,
        "missing": False,
    }


def _auto_ref(name: str | None, version: str | None, purl: str | None) -> str:
    if purl:
        return purl
    base = name or "unknown"
    return f"auto:{base}@{version or 'unspecified'}"


def _add_component(
    components: dict[str, dict[str, Any]],
    comp: dict[str, Any],
    warnings: list[dict[str, str]],
) -> None:
    ref = comp["bom_ref"]
    if ref in components:
        if canonical_hash(components[ref]) == canonical_hash(comp):
            return  # exact duplicate entry is harmless
        raise SBOMParseError(
            f"Duplicate bom-ref {ref!r} with conflicting component data; "
            "bom-ref values must be unique"
        )
    components[ref] = comp


def _merge_or_add_component(
    components: dict[str, dict[str, Any]],
    listed: dict[str, str],
    comp: dict[str, Any],
    warnings: list[dict[str, str]],
) -> None:
    """Process an entry from the ``components`` array.

    Conflicting duplicates *inside* the array are rejected.  When the same
    ref was first seen as ``metadata.component`` (common in real SBOMs), the
    richer array entry is merged in instead.
    """
    ref = comp["bom_ref"]
    comp_hash = canonical_hash(comp)
    if ref in listed:
        if listed[ref] != comp_hash:
            raise SBOMParseError(
                f"Duplicate bom-ref {ref!r} with conflicting component data; "
                "bom-ref values must be unique"
            )
        return
    listed[ref] = comp_hash

    existing = components.get(ref)
    if existing is None:
        components[ref] = comp
        return
    if canonical_hash(existing) == comp_hash:
        return

    claim_hashes = {canonical_hash(c) for c in existing.get("licenses", [])}
    for claim in comp.get("licenses", []):
        claim_hash = canonical_hash(claim)
        if claim_hash not in claim_hashes:
            existing.setdefault("licenses", []).append(claim)
            claim_hashes.add(claim_hash)
    for field_name in ("version", "purl", "supplier", "type"):
        if not existing.get(field_name) and comp.get(field_name):
            existing[field_name] = comp[field_name]
    if existing.get("name") in (None, ref) and comp.get("name"):
        existing["name"] = comp["name"]
    warnings.append(
        {
            "code": "duplicate_bom_ref_merged",
            "message": (
                f"bom-ref {ref!r} is present in both metadata.component and "
                "components; license data was merged"
            ),
        }
    )


def _stub_component(ref: str) -> dict[str, Any]:
    return {
        "bom_ref": ref,
        "type": "unknown",
        "name": ref.rsplit("/", 1)[-1] if "/" in ref else ref,
        "version": None,
        "purl": ref if ref.startswith("pkg:") else None,
        "supplier": None,
        "licenses": [],
        "missing": True,
    }


def _resolve_roots(
    components: dict[str, dict[str, Any]],
    edges: dict[str, list[str]],
    metadata_ref: str | None,
    warnings: list[dict[str, str]],
) -> list[str]:
    if metadata_ref and metadata_ref in components:
        return [metadata_ref]

    targets: set[str] = set()
    for children in edges.values():
        targets.update(children)

    sources = list(edges.keys())
    roots = [ref for ref in sources if ref not in targets]
    if roots:
        # Preserve first-seen order and de-duplicate.
        seen: set[str] = set()
        ordered = []
        for ref in roots:
            if ref not in seen:
                seen.add(ref)
                ordered.append(ref)
        if metadata_ref:
            warnings.append(
                {
                    "code": "metadata_root_unresolved",
                    "message": (
                        f"metadata.component bom-ref {metadata_ref!r} is not present; "
                        "using dependency graph roots instead"
                    ),
                }
            )
        return ordered

    if sources:
        warnings.append(
            {
                "code": "cyclic_graph_no_root",
                "message": "Dependency graph has no indegree-zero root (pure cycle?); "
                f"using first declared node {sources[0]!r} as root",
            }
        )
        return [sources[0]]

    return list(components.keys())


def _build_result(
    *,
    fmt: str,
    spec_version: str | None,
    components: dict[str, dict[str, Any]],
    raw_edges: list[tuple[str, list[str]]],
    metadata_ref: str | None,
    warnings: list[dict[str, str]],
    original_text: str,
) -> ParsedSBOM:
    edges: dict[str, list[str]] = {}
    for source, children in raw_edges:
        if source not in components:
            components[source] = _stub_component(source)
            warnings.append(
                {
                    "code": "dangling_dependency_ref",
                    "message": f"dependency ref {source!r} has no component entry",
                }
            )
        bucket = edges.setdefault(source, [])
        seen = set(bucket)
        for child in children:
            if child == source:
                # Self-loop is retained in the graph but needs no edge dup.
                pass
            if child not in seen:
                seen.add(child)
                bucket.append(child)
            if child not in components:
                components[child] = _stub_component(child)
                warnings.append(
                    {
                        "code": "dangling_depends_on_ref",
                        "message": (
                            f"dependency {source!r} depends on {child!r} which has "
                            "no component entry"
                        ),
                    }
                )

    roots = _resolve_roots(components, edges, metadata_ref, warnings)
    normalized = {
        "format": fmt,
        "spec_version": spec_version,
        "roots": roots,
        "components": components,
        "edges": edges,
        "warnings": warnings,
    }
    return ParsedSBOM(
        normalized=normalized, original_text=original_text, declared_format="json"
        if fmt.endswith("JSON")
        else "xml",
    )


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def _component_from_json(item: dict[str, Any]) -> dict[str, Any]:
    name = item.get("name")
    version = item.get("version")
    purl = item.get("purl")
    ref = item.get("bom-ref") or item.get("bomRef") or _auto_ref(name, version, purl)
    supplier = None
    sup = item.get("supplier")
    if isinstance(sup, dict) and isinstance(sup.get("name"), str):
        supplier = sup["name"]
    return _component_dict(
        ref=ref,
        name=name if isinstance(name, str) else None,
        version=version if isinstance(version, str) else None,
        purl=purl if isinstance(purl, str) else None,
        cdx_type=item.get("type") if isinstance(item.get("type"), str) else None,
        licenses=_norm_licenses(item.get("licenses")),
        supplier=supplier,
    )


def parse_cyclonedx_json(text: str) -> ParsedSBOM:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SBOMParseError(f"Invalid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise SBOMParseError("CycloneDX document must be a JSON object")

    if doc.get("bomFormat") and doc.get("bomFormat") != "CycloneDX":
        raise SBOMParseError(
            f"bomFormat is {doc.get('bomFormat')!r}, expected 'CycloneDX'"
        )

    warnings: list[dict[str, str]] = []
    components: dict[str, dict[str, Any]] = {}
    metadata_ref: str | None = None

    metadata = doc.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        comp = _component_from_json(metadata["component"])
        metadata_ref = comp["bom_ref"]
        _add_component(components, comp, warnings)

    raw_components = doc.get("components", [])
    if raw_components is None:
        raw_components = []
    if not isinstance(raw_components, list):
        raise SBOMParseError("'components' must be an array")
    listed_refs: dict[str, str] = {}
    for item in raw_components:
        if not isinstance(item, dict):
            raise SBOMParseError("Every component must be a JSON object")
        _merge_or_add_component(
            components, listed_refs, _component_from_json(item), warnings
        )

    raw_edges: list[tuple[str, list[str]]] = []
    dependencies = doc.get("dependencies", [])
    if dependencies is None:
        dependencies = []
    if not isinstance(dependencies, list):
        raise SBOMParseError("'dependencies' must be an array")
    for dep in dependencies:
        if not isinstance(dep, dict) or not isinstance(dep.get("ref"), str):
            warnings.append(
                {"code": "invalid_dependency_entry", "message": f"Skipping {dep!r}"}
            )
            continue
        children = dep.get("dependsOn", []) or []
        if not isinstance(children, list):
            continue
        raw_edges.append(
            (dep["ref"], [c for c in children if isinstance(c, str)])
        )

    return _build_result(
        fmt="CycloneDX-JSON",
        spec_version=doc.get("specVersion")
        if isinstance(doc.get("specVersion"), str)
        else None,
        components=components,
        raw_edges=raw_edges,
        metadata_ref=metadata_ref,
        warnings=warnings,
        original_text=text,
    )


# ---------------------------------------------------------------------------
# XML (namespace agnostic)
# ---------------------------------------------------------------------------


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child(el: ET.Element, name: str) -> ET.Element | None:
    for child in el:
        if _local(child.tag) == name:
            return child
    return None


def _children(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el if _local(c.tag) == name]


def _text(el: ET.Element | None) -> str | None:
    if el is None:
        return None
    return el.text.strip() if el.text and el.text.strip() else None


def _licenses_from_xml(parent: ET.Element | None) -> list[dict[str, str]]:
    claims: list[dict[str, str]] = []
    if parent is None:
        return claims
    licenses_el = parent if _local(parent.tag) == "licenses" else _child(parent, "licenses")
    if licenses_el is None:
        return claims
    for entry in licenses_el:
        tag = _local(entry.tag)
        if tag == "expression":
            value = _text(entry)
            if value:
                claims.append({"kind": "expression", "value": value})
        elif tag == "license":
            lid = _text(_child(entry, "id"))
            lname = _text(_child(entry, "name"))
            if lid:
                claims.append({"kind": "id", "value": lid})
            elif lname:
                claims.append({"kind": "name", "value": lname})
    return claims


def _component_from_xml(el: ET.Element) -> dict[str, Any]:
    name = _text(_child(el, "name"))
    version = _text(_child(el, "version"))
    purl = _text(_child(el, "purl"))
    ref = el.attrib.get("bom-ref") or _auto_ref(name, version, purl)
    supplier = None
    sup = _child(el, "supplier")
    if sup is not None:
        sname = _child(sup, "name")
        supplier = _text(sname)
    return _component_dict(
        ref=ref,
        name=name,
        version=version,
        purl=purl,
        cdx_type=el.attrib.get("type"),
        licenses=_licenses_from_xml(el),
        supplier=supplier,
    )


def parse_cyclonedx_xml(text: str) -> ParsedSBOM:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SBOMParseError(f"Invalid XML: {exc}") from exc

    warnings: list[dict[str, str]] = []
    components: dict[str, dict[str, Any]] = {}
    metadata_ref: str | None = None

    metadata = _child(root, "metadata")
    if metadata is not None:
        meta_comp = _child(metadata, "component")
        if meta_comp is not None:
            comp = _component_from_xml(meta_comp)
            metadata_ref = comp["bom_ref"]
            _add_component(components, comp, warnings)

    components_el = _child(root, "components")
    listed_refs: dict[str, str] = {}
    if components_el is not None:
        for item in _children(components_el, "component"):
            _merge_or_add_component(
                components, listed_refs, _component_from_xml(item), warnings
            )

    raw_edges: list[tuple[str, list[str]]] = []
    deps_el = _child(root, "dependencies")
    if deps_el is not None:
        for dep in _children(deps_el, "dependency"):
            source = dep.attrib.get("ref")
            if not source:
                continue
            # CycloneDX XML nests dependency elements:
            # <dependency ref="a"><dependency ref="b"/></dependency>
            children = [
                d.attrib["ref"]
                for d in _children(dep, "dependency")
                if d.attrib.get("ref")
            ]
            raw_edges.append((source, children))

    spec_version = root.attrib.get("version") or root.attrib.get("specVersion")
    return _build_result(
        fmt="CycloneDX-XML",
        spec_version=spec_version,
        components=components,
        raw_edges=raw_edges,
        metadata_ref=metadata_ref,
        warnings=warnings,
        original_text=text,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_sbom(content: bytes | str | dict[str, Any]) -> ParsedSBOM:
    if isinstance(content, dict):
        return parse_cyclonedx_json(
            json.dumps(content, ensure_ascii=False)
        )
    # utf-8-sig strips a BOM if present.
    text = (
        content.decode("utf-8-sig", errors="replace")
        if isinstance(content, bytes)
        else content
    )

    probe = text.lstrip()
    if not probe:
        raise SBOMParseError("SBOM document is empty")
    if probe.startswith("<"):
        return parse_cyclonedx_xml(text)
    return parse_cyclonedx_json(text)
