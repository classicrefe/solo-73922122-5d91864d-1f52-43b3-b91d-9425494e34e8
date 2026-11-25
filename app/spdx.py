"""SPDX restricted-license rules.

Responsibilities:

* import restricted SPDX identifier lists from several common shapes;
* match SBOM license identifiers against the restricted set, including the
  deprecated bare GPL/LGPL/AGPL identifiers and ``-only`` / ``-or-later``
  variants (conservative family matching);
* parse and evaluate the small SPDX expression language (``AND`` / ``OR`` /
  ``WITH`` / parentheses).

Dual licensing with ``OR`` is treated as a choice: a component is violating
only when every alternative is restricted.  ``AND`` means all licenses apply,
so any restricted operand makes the component violating.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


class RuleListError(ValueError):
    """Raised when a restricted-license list cannot be understood."""


def parse_rule_list(content: bytes | str, content_type: str = "") -> list[str]:
    """Parse an uploaded restricted list into a de-duplicated list of entries.

    Accepted shapes:

    * JSON array of strings: ``["GPL-3.0-only", "AGPL-3.0-only"]``
    * JSON object ``{"licenses": [...]}`` where items are strings or the
      official SPDX License List objects ``{"licenseId": "..."}``
    * JSON object ``{"restricted": [...]}`` / ``{"spdx_licenses": [...]}``
    * plain text: one SPDX id per line, ``#`` comments and commas allowed.
    """
    text = (
        content.decode("utf-8-sig", errors="replace")
        if isinstance(content, bytes)
        else content
    )

    stripped = text.strip()
    ctype = (content_type or "").lower()

    data: Any = None
    if "json" in ctype or stripped.startswith(("[", "{")):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            if stripped.startswith(("[", "{")):
                raise RuleListError(f"Invalid JSON rule list: {exc}") from exc
            data = None

    entries: list[str] = []
    if data is not None:
        raw_items: Iterable[Any]
        if isinstance(data, list):
            raw_items = data
        elif isinstance(data, dict):
            for key in ("licenses", "restricted", "spdx_licenses", "licenseIds"):
                if key in data:
                    raw_items = data[key]
                    break
            else:
                # Single official SPDX list document sometimes uses
                # {"licenseListVersion": ..., "licenses": [...]}.
                raise RuleListError(
                    "JSON rule object must contain a 'licenses'/'restricted' array"
                )
        else:
            raise RuleListError("Rule list JSON must be an array or object")

        if not isinstance(raw_items, list):
            raise RuleListError("The license entry collection must be an array")

        for item in raw_items:
            if isinstance(item, str):
                entries.append(item)
            elif isinstance(item, dict):
                lid = item.get("licenseId") or item.get("id") or item.get("spdx_id")
                if isinstance(lid, str):
                    entries.append(lid)
                else:
                    raise RuleListError(f"License object without licenseId: {item!r}")
            else:
                raise RuleListError(f"Unsupported license entry: {item!r}")
    else:
        # Plain text / CSV.
        for line in text.splitlines():
            line = line.split("#", 1)[0]
            entries.extend(part.strip() for part in re.split(r"[,\s]+", line))

    result: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        key = entry.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)

    if not result:
        raise RuleListError("Restricted license list is empty")
    return result


# ---------------------------------------------------------------------------
# Identifier matching
# ---------------------------------------------------------------------------

_SUFFIXES = ("-OR-LATER", "-ONLY")


def spdx_match_keys(identifier: str) -> set[str]:
    """Return uppercase keys used for restriction matching.

    The exact identifier and its version family (stripped of ``-only``,
    ``-or-later`` and a trailing ``+``) are included.
    """
    token = identifier.strip().upper()
    if not token:
        return set()
    keys = {token}
    family = token[:-1] if token.endswith("+") else token
    for suffix in _SUFFIXES:
        if family.endswith(suffix):
            family = family[: -len(suffix)]
            break
    keys.add(family)
    return keys


def name_match_key(name: str) -> str:
    return f"name:{name.strip().casefold()}"


@dataclass
class RestrictionRules:
    """Compiled restricted-license lookup."""

    entries: list[str]
    key_to_rules: dict[str, list[str]] = field(default_factory=dict)
    name_to_rules: dict[str, list[str]] = field(default_factory=dict)
    match_keys: set[str] = field(default_factory=set)

    @classmethod
    def compile(cls, entries: list[str]) -> RestrictionRules:
        key_to_rules: dict[str, list[str]] = {}
        name_to_rules: dict[str, list[str]] = {}
        all_keys: set[str] = set()
        for rule in entries:
            for key in spdx_match_keys(rule):
                key_to_rules.setdefault(key, []).append(rule)
                all_keys.add(key)
            nk = name_match_key(rule)
            name_to_rules.setdefault(nk, []).append(rule)
            all_keys.add(nk)
        return cls(
            entries=list(entries),
            key_to_rules=key_to_rules,
            name_to_rules=name_to_rules,
            match_keys=all_keys,
        )

    def match_spdx(self, identifier: str) -> list[str]:
        """Return matched rule entries for an SPDX identifier/token."""
        matched: set[str] = set()
        for key in spdx_match_keys(identifier):
            matched.update(self.key_to_rules.get(key, ()))
        return sorted(matched)

    def match_name(self, name: str) -> list[str]:
        return sorted(set(self.name_to_rules.get(name_match_key(name), ())))

    def is_restricted_spdx(self, identifier: str) -> bool:
        return bool(self.match_spdx(identifier))


def flipped_match_keys(old: RestrictionRules, new: RestrictionRules) -> set[str]:
    """Keys whose restricted status differs between two rule compilations."""
    return old.match_keys ^ new.match_keys


# ---------------------------------------------------------------------------
# SPDX expression parsing & evaluation
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


def _tokenize(expression: str) -> list[str]:
    return _TOKEN_RE.findall(expression)


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> tuple:
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise ValueError(f"Unexpected token {self._peek()!r} in SPDX expression")
        return node

    def _parse_or(self) -> tuple:
        left = self._parse_and()
        while (self._peek() or "").upper() == "OR":
            self._next()
            right = self._parse_and()
            left = ("or", left, right)
        return left

    def _parse_and(self) -> tuple:
        left = self._parse_atom()
        while True:
            tok = self._peek()
            if tok is None or tok == ")" or tok.upper() == "OR":
                break
            if tok.upper() == "AND":
                self._next()
            right = self._parse_atom()
            left = ("and", left, right)
        return left

    def _parse_atom(self) -> tuple:
        tok = self._peek()
        if tok is None:
            raise ValueError("Unexpected end of SPDX expression")
        if tok == "(":
            self._next()
            node = self._parse_or()
            closing = self._next() if self._peek() is not None else None
            if closing != ")":
                raise ValueError("Missing ')' in SPDX expression")
            return node
        if tok.upper() in {"AND", "OR", "WITH", ")"}:
            raise ValueError(f"Unexpected keyword/token {tok!r} in SPDX expression")
        license_id = self._next()
        exception = None
        if (self._peek() or "").upper() == "WITH":
            self._next()
            exception_tok = self._peek()
            if exception_tok is None or exception_tok.upper() in {"AND", "OR", "WITH"}:
                raise ValueError("WITH must be followed by an exception identifier")
            exception = self._next()
        return ("license", license_id, exception)


def parse_expression(expression: str) -> tuple:
    """Parse an SPDX expression into a small tuple AST.

    ``("license", identifier, exception|None)``,
    ``("and", left, right)``, ``("or", left, right)``.
    """
    return _Parser(_tokenize(expression)).parse()


@dataclass
class ExpressionVerdict:
    violates: bool
    bad_licenses: list[dict[str, Any]] = field(default_factory=list)
    mentioned_licenses: list[dict[str, Any]] = field(default_factory=list)
    parse_error: str | None = None


def _eval_node(node: tuple, rules: RestrictionRules) -> tuple[bool, list[dict]]:
    kind = node[0]
    if kind == "license":
        _, identifier, exception = node
        matched = rules.match_spdx(identifier)
        if matched:
            return True, [
                {
                    "license": identifier,
                    "exception": exception,
                    "matched_rule_ids": matched,
                }
            ]
        return False, []
    _, left, right = node
    left_bad, left_items = _eval_node(left, rules)
    right_bad, right_items = _eval_node(right, rules)
    if kind == "and":
        # All licenses apply: any restricted operand poisons the result.
        return (left_bad or right_bad), left_items + right_items
    # OR: a choice exists. Violation only if every alternative is bad.
    if left_bad and right_bad:
        return True, left_items + right_items
    return False, []


def _collect_mentioned(node: tuple, rules: RestrictionRules) -> list[dict]:
    kind = node[0]
    if kind == "license":
        _, identifier, exception = node
        matched = rules.match_spdx(identifier)
        if matched:
            return [
                {
                    "license": identifier,
                    "exception": exception,
                    "matched_rule_ids": matched,
                }
            ]
        return []
    return _collect_mentioned(node[1], rules) + _collect_mentioned(node[2], rules)


def evaluate_expression(expression: str, rules: RestrictionRules) -> ExpressionVerdict:
    try:
        ast = parse_expression(expression)
        bad, items = _eval_node(ast, rules)
        mentioned = _collect_mentioned(ast, rules)
        # De-duplicate mentioned entries by license token.
        seen: set[str] = set()
        mentioned_unique = []
        for item in mentioned:
            if item["license"] not in seen:
                seen.add(item["license"])
                mentioned_unique.append(item)
        return ExpressionVerdict(
            violates=bad,
            bad_licenses=items,
            mentioned_licenses=mentioned_unique,
        )
    except (ValueError, IndexError) as exc:
        # Fallback: scan for known restricted identifiers so a malformed
        # expression cannot silently hide a known-bad license.
        found: list[dict[str, Any]] = []
        for token in _tokenize(expression):
            if token in {"(", ")", "AND", "OR", "WITH"}:
                continue
            matched = rules.match_spdx(token)
            if matched:
                found.append(
                    {"license": token, "exception": None, "matched_rule_ids": matched}
                )
        return ExpressionVerdict(
            violates=bool(found),
            bad_licenses=found,
            mentioned_licenses=found,
            parse_error=str(exc),
        )
