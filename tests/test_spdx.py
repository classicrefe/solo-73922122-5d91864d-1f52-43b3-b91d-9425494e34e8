from app.spdx import (
    RestrictionRules,
    evaluate_expression,
    parse_rule_list,
)


def test_parse_rule_list_shapes():
    assert parse_rule_list('["GPL-3.0-only", "MIT"]') == ["GPL-3.0-only", "MIT"]
    doc = '{"licenses": [{"licenseId": "AGPL-3.0-only"}, {"licenseId": "MIT"}]}'
    assert parse_rule_list(doc, "application/json") == ["AGPL-3.0-only", "MIT"]
    text = "# comment\nGPL-3.0-only, MIT\n\nApache-2.0\n"
    assert parse_rule_list(text, "text/plain") == [
        "GPL-3.0-only",
        "MIT",
        "Apache-2.0",
    ]


def test_parse_rule_list_dedup_case_insensitive():
    assert parse_rule_list('["MIT", "mit", "MIT"]') == ["MIT"]


def test_family_matching_deprecated_and_suffixes():
    rules = RestrictionRules.compile(["GPL-3.0-only"])
    assert rules.is_restricted_spdx("GPL-3.0-only")
    # conservative family match across -only / -or-later / deprecated bare id
    assert rules.is_restricted_spdx("GPL-3.0-or-later")
    assert rules.is_restricted_spdx("GPL-3.0")
    assert not rules.is_restricted_spdx("LGPL-3.0-only")
    assert not rules.is_restricted_spdx("MIT")


def test_or_expression_allows_choice():
    rules = RestrictionRules.compile(["GPL-3.0-only"])
    verdict = evaluate_expression("MIT OR GPL-3.0-only", rules)
    assert verdict.violates is False
    assert verdict.mentioned_licenses  # GPL visible as restricted alternative


def test_or_expression_all_restricted_violates():
    rules = RestrictionRules.compile(["GPL-3.0-only", "AGPL-3.0-only"])
    verdict = evaluate_expression("GPL-3.0-only OR AGPL-3.0-only", rules)
    assert verdict.violates is True
    assert {x["license"] for x in verdict.bad_licenses} == {
        "GPL-3.0-only",
        "AGPL-3.0-only",
    }


def test_and_expression_any_restricted_violates():
    rules = RestrictionRules.compile(["GPL-3.0-only"])
    verdict = evaluate_expression("MIT AND GPL-3.0-only", rules)
    assert verdict.violates is True
    assert verdict.bad_licenses[0]["license"] == "GPL-3.0-only"


def test_nested_expression_and_with():
    rules = RestrictionRules.compile(["GPL-2.0-only"])
    verdict = evaluate_expression(
        "(MIT OR Apache-2.0) AND (GPL-2.0-only WITH Classpath-exception-2.0)",
        rules,
    )
    assert verdict.violates is True
    assert verdict.bad_licenses[0]["exception"] == "Classpath-exception-2.0"


def test_malformed_expression_fallback_does_not_hide_bad_license():
    rules = RestrictionRules.compile(["GPL-3.0-only"])
    verdict = evaluate_expression("GPL-3.0-only OR OR", rules)
    assert verdict.parse_error is not None
    assert verdict.violates is True
