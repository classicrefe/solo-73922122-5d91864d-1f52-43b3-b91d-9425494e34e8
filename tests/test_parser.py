import pytest

from app.cyclonedx import SBOMParseError, parse_sbom
from app.fixtures import cycle_sbom, version_conflict_sbom


def test_parse_version_conflict_fixture():
    parsed = parse_sbom(version_conflict_sbom())
    norm = parsed.normalized
    assert len(norm["components"]) == 5  # root + 4
    assert norm["roots"] == ["pkg:maven/com.acme/shop@2.4.0"]
    log_refs = [r for r in norm["components"] if r.endswith("logging-lib@1.4.2") or r.endswith("logging-lib@2.1.0")]
    assert len(log_refs) == 2


def test_parse_cycle_fixture_edges_preserved():
    norm = parse_sbom(cycle_sbom()).normalized
    root = norm["roots"][0]
    assert len(norm["edges"][root]) == 3
    # reverse edge creating the cycle is preserved
    vault = "pkg:npm/token-vault@2.2.0"
    auth = "pkg:npm/auth-gateway@4.0.0"
    assert norm["edges"][vault] == [auth]


def test_duplicate_bom_ref_conflicting_raises():
    doc = {
        "bomFormat": "CycloneDX",
        "metadata": {},
        "components": [
            {"bom-ref": "a", "name": "A", "version": "1", "licenses": []},
            {"bom-ref": "a", "name": "A-different", "version": "2"},
        ],
        "dependencies": [],
    }
    with pytest.raises(SBOMParseError):
        parse_sbom(doc)


def test_dangling_reference_becomes_stub_with_warning():
    doc = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"bom-ref": "root", "name": "r", "version": "1"}},
        "components": [
            {"bom-ref": "root", "name": "r", "version": "1"},
            {"bom-ref": "a", "name": "a", "version": "1"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["a", "ghost"]},
            {"ref": "a", "dependsOn": []},
        ],
    }
    norm = parse_sbom(doc).normalized
    assert "ghost" in norm["components"]
    assert norm["components"]["ghost"]["missing"] is True
    codes = {w["code"] for w in norm["warnings"]}
    assert "dangling_depends_on_ref" in codes


def test_parse_xml_smoke():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
      <metadata><component bom-ref="app@1" type="application">
        <name>app</name><version>1</version>
      </component></metadata>
      <components>
        <component bom-ref="lib@1" type="library">
          <name>lib</name><version>1</version>
          <licenses><license><id>GPL-3.0-only</id></license></licenses>
        </component>
      </components>
      <dependencies>
        <dependency ref="app@1"><dependency ref="lib@1"/></dependency>
        <dependency ref="lib@1"/>
      </dependencies>
    </bom>
    """
    norm = parse_sbom(xml).normalized
    assert norm["format"] == "CycloneDX-XML"
    assert norm["roots"] == ["app@1"]
    assert norm["edges"]["app@1"] == ["lib@1"]
    claim = norm["components"]["lib@1"]["licenses"][0]
    assert claim == {"kind": "id", "value": "GPL-3.0-only"}
