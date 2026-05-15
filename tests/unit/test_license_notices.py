import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_current_yolo_notice_is_agpl_not_mit():
    third_party = (REPO_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")

    assert "Ultralytics YOLOv5" in third_party
    assert "AGPL-3.0" in third_party
    assert "YOLO | MIT" not in third_party


def test_release_compliance_payload_files_exist():
    required_files = [
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "MODEL_LICENSES.md",
        "DATA_LICENSES.md",
        "PROVIDER_TERMS.md",
        "SOURCE.txt",
        "SBOM.txt",
        "release-manifest.v1.json",
    ]

    for relative_path in required_files:
        assert (REPO_ROOT / relative_path).is_file()


def test_v1_rc1_user_docs_exist():
    required_docs = [
        "docs/v1-rc1-quick-start.md",
        "docs/v1-rc1-package-guide.md",
        "docs/towerscout-user-guide.md",
        "docs/project-overview.md",
        "docs/oci-quick-start.md",
        "docs/oci-runtime-contract.md",
        "docs/release-asset-bundle-contract.md",
    ]

    for relative_path in required_docs:
        assert (REPO_ROOT / relative_path).is_file()


def test_legacy_root_license_txt_is_quarantined():
    assert not (REPO_ROOT / "LICENSE.TXT").exists()
    assert (REPO_ROOT / "docs" / "legacy" / "LEGACY-LICENSE-NOTICE.md").is_file()


def test_package_metadata_points_to_composite_license_file():
    package_json = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    package_lock = json.loads(
        (REPO_ROOT / "package-lock.json").read_text(encoding="utf-8")
    )

    assert package_json["license"] == "SEE LICENSE IN LICENSE"
    assert package_lock["packages"][""]["license"] == "SEE LICENSE IN LICENSE"


def test_license_notice_route_is_visible_in_app_shell():
    template = (
        REPO_ROOT / "webapp" / "templates" / "towerscout.html"
    ).read_text(encoding="utf-8")

    assert 'href="/license"' in template
    assert "Source/licenses" in template
    assert template.count('href="/license"') == 1
    assert 'href="/docs/project-overview.md"' in template
    assert 'href="/docs/towerscout-user-guide.md"' in template
    assert 'href="https://www.youtube.com/@thaddeussegura8452/videos"' in template
    assert (
        'href="https://www.sciencedirect.com/science/article/pii/'
        'S2589750024000943?via%3Dihub"'
    ) in template
    assert "Documentation Placeholder" not in template
    assert "Video Guide Placeholder" not in template
