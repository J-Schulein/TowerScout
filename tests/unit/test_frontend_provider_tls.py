from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP_WIZARD = REPO_ROOT / "webapp" / "js" / "src" / "setup-wizard.js"
SETTINGS = REPO_ROOT / "webapp" / "js" / "src" / "settings.js"


def test_setup_and_settings_preserve_provider_tls_error_details():
    for path in (SETUP_WIZARD, SETTINGS):
        source = path.read_text(encoding="utf-8")

        assert "error.payload = data" in source
        assert "payload.validation_results || {}" in source
        assert "payload.support_action || details.support_action" in source
        assert "details.repair_command" in source
        assert "Category:" in source

    setup_source = SETUP_WIZARD.read_text(encoding="utf-8")
    assert "helper_available" in setup_source
    assert "getProviderValidationState" in setup_source
    assert "shouldShowProviderTlsRepair" in setup_source
    assert "getProviderTlsRepairViewModel" in setup_source
    assert "PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED = false" in setup_source
    assert "operation_authorization" in setup_source
    assert "TLS_REPAIR_CATEGORIES" in setup_source
