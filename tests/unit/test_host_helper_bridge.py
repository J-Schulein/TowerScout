import pytest

import ts_host_helper


SESSION_ENV = {
    "TOWERSCOUT_HOST_HELPER_ENABLED": "1",
    "TOWERSCOUT_HOST_HELPER_PORT": "50123",
    "TOWERSCOUT_HOST_HELPER_SESSION_ID": "a" * 32,
    "TOWERSCOUT_HOST_HELPER_SESSION_KEY": "A" * 43,
}


def test_host_helper_bridge_requires_complete_explicit_configuration():
    assert ts_host_helper.load_host_helper_bridge_config({}) is None
    assert ts_host_helper.load_host_helper_bridge_config(
        {
            **SESSION_ENV,
            "TOWERSCOUT_HOST_HELPER_ENABLED": "0",
        }
    ) is None
    assert ts_host_helper.load_host_helper_bridge_config(
        {
            **SESSION_ENV,
            "TOWERSCOUT_HOST_HELPER_PORT": "0",
        }
    ) is None
    assert ts_host_helper.load_host_helper_bridge_config(
        {
            **SESSION_ENV,
            "TOWERSCOUT_HOST_HELPER_SESSION_KEY": "short",
        }
    ) is None


def test_repairable_provider_bridge_issues_scoped_short_lived_authorization():
    bridge = ts_host_helper.build_provider_tls_repair_bridge(
        "google",
        "tls_ca_untrusted",
        environment=SESSION_ENV,
        now=1_800_000_000,
    )

    assert bridge["base_url"] == "http://127.0.0.1:50123"
    assert bridge["probe"]["path"] == "/health"
    assert bridge["probe"]["scope"] == "helper_probe"
    assert bridge["provider_tls_repair_capability"] is False
    operation = bridge["operation_authorization"]
    assert operation["operation_type"] == "provider_tls_repair"
    assert operation["operation_token"].startswith("v1.")
    assert "helper_token" not in str(bridge).lower()
    assert "durable" not in str(bridge).lower()

    config = ts_host_helper.load_host_helper_bridge_config(SESSION_ENV)
    payload = ts_host_helper.validate_browser_authorization(
        config,
        operation["operation_token"],
        expected_scope="provider_tls_repair",
        expected_provider="google",
        now=1_800_000_001,
    )
    assert payload["session_id"] == "a" * 32
    assert payload["operation_id"] == ""


def test_bridge_is_not_issued_for_non_repairable_failures():
    assert ts_host_helper.build_provider_tls_repair_bridge(
        "google",
        "invalid_provider_key",
        environment=SESSION_ENV,
    ) is None
    assert ts_host_helper.build_provider_tls_repair_bridge(
        "",
        "tls_ca_untrusted",
        environment=SESSION_ENV,
    ) is None


def test_expired_and_cross_provider_authorizations_are_rejected():
    bridge = ts_host_helper.build_provider_tls_repair_bridge(
        "azure",
        "tls_bundle_missing",
        environment=SESSION_ENV,
        now=1_800_000_000,
    )
    config = ts_host_helper.load_host_helper_bridge_config(SESSION_ENV)
    token = bridge["operation_authorization"]["operation_token"]

    with pytest.raises(ValueError, match="authorization_provider"):
        ts_host_helper.validate_browser_authorization(
            config,
            token,
            expected_scope="provider_tls_repair",
            expected_provider="google",
            now=1_800_000_001,
        )
    with pytest.raises(ValueError, match="authorization_expired"):
        ts_host_helper.validate_browser_authorization(
            config,
            token,
            expected_scope="provider_tls_repair",
            expected_provider="azure",
            now=1_800_000_121,
        )


def test_status_authorization_is_bound_to_provider_and_operation():
    operation_id = "b" * 32
    bridge = ts_host_helper.build_operation_status_bridge(
        "google",
        operation_id,
        environment=SESSION_ENV,
        now=1_800_000_000,
    )
    config = ts_host_helper.load_host_helper_bridge_config(SESSION_ENV)
    token = bridge["status_authorization"]["authorization"]

    payload = ts_host_helper.validate_browser_authorization(
        config,
        token,
        expected_scope="operation_status",
        expected_provider="google",
        expected_operation_id=operation_id,
        now=1_800_000_001,
    )
    assert payload["operation_id"] == operation_id
    with pytest.raises(ValueError, match="authorization_operation"):
        ts_host_helper.validate_browser_authorization(
            config,
            token,
            expected_scope="operation_status",
            expected_provider="google",
            expected_operation_id="c" * 32,
            now=1_800_000_001,
        )


def test_payload_enrichment_keeps_availability_probe_driven_and_manual_fallback():
    payload = {
        "message": "TLS validation failed.",
        "details": {
            "provider": "azure",
            "category": "tls_ca_untrusted",
            "repairable": True,
            "helper_available": False,
            "repair_command": (
                ".\\scripts\\repair-provider-tls.cmd "
                "-Provider azure -Engine docker -Gpu off"
            ),
        },
    }

    enriched = ts_host_helper.enrich_provider_tls_repair_payload(
        payload,
        environment=SESSION_ENV,
        now=1_800_000_000,
    )

    assert enriched["helper_available"] is False
    assert enriched["details"]["helper_available"] is False
    assert enriched["details"]["repair_command"] == payload["details"]["repair_command"]
    assert enriched["details"]["helper_bridge"]["base_url"] == "http://127.0.0.1:50123"


def test_payload_enrichment_preserves_unrelated_network_errors():
    payload = {
        "message": "Tile request failed.",
        "details": {
            "category": "provider_network_blocked",
            "provider": "google",
        },
    }

    enriched = ts_host_helper.enrich_provider_tls_repair_payload(
        payload,
        environment=SESSION_ENV,
        now=1_800_000_000,
    )

    assert enriched == payload
