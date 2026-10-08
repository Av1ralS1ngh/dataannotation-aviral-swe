from release_trust.config import Settings


def test_settings_read_service_endpoints(monkeypatch):
    monkeypatch.setenv("REGISTRY_URL", "http://registry.example")
    monkeypatch.setenv("METADATA_URL", "http://metadata.example")
    monkeypatch.setenv("LOG_LEVEL", "debug")

    settings = Settings.from_environment()
    assert settings.registry_url == "http://registry.example"
    assert settings.metadata_url == "http://metadata.example"
    assert settings.log_level == "DEBUG"
