from signaldesk_web import Settings, create_app


def test_package_imports() -> None:
    assert Settings.model_fields["service_name"].default == "signaldesk-web"
    assert callable(create_app)
