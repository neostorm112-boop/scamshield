from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    return TestClient(create_app(background=False))


def test_cross_site_post_is_rejected(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post(
            "/check", data={"url": "rta.ae"}, headers={"Origin": "https://evil.example"}, follow_redirects=False
        )
        assert r.status_code == 403


def test_local_origin_and_no_origin_post_pass(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post(
            "/check", data={"url": "rta.ae"}, headers={"Origin": "http://127.0.0.1:8000"}, follow_redirects=False
        )
        assert r.status_code != 403
        r = client.post("/check", data={"url": "rta.ae"}, follow_redirects=False)
        assert r.status_code != 403


def test_foreign_host_header_is_rejected(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_fqdn_is_escaped_before_wbr():
    from scamshield.app import templates

    out = templates.env.overlay(autoescape=True).from_string("{{ f|wbr_dots }}").render(f="a<script>x</script>.com")
    assert "&lt;script&gt;" in out and "<script>" not in out and "<wbr>" in out


def test_unknown_domain_facts_is_404(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.get("/d/nonexistent.example/partials/facts").status_code == 404
