from fastapi.testclient import TestClient

from api import main


def test_scan_persists_url_assessment_and_stats(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "api.db")
    client = TestClient(main.app)

    response = client.post(
        "/scan",
        json={"input_text": "http://192.0.2.1/verify-account", "input_type": "url"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] == 80
    assert result["label"] == "phishing"
    assert isinstance(result["reasons"], list)

    recent = client.get("/recent").json()
    assert len(recent) == 1
    assert recent[0]["input_text"] == "http://192.0.2.1/verify-account"
    assert recent[0]["reasons"] == result["reasons"]

    assert client.get("/stats").json() == {
        "total": 1,
        "phishing": 1,
        "suspicious": 0,
        "safe": 0,
    }


def test_message_assessment_and_cors_headers(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "api.db")
    client = TestClient(main.app)

    response = client.post(
        "/scan",
        json={
            "input_text": "Urgent! Verify your account immediately.",
            "input_type": "message",
        },
        headers={"Origin": "https://client.example"},
    )

    assert response.status_code == 200
    assert response.json()["label"] == "suspicious"
    assert response.headers["access-control-allow-origin"] == "*"


def test_scan_validates_input_type_and_blank_text() -> None:
    client = TestClient(main.app)

    invalid_type = client.post(
        "/scan", json={"input_text": "hi", "input_type": "email"}
    )
    blank_text = client.post(
        "/scan", json={"input_text": "  ", "input_type": "message"}
    )

    assert invalid_type.status_code == 422
    assert blank_text.status_code == 422


def test_recent_returns_at_most_ten(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "api.db")
    client = TestClient(main.app)

    for index in range(12):
        response = client.post(
            "/scan",
            json={"input_text": f"ordinary message {index}", "input_type": "message"},
        )
        assert response.status_code == 200

    rows = client.get("/recent").json()
    assert len(rows) == 10
    assert rows[0]["input_text"] == "ordinary message 11"
    assert rows[-1]["input_text"] == "ordinary message 2"


def test_static_frontend_folder_is_mounted() -> None:
    response = TestClient(main.app).get("/static/.gitkeep")

    assert response.status_code == 200
