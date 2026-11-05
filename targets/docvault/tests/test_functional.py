from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ALICE = {"X-User-Token": "tok-alice-acme"}
CAROL = {"X-User-Token": "tok-carol-acme"}
BOB = {"X-User-Token": "tok-bob-globex"}


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_requires_authentication():
    assert client.get("/documents").status_code == 401
    assert client.get("/documents/1").status_code == 401
    assert client.get("/documents/1", headers={"X-User-Token": "bogus"}).status_code == 401


def test_list_is_tenant_scoped():
    ids = {d["id"] for d in client.get("/documents", headers=ALICE).json()}
    assert {1, 2} <= ids
    assert 3 not in ids
    assert {d["id"] for d in client.get("/documents", headers=BOB).json()} >= {3}


def test_owner_can_read_own_document():
    r = client.get("/documents/1", headers=ALICE)
    assert r.status_code == 200
    assert r.json()["title"] == "acme-q3-roadmap"


def test_same_tenant_colleague_can_read_document():
    r = client.get("/documents/1", headers=CAROL)
    assert r.status_code == 200
    assert r.json()["id"] == 1


def test_missing_document_is_404():
    assert client.get("/documents/9999", headers=ALICE).status_code == 404


def test_create_then_read():
    r = client.post("/documents", headers=BOB, json={"title": "t", "body": "b"})
    assert r.status_code == 201
    new_id = r.json()["id"]
    got = client.get(f"/documents/{new_id}", headers=BOB)
    assert got.status_code == 200
    assert got.json()["body"] == "b"
