"""In-memory data store for docvault.

All users, tenants, tokens and documents here are synthetic fixtures.
"""

from __future__ import annotations

import threading

from pydantic import BaseModel


class User(BaseModel):
    id: int
    name: str
    tenant_id: int


class Document(BaseModel):
    id: int
    tenant_id: int
    owner_id: int
    title: str
    body: str

    def summary(self) -> dict:
        return {"id": self.id, "title": self.title, "owner_id": self.owner_id}


# Synthetic bearer tokens. These are test fixtures, not credentials.
_SEED_USERS = {
    "tok-alice-acme": User(id=1, name="alice", tenant_id=1),
    "tok-carol-acme": User(id=3, name="carol", tenant_id=1),
    "tok-bob-globex": User(id=2, name="bob", tenant_id=2),
}

_SEED_DOCUMENTS = [
    Document(id=1, tenant_id=1, owner_id=1, title="acme-q3-roadmap", body="ACME-INTERNAL roadmap draft"),
    Document(id=2, tenant_id=1, owner_id=3, title="acme-payroll-notes", body="ACME-INTERNAL payroll notes"),
    Document(id=3, tenant_id=2, owner_id=2, title="globex-board-minutes", body="GLOBEX-INTERNAL board minutes"),
]


class Store:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users = dict(_SEED_USERS)
        self._documents = {d.id: d for d in _SEED_DOCUMENTS}
        self._next_id = max(self._documents) + 1

    def user_for_token(self, token: str) -> User | None:
        return self._users.get(token)

    def get_document(self, doc_id: int) -> Document | None:
        return self._documents.get(doc_id)

    def documents_for_tenant(self, tenant_id: int) -> list[Document]:
        return [d for d in self._documents.values() if d.tenant_id == tenant_id]

    def create_document(self, tenant_id: int, owner_id: int, title: str, body: str) -> Document:
        with self._lock:
            doc = Document(id=self._next_id, tenant_id=tenant_id, owner_id=owner_id, title=title, body=body)
            self._documents[doc.id] = doc
            self._next_id += 1
            return doc


STORE = Store()
