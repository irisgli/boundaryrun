from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .store import STORE, User

app = FastAPI(title="docvault")


class NewDocument(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(max_length=10_000)


def current_user(x_user_token: str | None = Header(default=None)) -> User:
    user = STORE.user_for_token(x_user_token) if x_user_token else None
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/documents")
def list_documents(user: User = Depends(current_user)) -> list[dict]:
    return [d.summary() for d in STORE.documents_for_tenant(user.tenant_id)]


@app.get("/documents/{doc_id}")
def get_document(doc_id: int, user: User = Depends(current_user)) -> dict:
    doc = STORE.get_document(doc_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="document not found")
    return doc.model_dump()


@app.post("/documents", status_code=201)
def create_document(body: NewDocument, user: User = Depends(current_user)) -> dict:
    doc = STORE.create_document(user.tenant_id, user.id, body.title, body.body)
    return doc.model_dump()
