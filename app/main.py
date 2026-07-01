# RYAN-DAY1
"""FastAPI application + route registration for the Sentinel PEP.

Owner: Ryan (Infrastructure + Output Lead).
Gate: Day-1 noon — exposes the single ingress POST /v1/chat and GET /health.
The chat route delegates all behaviour to app.pep.ingress.handle_request; no
authorization or detection logic lives in this file — only request/response
shaping.
"""
from fastapi import FastAPI
from pydantic import BaseModel

from app.pep import ingress

app = FastAPI(title="Sentinel PEP", version="0.1.0")


class ChatRequest(BaseModel):
    prompt: str
    user_id: str


class ChatResponse(BaseModel):
    decision: str
    reason: str
    response: str | None


@app.get("/health")
def health() -> dict:
    """Liveness check for the Day-1 gate and ops."""
    return {"status": "ok"}


@app.post("/v1/chat", response_model=ChatResponse)
def chat(request: ChatRequest):
    """Single chat ingress: hand prompt + user_id to the PEP, return its verdict."""
    return ingress.handle_request(request.prompt, request.user_id)
