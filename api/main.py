"""FastAPI application for CyberShield scan assessments."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api import database
from src.features import extract_url_features

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
FRONTEND_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = database.DB_PATH

app = FastAPI(title="CyberShield API", description="Phishing and scam scan API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_MESSAGE_INDICATORS = (
    (re.compile(r"\b(?:urgent|immediately|act now|within \d+ hours?)\b", re.I), 20,
     "Urgent or high-pressure language"),
    (re.compile(r"\b(?:password|login|sign in|verify|confirm|account)\b", re.I), 20,
     "Requests account or credential-related action"),
    (re.compile(r"\b(?:payment|wire transfer|bank details|gift card|crypto)\b", re.I), 25,
     "Requests payment or financial information"),
    (re.compile(r"\b(?:prize|winner|claim your|free gift)\b", re.I), 15,
     "Uses a prize or unsolicited reward claim"),
)


class ScanRequest(BaseModel):
    input_text: str = Field(min_length=1)
    input_type: Literal["url", "message"]


class ScanResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    label: Literal["safe", "suspicious", "phishing"]
    reasons: list[str]


class StatsResponse(BaseModel):
    total: int
    phishing: int
    suspicious: int
    safe: int


class RecentScanResponse(BaseModel):
    id: int
    input_text: str
    input_type: Literal["url", "message"]
    risk_score: float
    label: Literal["safe", "suspicious", "phishing"]
    reasons: list[str]
    created_at: str


def _url_assessment(url: str) -> tuple[int, list[str]]:
    features = extract_url_features(url)
    score = 0
    reasons: list[str] = []

    if features["is_ip_address"]:
        score += 45
        reasons.append("URL uses an IP address instead of a domain name")
    if features["at_symbol"]:
        score += 40
        reasons.append("URL contains an @ symbol that may disguise its destination")
    if not features["uses_https"]:
        score += 15
        reasons.append("URL does not use HTTPS")
    keyword_count = int(features["suspicious_keywords"])
    if keyword_count:
        score += min(keyword_count * 10, 30)
        reasons.append("URL contains suspicious security or account-related keywords")
    if features["length"] > 75:
        score += 10
        reasons.append("URL is unusually long")
    if features["subdomains"] >= 3:
        score += 10
        reasons.append("URL contains several subdomain levels")

    if not reasons:
        reasons.append("No obvious URL risk indicators were detected")
    return min(score, 100), reasons


def _message_assessment(message: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    for pattern, points, reason in _MESSAGE_INDICATORS:
        if pattern.search(message):
            score += points
            reasons.append(reason)

    urls = _URL_PATTERN.findall(message)
    for url in urls:
        url_score, url_reasons = _url_assessment(url.rstrip(".,);!?"))
        if url_score:
            score += min(url_score, 35)
            reasons.extend(f"Embedded link: {reason.lower()}" for reason in url_reasons)

    if not reasons:
        reasons.append("No obvious scam indicators were detected")
    return min(score, 100), reasons


def _label_for_score(risk_score: int) -> Literal["safe", "suspicious", "phishing"]:
    if risk_score >= 70:
        return "phishing"
    if risk_score >= 35:
        return "suspicious"
    return "safe"


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    """Assess submitted content using transparent starter heuristics."""
    input_text = request.input_text.strip()
    if not input_text:
        raise HTTPException(status_code=422, detail="input_text must not be blank")

    try:
        if request.input_type == "url":
            risk_score, reasons = _url_assessment(input_text)
        else:
            risk_score, reasons = _message_assessment(input_text)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    label = _label_for_score(risk_score)
    database.save_scan(
        input_text=input_text,
        input_type=request.input_type,
        risk_score=risk_score,
        label=label,
        reasons=json.dumps(reasons),
        db_path=DB_PATH,
    )
    return ScanResponse(risk_score=risk_score, label=label, reasons=reasons)


@app.get("/stats", response_model=StatsResponse)
def stats() -> StatsResponse:
    counts = database.get_stats(db_path=DB_PATH)
    return StatsResponse(
        total=counts["total_scans"],
        phishing=counts["phishing_count"],
        suspicious=counts["suspicious_count"],
        safe=counts["safe_count"],
    )


@app.get("/recent", response_model=list[RecentScanResponse])
def recent() -> list[RecentScanResponse]:
    """Return the ten latest saved scans."""
    rows = database.get_recent_scans(limit=10, db_path=DB_PATH)
    return [
        RecentScanResponse(
            **{**row, "reasons": json.loads(row["reasons"])}
        )
        for row in rows
    ]
