from datetime import datetime, timezone
from math import isfinite
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()


VALID_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def invalid_result():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": [],
    }


def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    try:
        text = value.strip()

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        # A timestamp without timezone is not accepted.
        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def valid_source(source: Any) -> bool:
    if not isinstance(source, dict):
        return False

    if not isinstance(source.get("id"), str):
        return False

    if not isinstance(source.get("origin"), str):
        return False

    if not isinstance(source.get("value"), str):
        return False

    if not isinstance(source.get("observedAt"), str):
        return False

    if source.get("type") not in VALID_TYPES:
        return False

    return True


def fresh(source: dict, as_of: datetime, staleness_days: float) -> bool:
    observed_at = parse_timestamp(source.get("observedAt"))

    if observed_at is None:
        return False

    age_seconds = (as_of - observed_at).total_seconds()
    allowed_seconds = staleness_days * 86400.0

    return age_seconds <= allowed_seconds


def process(body: Any):
    # ============================================================
    # RULE 1 — INVALID
    # ============================================================

    if not isinstance(body, dict):
        return invalid_result()

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return invalid_result()

    claim_value = claim.get("value")

    if not isinstance(claim_value, str):
        return invalid_result()

    if "asOf" not in body:
        return invalid_result()

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return invalid_result()

    staleness_days = body.get("stalenessDays")

    # bool is not accepted as a number.
    if isinstance(staleness_days, bool):
        return invalid_result()

    if not isinstance(staleness_days, (int, float)):
        return invalid_result()

    if not isfinite(float(staleness_days)):
        return invalid_result()

    sources = body.get("sources")

    if not isinstance(sources, list):
        return invalid_result()

    # ============================================================
    # VALID SOURCES ONLY
    # ============================================================

    valid_sources = [
        source
        for source in sources
        if valid_source(source)
    ]

    # ============================================================
    # RULE 2 — CONTRADICTED
    #
    # Fresh authoritative disagreement has priority over support.
    # ============================================================

    contradictions = []

    for source in valid_sources:
        if source.get("authoritative") is not True:
            continue

        if not fresh(
            source,
            as_of,
            float(staleness_days),
        ):
            continue

        if source["value"] != claim_value:
            contradictions.append(source["id"])

    if contradictions:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradictions),
        }

    # ============================================================
    # RULE 3 — SUPPORTED
    #
    # Only fresh sources agreeing with the claim.
    # One representative per origin.
    # Representative = lexicographically smallest ID.
    # ============================================================

    representatives = {}

    for source in valid_sources:
        if not fresh(
            source,
            as_of,
            float(staleness_days),
        ):
            continue

        if source["value"] != claim_value:
            continue

        origin = source["origin"]

        existing = representatives.get(origin)

        if existing is None or source["id"] < existing["id"]:
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:
        ids = sorted(source["id"] for source in reps)

        types = {source["type"] for source in reps}

        confidence = "high" if len(types) >= 2 else "medium"

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": ids,
        }

    # ============================================================
    # RULE 4 — UNVERIFIED
    # ============================================================

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }


@app.post("/corroborate")
async def corroborate(body: Any):
    return JSONResponse(content=process(body))


# Vercel normally routes api/index.py through /api/*.
# This second route makes the same application available if
# Vercel forwards the rewritten path as /api/corroborate.
@app.post("/api/corroborate")
async def corroborate_api(body: Any):
    return JSONResponse(content=process(body))
