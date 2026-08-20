from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

ASSIGNED_SUBJECT = "qt7otj.example"

VALID_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def parse_timestamp(value: Any):
    """
    Parse an ISO-8601 timestamp.

    Returns a timezone-aware datetime or None.
    """
    if not isinstance(value, str):
        return None

    try:
        text = value.strip()

        # Support timestamps ending in Z.
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        # Treat an explicitly timezone-less timestamp as invalid.
        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def invalid_response():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": [],
    }


def is_valid_source(source: Any) -> bool:
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


def is_fresh(source: dict, as_of: datetime, staleness_days: float) -> bool:
    observed = parse_timestamp(source["observedAt"])

    if observed is None:
        return False

    age_seconds = (as_of - observed).total_seconds()

    # Future observations are not stale.
    # Freshness is defined directly by:
    #     asOf - observedAt <= stalenessDays
    #
    # A future observedAt therefore satisfies the stated inequality.
    return age_seconds <= staleness_days * 86400


def corroborate(body: Any):
    # ------------------------------------------------------------
    # Rule 1: invalid / low / []
    # ------------------------------------------------------------

    if not isinstance(body, dict):
        return invalid_response()

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return invalid_response()

    if not isinstance(claim.get("value"), str):
        return invalid_response()

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return invalid_response()

    staleness_days = body.get("stalenessDays")

    # bool is a subclass of int in Python, but it is not a number
    # for this API's purposes.
    if (
        isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
    ):
        return invalid_response()

    sources = body.get("sources")

    if not isinstance(sources, list):
        return invalid_response()

    claim_value = claim["value"]

    # ------------------------------------------------------------
    # Keep only valid sources.
    # Invalid sources are ignored entirely.
    # ------------------------------------------------------------

    valid_sources = [
        source
        for source in sources
        if is_valid_source(source)
    ]

    # ------------------------------------------------------------
    # Rule 2: authoritative fresh disagreement
    #
    # This is evaluated BEFORE support.
    # ------------------------------------------------------------

    contradicting = []

    for source in valid_sources:
        if not is_fresh(source, as_of, staleness_days):
            continue

        if source.get("authoritative") is True:
            if source["value"] != claim_value:
                contradicting.append(source)

    if contradicting:
        ids = sorted(source["id"] for source in contradicting)

        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": ids,
        }

    # ------------------------------------------------------------
    # Rule 3: supported
    #
    # Only fresh sources whose value equals the claim count.
    # Then reduce to one representative per origin.
    # Representative = lexicographically smallest id.
    # ------------------------------------------------------------

    matching_fresh = []

    for source in valid_sources:
        if not is_fresh(source, as_of, staleness_days):
            continue

        if source["value"] == claim_value:
            matching_fresh.append(source)

    representatives_by_origin = {}

    for source in matching_fresh:
        origin = source["origin"]

        existing = representatives_by_origin.get(origin)

        if existing is None or source["id"] < existing["id"]:
            representatives_by_origin[origin] = source

    representatives = list(representatives_by_origin.values())

    if len(representatives) >= 2:
        representative_ids = sorted(
            source["id"] for source in representatives
        )

        distinct_types = {
            source["type"]
            for source in representatives
        }

        confidence = (
            "high"
            if len(distinct_types) >= 2
            else "medium"
        )

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": representative_ids,
        }

    # ------------------------------------------------------------
    # Rule 4: unverified
    # ------------------------------------------------------------

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }


@app.post("/corroborate")
async def corroborate_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            content=invalid_response(),
            status_code=200,
        )

    result = corroborate(body)

    return JSONResponse(
        content=result,
        status_code=200,
    )
