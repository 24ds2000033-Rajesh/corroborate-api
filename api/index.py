from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse


app = FastAPI()


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

        # Treat a timestamp without timezone information as invalid.
        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def is_valid_source(source: Any) -> bool:
    """
    A source is valid only when:
      id, origin, value, observedAt are strings
      type is one of the five allowed values.
    """
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
    """
    Fresh means:

        asOf - observedAt <= stalenessDays

    A future observedAt is not stale, because the difference is negative.
    """
    observed_at = parse_timestamp(source["observedAt"])

    if observed_at is None:
        # Invalid timestamp means the source cannot participate.
        return False

    age_seconds = (as_of - observed_at).total_seconds()
    allowed_seconds = staleness_days * 86400.0

    return age_seconds <= allowed_seconds


def invalid_response():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": [],
    }


def corroborate(body: Any) -> dict:
    # ------------------------------------------------------------
    # Rule 1: invalid input
    # ------------------------------------------------------------

    if not isinstance(body, dict):
        return invalid_response()

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return invalid_response()

    claim_value = claim.get("value")

    if not isinstance(claim_value, str):
        return invalid_response()

    as_of_raw = body.get("asOf")

    if as_of_raw is None:
        return invalid_response()

    as_of = parse_timestamp(as_of_raw)

    if as_of is None:
        return invalid_response()

    staleness_days = body.get("stalenessDays")

    # bool is technically a subclass of int in Python, but must
    # not be accepted as a number here.
    if isinstance(staleness_days, bool):
        return invalid_response()

    if not isinstance(staleness_days, (int, float)):
        return invalid_response()

    # NaN / infinity are not meaningful staleness windows.
    if not __import__("math").isfinite(float(staleness_days)):
        return invalid_response()

    sources = body.get("sources")

    if not isinstance(sources, list):
        return invalid_response()

    # ------------------------------------------------------------
    # Keep only structurally valid sources.
    # Invalid sources are ignored entirely.
    # ------------------------------------------------------------

    valid_sources = [
        source
        for source in sources
        if is_valid_source(source)
    ]

    # ------------------------------------------------------------
    # Rule 2: authoritative fresh contradiction
    #
    # This check happens BEFORE support.
    # ------------------------------------------------------------

    contradicting = []

    for source in valid_sources:
        if not source.get("authoritative", False):
            continue

        if not is_fresh(source, as_of, float(staleness_days)):
            continue

        if source["value"] != claim_value:
            contradicting.append(source["id"])

    if contradicting:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradicting),
        }

    # ------------------------------------------------------------
    # Rule 3:
    #
    # Keep only:
    #   - fresh
    #   - agreeing with claim
    #
    # Then one representative per origin.
    # Representative = lexicographically smallest id.
    # ------------------------------------------------------------

    agreeing_fresh = []

    for source in valid_sources:
        if not is_fresh(source, as_of, float(staleness_days)):
            continue

        if source["value"] != claim_value:
            continue

        agreeing_fresh.append(source)

    representatives_by_origin = {}

    for source in agreeing_fresh:
        origin = source["origin"]

        current = representatives_by_origin.get(origin)

        if current is None or source["id"] < current["id"]:
            representatives_by_origin[origin] = source

    representatives = list(representatives_by_origin.values())

    if len(representatives) >= 2:
        representative_ids = sorted(
            source["id"] for source in representatives
        )

        distinct_types = {
            source["type"] for source in representatives
        }

        if len(distinct_types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": representative_ids,
        }

    # ------------------------------------------------------------
    # Rule 4: everything else is unverified.
    # ------------------------------------------------------------

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }


@app.post("/corroborate")
async def corroborate_endpoint(body: Any):
    result = corroborate(body)

    # Explicitly return only the required response object.
    return JSONResponse(content=result)
