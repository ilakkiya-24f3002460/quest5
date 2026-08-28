import hashlib
import json
import math
import re
from copy import deepcopy

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()


# ============================================================
# STATE
# ============================================================

freezes = {}


# ============================================================
# CONSTANTS
# ============================================================

FREEZE_CODES = {
    "INVALID_INPUT",
    "UNALLOWED_UNSUPPORTED_REASON",
    "NOT_LOADABLE",
    "CALIBRATION_MISMATCH",
    "TOKENIZER_MISMATCH",
}

SELECT_CODES = {
    "NOT_FROZEN",
    "INVALID_LINEAGE",
    "INVALID_POLICY",
    "INVALID_PREDICTIONS",
    "INVALID_MANIFEST",
    "AGGREGATE_FLOOR",
    "SIZE_LIMIT",
    "LATENCY_LIMIT",
}


# ============================================================
# HELPERS
# ============================================================

def compact(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_text(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def sha256_json(obj):
    return sha256_text(compact(obj))


def utf8_key(value):
    return value.encode("utf-8")


def sort_unique_codes(codes):
    return sorted(
        set(codes),
        key=utf8_key,
    )


def is_nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def is_safe_int(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= 9007199254740991
    )


def is_finite_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def is_finite_nonnegative(x):
    return (
        is_finite_number(x)
        and float(x) >= 0
    )


def is_finite_unit(x):
    return (
        is_finite_number(x)
        and 0 <= float(x) <= 1
    )


def valid_binary(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and x in (0, 1)
    )


def canonicalize_json(obj):
    return compact(obj)


def exact_equal(a, b):
    return canonicalize_json(a) == canonicalize_json(b)


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(files):
    """
    Returns:
        valid, inventory, total_bytes, package_digest
    """

    if not isinstance(files, dict) or len(files) == 0:
        return False, [], None, None

    names = list(files.keys())

    # JSON object keys must be strings.
    if any(not isinstance(name, str) for name in names):
        return False, [], None, None

    # Values must be strings.
    if any(not isinstance(files[name], str) for name in names):
        return False, [], None, None

    # JSON objects cannot contain duplicate keys after parsing,
    # so uniqueness is naturally enforced here.

    names.sort(key=utf8_key)

    inventory = []

    total = 0

    for name in names:

        content = files[name]

        encoded = content.encode("utf-8")

        byte_count = len(encoded)

        digest = hashlib.sha256(
            encoded
        ).hexdigest()

        inventory.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest,
        })

        total += byte_count

    package_digest = sha256_json(
        inventory
    )

    return (
        True,
        inventory,
        total,
        package_digest,
    )


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def process_freeze_candidate(
    candidate,
    calibration_digest,
    tokenizer_digest,
    allowed_reasons,
):
    codes = []

    # Basic candidate validation
    if not isinstance(candidate, dict):
        return {
            "name": "",
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"],
        }

    name = candidate.get("name")

    if not is_nonempty_string(name):
        codes.append("INVALID_INPUT")
        name = ""

    files = candidate.get("files")

    files_valid, inventory, total_bytes, package_digest = (
        build_inventory(files)
    )

    if not files_valid:
        codes.append("INVALID_INPUT")
        inventory = []
        total_bytes = None
        package_digest = None

    loadable = candidate.get("loadable")

    if not isinstance(loadable, bool):
        codes.append("INVALID_INPUT")
        loadable_valid = False
    else:
        loadable_valid = True

    cand_calibration = candidate.get(
        "calibrationDigest"
    )

    cand_tokenizer = candidate.get(
        "tokenizerDigest"
    )

    if not is_nonempty_string(cand_calibration):
        codes.append("INVALID_INPUT")

    if not is_nonempty_string(cand_tokenizer):
        codes.append("INVALID_INPUT")

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    # A missing reason is different from a supplied reason.
    has_unsupported_reason = (
        isinstance(unsupported_reason, str)
        and len(unsupported_reason) > 0
    )

    if unsupported_reason is not None and not has_unsupported_reason:
        codes.append("INVALID_INPUT")

    # --------------------------------------------------------
    # Unsupported candidate
    # --------------------------------------------------------

    if has_unsupported_reason:

        if unsupported_reason not in allowed_reasons:
            codes.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

        if codes:
            status = "invalid"
        else:
            status = "unsupported"

    else:

        # ----------------------------------------------------
        # Normal frozen candidate
        # ----------------------------------------------------

        if loadable_valid and not loadable:
            codes.append("NOT_LOADABLE")

        if (
            is_nonempty_string(cand_calibration)
            and cand_calibration != calibration_digest
        ):
            codes.append(
                "CALIBRATION_MISMATCH"
            )

        if (
            is_nonempty_string(cand_tokenizer)
            and cand_tokenizer != tokenizer_digest
        ):
            codes.append(
                "TOKENIZER_MISMATCH"
            )

        if codes:
            status = "invalid"
        else:
            status = "frozen"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sort_unique_codes(codes),
    }


# ============================================================
# FREEZE
# ============================================================

def handle_freeze(data):

    # --------------------------------------------------------
    # Top-level validation
    # --------------------------------------------------------

    if not isinstance(data, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    freeze_id = data.get("freezeId")

    calibration_digest = data.get(
        "calibrationDigest"
    )

    tokenizer_digest = data.get(
        "tokenizerDigest"
    )

    allowed_reasons = data.get(
        "allowedUnsupportedReasons"
    )

    candidates = data.get(
        "candidates"
    )

    if (
        not is_nonempty_string(freeze_id)
        or len(freeze_id) > 128
        or not is_nonempty_string(calibration_digest)
        or not is_nonempty_string(tokenizer_digest)
        or not isinstance(allowed_reasons, list)
        or not isinstance(candidates, list)
        or len(candidates) == 0
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    # --------------------------------------------------------
    # Allowed reasons must be unique non-empty strings
    # --------------------------------------------------------

    if any(
        not is_nonempty_string(x)
        for x in allowed_reasons
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    if len(set(allowed_reasons)) != len(
        allowed_reasons
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    # --------------------------------------------------------
    # Candidate names must be unique
    # --------------------------------------------------------

    candidate_names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        name = candidate.get("name")

        if not is_nonempty_string(name):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        candidate_names.append(name)

    if len(set(candidate_names)) != len(
        candidate_names
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    # --------------------------------------------------------
    # Process
    # --------------------------------------------------------

    processed = []

    for candidate in candidates:

        processed.append(
            process_freeze_candidate(
                candidate,
                calibration_digest,
                tokenizer_digest,
                set(allowed_reasons),
            )
        )

    processed.sort(
        key=lambda x: utf8_key(x["name"])
    )

    response = {
        "freezeId": freeze_id,
        "candidates": processed,
    }

    # --------------------------------------------------------
    # State / idempotency
    # --------------------------------------------------------

    canonical_input = compact(data)

    if freeze_id in freezes:

        old = freezes[freeze_id]

        if old["input"] == canonical_input:
            return JSONResponse(
                old["response"]
            )

        return JSONResponse(
            {"error": "FREEZE_ID_CONFLICT"},
            status_code=409,
        )

    freezes[freeze_id] = {
        "input": canonical_input,
        "response": deepcopy(response),
    }

    return JSONResponse(response)


# ============================================================
# RECOMPUTE MANIFEST
# ============================================================

def validate_manifest(candidate):
    """
    Recompute inventory/package digest from the
    submitted candidate manifest.

    The select request contains the frozen response,
    not the original file contents, so integrity is
    checked against the recorded frozen manifest.
    """

    if not isinstance(candidate, dict):
        return False

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False

    previous_names = []

    recomputed_total = 0

    clean_inventory = []

    for item in inventory:

        if not isinstance(item, dict):
            return False

        # Exact expected keys.
        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return False

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if not is_nonempty_string(name):
            return False

        if not is_safe_int(size):
            return False

        if not isinstance(digest, str):
            return False

        if not re.fullmatch(
            r"[0-9a-f]{64}",
            digest,
        ):
            return False

        previous_names.append(name)

        recomputed_total += size

        clean_inventory.append({
            "name": name,
            "bytes": size,
            "sha256": digest,
        })

    if len(set(previous_names)) != len(
        previous_names
    ):
        return False

    if previous_names != sorted(
        previous_names,
        key=utf8_key,
    ):
        return False

    recorded_total = candidate.get(
        "totalBytes"
    )

    recorded_digest = candidate.get(
        "packageDigest"
    )

    if not is_safe_int(recorded_total):
        return False

    if not isinstance(recorded_digest, str):
        return False

    if not re.fullmatch(
        r"[0-9a-f]{64}",
        recorded_digest,
    ):
        return False

    if recomputed_total != recorded_total:
        return False

    recomputed_digest = sha256_json(
        clean_inventory
    )

    if recomputed_digest != recorded_digest:
        return False

    return True


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    required = [
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    ]

    if any(
        key not in policy
        for key in required
    ):
        return False

    if not is_safe_int(
        policy["maxBytes"]
    ):
        return False

    if not is_finite_unit(
        policy["aggregateFloor"]
    ):
        return False

    if not isinstance(
        policy["requiredSlices"],
        dict,
    ):
        return False

    for name, floor in policy[
        "requiredSlices"
    ].items():

        if not is_nonempty_string(name):
            return False

        if not is_finite_unit(floor):
            return False

    if not is_finite_nonnegative(
        policy["maxLatencyMs"]
    ):
        return False

    order = policy["candidateOrder"]

    if not isinstance(order, list):
        return False

    if any(
        not is_nonempty_string(x)
        for x in order
    ):
        return False

    if len(set(order)) != len(order):
        return False

    return True


# ============================================================
# SELECT CANDIDATE
# ============================================================

def handle_select(data):

    if not isinstance(data, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    freeze_id = data.get("freezeId")
    submitted_candidates = data.get(
        "candidates"
    )
    policy = data.get("policy")
    latencies = data.get("latencies")
    rows = data.get("rows")

    # Basic contract validation
    if (
        not is_nonempty_string(freeze_id)
        or not isinstance(
            submitted_candidates,
            list,
        )
        or len(submitted_candidates) == 0
        or not isinstance(policy, dict)
        or not isinstance(latencies, dict)
        or not isinstance(rows, list)
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    # --------------------------------------------------------
    # Must have frozen state
    # --------------------------------------------------------

    if freeze_id not in freezes:

        return JSONResponse({
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        })

    stored_response = freezes[
        freeze_id
    ]["response"]

    stored_candidates = stored_response[
        "candidates"
    ]

    # --------------------------------------------------------
    # Submitted candidate array must exactly equal frozen
    # --------------------------------------------------------

    if not exact_equal(
        submitted_candidates,
        stored_candidates,
    ):
        return JSONResponse(
            {"error": "INVALID_LINEAGE"},
            status_code=409,
        )

    # --------------------------------------------------------
    # Validate policy
    # --------------------------------------------------------

    policy_valid = validate_policy(
        policy
    )

    candidate_names = [
        c["name"]
        for c in stored_candidates
    ]

    candidate_name_set = set(
        candidate_names
    )

    order = policy.get(
        "candidateOrder"
    )

    order_valid = (
        isinstance(order, list)
        and len(order) == len(candidate_names)
        and set(order) == candidate_name_set
        and len(set(order)) == len(order)
    )

    if not policy_valid or not order_valid:

        results = []

        for candidate in stored_candidates:

            results.append({
                "name": candidate["name"],
                "aggregate": None,
                "slices": {
                    name: None
                    for name in (
                        policy.get(
                            "requiredSlices",
                            {}
                        )
                        if isinstance(policy, dict)
                        else {}
                    )
                },
                "totalBytes": (
                    candidate.get("totalBytes")
                    if validate_manifest(candidate)
                    else None
                ),
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ],
            })

        return JSONResponse({
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        })

    # --------------------------------------------------------
    # Validate rows
    # --------------------------------------------------------

    rows_valid = True

    for row in rows:

        if not isinstance(row, dict):
            rows_valid = False
            break

        if set(row.keys()) != {
            "label",
            "slice",
            "predictions",
        }:
            rows_valid = False
            break

        if not valid_binary(
            row["label"]
        ):
            rows_valid = False
            break

        if not is_nonempty_string(
            row["slice"]
        ):
            rows_valid = False
            break

        if not isinstance(
            row["predictions"],
            dict,
        ):
            rows_valid = False
            break

    # --------------------------------------------------------
    # Validate latency map
    # --------------------------------------------------------

    latency_valid = True

    for name in candidate_names:

        if (
            name not in latencies
            or not is_finite_nonnegative(
                latencies[name]
            )
        ):
            latency_valid = False

    # --------------------------------------------------------
    # Calculate each candidate
    # --------------------------------------------------------

    results = []

    candidate_order_index = {
        name: i
        for i, name in enumerate(order)
    }

    for candidate in stored_candidates:

        name = candidate["name"]

        codes = []

        # -----------------------------------------------
        # Frozen status
        # -----------------------------------------------

        if candidate["status"] != "frozen":
            codes.append("NOT_FROZEN")

        # -----------------------------------------------
        # Manifest
        # -----------------------------------------------

        manifest_valid = validate_manifest(
            candidate
        )

        if not manifest_valid:
            codes.append(
                "INVALID_MANIFEST"
            )

        # -----------------------------------------------
        # Predictions
        # -----------------------------------------------

        prediction_valid = rows_valid

        if prediction_valid:

            for row in rows:

                predictions = row[
                    "predictions"
                ]

                if (
                    name not in predictions
                    or not valid_binary(
                        predictions[name]
                    )
                ):
                    prediction_valid = False
                    break

        if not prediction_valid:
            codes.append(
                "INVALID_PREDICTIONS"
            )

        # -----------------------------------------------
        # Aggregate / slices
        # -----------------------------------------------

        aggregate = None

        slice_results = {
            slice_name: None
            for slice_name in policy[
                "requiredSlices"
            ]
        }

        if prediction_valid:

            if len(rows) > 0:

                correct = sum(
                    1
                    for row in rows
                    if row["predictions"][name]
                    == row["label"]
                )

                aggregate = round(
                    correct / len(rows),
                    12,
                )

                if (
                    aggregate
                    < float(
                        policy[
                            "aggregateFloor"
                        ]
                    )
                ):
                    codes.append(
                        "AGGREGATE_FLOOR"
                    )

                # ---------------------------------------
                # Slice calculations
                # ---------------------------------------

                for slice_name, floor in (
                    policy[
                        "requiredSlices"
                    ].items()
                ):

                    slice_rows = [
                        row
                        for row in rows
                        if row["slice"]
                        == slice_name
                    ]

                    if len(slice_rows) == 0:

                        codes.append(
                            f"MISSING_SLICE:{slice_name}"
                        )

                        slice_results[
                            slice_name
                        ] = None

                    else:

                        slice_correct = sum(
                            1
                            for row in slice_rows
                            if row[
                                "predictions"
                            ][name]
                            == row["label"]
                        )

                        slice_accuracy = round(
                            slice_correct
                            / len(slice_rows),
                            12,
                        )

                        slice_results[
                            slice_name
                        ] = slice_accuracy

                        if (
                            slice_accuracy
                            < float(floor)
                        ):
                            codes.append(
                                f"SLICE_FLOOR:{slice_name}"
                            )

        # -----------------------------------------------
        # Size
        # -----------------------------------------------

        total_bytes = None

        if manifest_valid:

            total_bytes = candidate[
                "totalBytes"
            ]

            if total_bytes > policy[
                "maxBytes"
            ]:
                codes.append(
                    "SIZE_LIMIT"
                )

        # -----------------------------------------------
        # Latency
        # -----------------------------------------------

        latency_ms = None

        if (
            name in latencies
            and is_finite_nonnegative(
                latencies[name]
            )
        ):

            latency_ms = latencies[name]

            if (
                latency_ms
                > policy["maxLatencyMs"]
            ):
                codes.append(
                    "LATENCY_LIMIT"
                )

        else:

            codes.append(
                "INVALID_LINEAGE"
            )

        # -----------------------------------------------
        # Candidate admitted?
        # -----------------------------------------------

        admitted = (
            len(codes) == 0
        )

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slice_results,
            "totalBytes": total_bytes,
            "latencyMs": latency_ms,
            "admitted": admitted,
            "reasonCodes": sort_unique_codes(
                codes
            ),
        })

    # --------------------------------------------------------
    # Result order
    # --------------------------------------------------------

    results.sort(
        key=lambda r: (
            candidate_order_index.get(
                r["name"],
                len(candidate_order_index),
            ),
            utf8_key(r["name"]),
        )
    )

    # --------------------------------------------------------
    # Select winner
    # --------------------------------------------------------

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    winner = None

    if admitted:

        winner = min(
            admitted,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                candidate_order_index[
                    r["name"]
                ],
            )
        )

    selected = (
        winner["name"]
        if winner is not None
        else None
    )

    package_manifest = None

    if winner is not None:

        for candidate in stored_candidates:

            if candidate["name"] == winner["name"]:

                package_manifest = deepcopy(
                    candidate
                )

                break

    return JSONResponse({
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    })


# ============================================================
# MAIN ENDPOINT
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    if not isinstance(data, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    phase = data.get("phase")

    if phase == "freeze":

        return handle_freeze(data)

    elif phase == "select":

        return handle_select(data)

    else:

        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "endpoint": "/quantize",
    }
