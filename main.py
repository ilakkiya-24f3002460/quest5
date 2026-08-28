import hashlib
import json
import math
from copy import deepcopy

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

# Persistent state for the running service.
# Key = freezeId
FREEZES = {}


# ============================================================
# HELPERS
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def utf8_key(value):
    return value.encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(value):
    return sha256_text(compact_json(value))


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: x.encode("utf-8")
    )


def nonempty_string(value):
    return isinstance(value, str) and len(value) > 0


def safe_nonnegative_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 9007199254740991
    )


def finite_nonnegative(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def finite_unit(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def binary_value(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


# ============================================================
# INVENTORY
# ============================================================

def make_inventory(files):
    """
    Returns:
        valid,
        inventory,
        total_bytes,
        package_digest
    """

    if not isinstance(files, dict) or len(files) == 0:
        return False, [], None, None

    inventory = []

    for name, content in files.items():

        if not isinstance(name, str):
            return False, [], None, None

        if not isinstance(content, str):
            return False, [], None, None

        raw = content.encode("utf-8")

        inventory.append({
            "name": name,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    inventory.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    total = sum(
        item["bytes"]
        for item in inventory
    )

    digest = sha256_json(inventory)

    return True, inventory, total, digest


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons
):

    # Candidate itself must be an object.
    if not isinstance(candidate, dict):
        return {
            "name": "",
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"]
        }

    name = candidate.get("name")

    codes = []

    if not nonempty_string(name):
        codes.append("INVALID_INPUT")
        name = ""

    files = candidate.get("files")

    files_valid, inventory, total_bytes, package_digest = \
        make_inventory(files)

    if not files_valid:
        codes.append("INVALID_INPUT")
        inventory = []
        total_bytes = None
        package_digest = None

    loadable = candidate.get("loadable")

    if not isinstance(loadable, bool):
        codes.append("INVALID_INPUT")

    candidate_calibration = candidate.get(
        "calibrationDigest"
    )

    candidate_tokenizer = candidate.get(
        "tokenizerDigest"
    )

    if not nonempty_string(candidate_calibration):
        codes.append("INVALID_INPUT")

    if not nonempty_string(candidate_tokenizer):
        codes.append("INVALID_INPUT")

    unsupported = candidate.get(
        "unsupportedReason",
        None
    )

    # --------------------------------------------------------
    # Unsupported candidate
    # --------------------------------------------------------

    if unsupported is not None:

        if not nonempty_string(unsupported):
            codes.append("INVALID_INPUT")

        elif unsupported not in allowed_reasons:
            codes.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

        if len(codes) == 0:
            status = "unsupported"
        else:
            status = "invalid"

    # --------------------------------------------------------
    # Normal candidate
    # --------------------------------------------------------

    else:

        if isinstance(loadable, bool):

            if not loadable:
                codes.append("NOT_LOADABLE")

        if (
            nonempty_string(candidate_calibration)
            and candidate_calibration != request_calibration
        ):
            codes.append(
                "CALIBRATION_MISMATCH"
            )

        if (
            nonempty_string(candidate_tokenizer)
            and candidate_tokenizer != request_tokenizer
        ):
            codes.append(
                "TOKENIZER_MISMATCH"
            )

        if len(codes) == 0:
            status = "frozen"
        else:
            status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sorted_codes(codes)
    }


# ============================================================
# FREEZE INPUT FINGERPRINT
# ============================================================

def freeze_fingerprint(data):
    return compact_json(data)


# ============================================================
# FREEZE OPERATION
# ============================================================

def do_freeze(data):

    # Required top-level fields
    freeze_id = data.get("freezeId")
    calibration = data.get("calibrationDigest")
    tokenizer = data.get("tokenizerDigest")
    allowed = data.get("allowedUnsupportedReasons")
    candidates = data.get("candidates")

    # These are request-contract failures.
    if not nonempty_string(freeze_id):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if len(freeze_id) > 128:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if not nonempty_string(calibration):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if not nonempty_string(tokenizer):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if not isinstance(allowed, list):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if not isinstance(candidates, list):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if len(candidates) == 0:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    # Allowed unsupported reasons must be unique
    # non-empty strings.
    if any(
        not nonempty_string(x)
        for x in allowed
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if len(set(allowed)) != len(allowed):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    # Candidate names must be unique.
    names = []

    for candidate in candidates:

        if isinstance(candidate, dict):
            name = candidate.get("name")

            if nonempty_string(name):
                names.append(name)

    if len(names) != len(set(names)):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    # --------------------------------------------------------
    # Check idempotency BEFORE storing anything.
    # --------------------------------------------------------

    fingerprint = freeze_fingerprint(data)

    if freeze_id in FREEZES:

        old = FREEZES[freeze_id]

        if old["fingerprint"] == fingerprint:
            return JSONResponse(
                deepcopy(old["response"])
            )

        return JSONResponse(
            {"error": "FREEZE_ID_CONFLICT"},
            status_code=409
        )

    # --------------------------------------------------------
    # Build candidate results.
    # --------------------------------------------------------

    result_candidates = []

    for candidate in candidates:

        result_candidates.append(
            freeze_candidate(
                candidate,
                calibration,
                tokenizer,
                set(allowed)
            )
        )

    result_candidates.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    response = {
        "freezeId": freeze_id,
        "candidates": result_candidates
    }

    # Persist.
    FREEZES[freeze_id] = {
        "fingerprint": fingerprint,
        "response": deepcopy(response)
    }

    return JSONResponse(response)


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_recorded_manifest(candidate):

    if not isinstance(candidate, dict):
        return False

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False

    previous_names = []

    total = 0

    cleaned = []

    for item in inventory:

        if not isinstance(item, dict):
            return False

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False

        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return False

        if not safe_nonnegative_int(byte_count):
            return False

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(
                c not in "0123456789abcdef"
                for c in digest
            )
        ):
            return False

        previous_names.append(name)

        total += byte_count

        cleaned.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest
        })

    # Names unique.
    if len(previous_names) != len(
        set(previous_names)
    ):
        return False

    # Names sorted by UTF-8.
    if previous_names != sorted(
        previous_names,
        key=lambda x: x.encode("utf-8")
    ):
        return False

    recorded_total = candidate.get(
        "totalBytes"
    )

    recorded_digest = candidate.get(
        "packageDigest"
    )

    if not safe_nonnegative_int(recorded_total):
        return False

    if (
        not isinstance(recorded_digest, str)
        or len(recorded_digest) != 64
        or any(
            c not in "0123456789abcdef"
            for c in recorded_digest
        )
    ):
        return False

    if total != recorded_total:
        return False

    if sha256_json(cleaned) != recorded_digest:
        return False

    return True


# ============================================================
# POLICY VALIDATION
# ============================================================

def policy_valid(policy):

    if not isinstance(policy, dict):
        return False

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder"
    }

    if not required.issubset(policy.keys()):
        return False

    if not safe_nonnegative_int(
        policy["maxBytes"]
    ):
        return False

    if not finite_unit(
        policy["aggregateFloor"]
    ):
        return False

    if not isinstance(
        policy["requiredSlices"],
        dict
    ):
        return False

    for name, floor in policy[
        "requiredSlices"
    ].items():

        if not nonempty_string(name):
            return False

        if not finite_unit(floor):
            return False

    if not finite_nonnegative(
        policy["maxLatencyMs"]
    ):
        return False

    order = policy["candidateOrder"]

    if not isinstance(order, list):
        return False

    if any(
        not nonempty_string(x)
        for x in order
    ):
        return False

    if len(order) != len(set(order)):
        return False

    return True


# ============================================================
# SELECT
# ============================================================

def do_select(data):

    freeze_id = data.get("freezeId")
    candidates = data.get("candidates")
    policy = data.get("policy")
    latencies = data.get("latencies")
    rows = data.get("rows")

    # The prompt explicitly says this combination must
    # produce HTTP 400.
    if (
        not nonempty_string(freeze_id)
        or not isinstance(candidates, list)
        or len(candidates) == 0
        or not isinstance(policy, dict)
        or not isinstance(rows, list)
        or not isinstance(latencies, dict)
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    # --------------------------------------------------------
    # Unknown freeze
    # --------------------------------------------------------

    if freeze_id not in FREEZES:

        results = []

        for candidate in candidates:

            name = (
                candidate.get("name", "")
                if isinstance(candidate, dict)
                else ""
            )

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "NOT_FROZEN"
                ]
            })

        return JSONResponse({
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        })

    stored = FREEZES[
        freeze_id
    ]["response"]

    stored_candidates = stored[
        "candidates"
    ]

    # --------------------------------------------------------
    # Supplied candidates must equal frozen candidates.
    # --------------------------------------------------------

    if compact_json(candidates) != compact_json(
        stored_candidates
    ):
        return JSONResponse(
            {"error": "INVALID_LINEAGE"},
            status_code=409
        )

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    if not policy_valid(policy):

        results = []

        for candidate in stored_candidates:

            results.append({
                "name": candidate["name"],
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ]
            })

        return JSONResponse({
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        })

    # --------------------------------------------------------
    # Candidate names and order must match.
    # --------------------------------------------------------

    stored_names = [
        c["name"]
        for c in stored_candidates
    ]

    order = policy[
        "candidateOrder"
    ]

    if (
        len(order) != len(stored_names)
        or set(order) != set(stored_names)
        or len(order) != len(set(order))
    ):

        results = []

        for candidate in stored_candidates:

            results.append({
                "name": candidate["name"],
                "aggregate": None,
                "slices": {
                    name: None
                    for name in policy[
                        "requiredSlices"
                    ]
                },
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ]
            })

        return JSONResponse({
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        })

    order_index = {
        name: i
        for i, name in enumerate(order)
    }

    # --------------------------------------------------------
    # Validate rows
    # --------------------------------------------------------

    row_structure_valid = True

    for row in rows:

        if not isinstance(row, dict):
            row_structure_valid = False
            break

        if set(row.keys()) != {
            "label",
            "slice",
            "predictions"
        }:
            row_structure_valid = False
            break

        if not binary_value(row["label"]):
            row_structure_valid = False
            break

        if not nonempty_string(row["slice"]):
            row_structure_valid = False
            break

        if not isinstance(
            row["predictions"],
            dict
        ):
            row_structure_valid = False
            break

    # --------------------------------------------------------
    # Candidate results
    # --------------------------------------------------------

    results = []

    for candidate in stored_candidates:

        name = candidate["name"]

        codes = []

        # ----------------------------------------------------
        # Candidate status
        # ----------------------------------------------------

        if candidate["status"] != "frozen":
            codes.append("NOT_FROZEN")

        # ----------------------------------------------------
        # Manifest
        # ----------------------------------------------------

        manifest_ok = validate_recorded_manifest(
            candidate
        )

        if not manifest_ok:
            codes.append("INVALID_MANIFEST")

        # ----------------------------------------------------
        # Prediction validation
        # ----------------------------------------------------

        predictions_ok = row_structure_valid

        if predictions_ok:

            for row in rows:

                predictions = row[
                    "predictions"
                ]

                if name not in predictions:
                    predictions_ok = False
                    break

                if not binary_value(
                    predictions[name]
                ):
                    predictions_ok = False
                    break

        if not predictions_ok:
            codes.append(
                "INVALID_PREDICTIONS"
            )

        # ----------------------------------------------------
        # Accuracy
        # ----------------------------------------------------

        aggregate = None

        slice_values = {
            slice_name: None
            for slice_name in policy[
                "requiredSlices"
            ]
        }

        if predictions_ok and len(rows) > 0:

            correct = 0

            for row in rows:

                if (
                    row["predictions"][name]
                    == row["label"]
                ):
                    correct += 1

            aggregate = round(
                correct / len(rows),
                12
            )

            if (
                aggregate
                < float(
                    policy["aggregateFloor"]
                )
            ):
                codes.append(
                    "AGGREGATE_FLOOR"
                )

            # Required slices.
            for slice_name, floor in (
                policy["requiredSlices"].items()
            ):

                matching = [
                    row
                    for row in rows
                    if row["slice"] == slice_name
                ]

                if len(matching) == 0:

                    codes.append(
                        f"MISSING_SLICE:{slice_name}"
                    )

                    slice_values[
                        slice_name
                    ] = None

                else:

                    slice_correct = sum(
                        1
                        for row in matching
                        if (
                            row["predictions"][name]
                            == row["label"]
                        )
                    )

                    accuracy = round(
                        slice_correct
                        / len(matching),
                        12
                    )

                    slice_values[
                        slice_name
                    ] = accuracy

                    if accuracy < float(floor):

                        codes.append(
                            f"SLICE_FLOOR:{slice_name}"
                        )

        # ----------------------------------------------------
        # Total bytes
        # ----------------------------------------------------

        total_bytes = None

        if manifest_ok:

            total_bytes = candidate[
                "totalBytes"
            ]

            if (
                total_bytes
                > policy["maxBytes"]
            ):
                codes.append(
                    "SIZE_LIMIT"
                )

        # ----------------------------------------------------
        # Latency
        # ----------------------------------------------------

        latency = None

        if (
            name in latencies
            and finite_nonnegative(
                latencies[name]
            )
        ):

            latency = latencies[name]

            if (
                float(latency)
                > float(
                    policy["maxLatencyMs"]
                )
            ):
                codes.append(
                    "LATENCY_LIMIT"
                )

        else:

            codes.append(
                "INVALID_LINEAGE"
            )

        # ----------------------------------------------------
        # Admission
        # ----------------------------------------------------

        admitted = len(codes) == 0

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slice_values,
            "totalBytes": total_bytes,
            "latencyMs": latency,
            "admitted": admitted,
            "reasonCodes": sorted_codes(codes)
        })

    # --------------------------------------------------------
    # Results order = candidateOrder
    # --------------------------------------------------------

    results.sort(
        key=lambda result: (
            order_index.get(
                result["name"],
                len(order)
            ),
            utf8_key(result["name"])
        )
    )

    # --------------------------------------------------------
    # Winner
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
            key=lambda result: (
                result["totalBytes"],
                float(result["latencyMs"]),
                order_index[
                    result["name"]
                ]
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

            if (
                candidate["name"]
                == winner["name"]
            ):

                package_manifest = deepcopy(
                    candidate
                )

                break

    return JSONResponse({
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    })


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if not isinstance(data, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    phase = data.get("phase")

    if phase == "freeze":
        return do_freeze(data)

    if phase == "select":
        return do_select(data)

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def health():
    return {
        "status": "ok",
        "endpoint": "/quantize"
    }
