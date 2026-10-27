import asyncio
import hashlib
import json
import logging

logger = logging.getLogger(__name__)
import time
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from fastapi import FastAPI, HTTPException, Body
from pydantic import ValidationError
from app.schemas import ProposeRequest, CommitRequest, PROFILE
from app.security import canonical_json_bytes, calculate_input_digest
from app.storage import (
    initialize_database,
    get_evaluation,
    get_cached_decision,
    save_propose_result,
)
from app.decision import (
    propose_for_dossier,
    validate_proposal,
    validate_exact_schema,
)

app = FastAPI(
    title="Safe AI Mailroom",
    description="An AI agent that checks authority before taking action.",
    version="1.0.0",
)

MAX_CONCURRENT_AI_CALLS = 8
REQUEST_TIMEOUT_SECONDS = 53
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
COMMIT_TIMEOUT_SECONDS = 180


@app.middleware("http")
async def enforce_payload_limits(request, call_next):
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > MAX_PAYLOAD_BYTES:
                return JSONResponse(
                    {"error": "Request body too large"},
                    status_code=413,
                )
        except ValueError:
            return JSONResponse(
                {"error": "Invalid Content-Length"},
                status_code=400,
            )

    body = await request.body()

    if len(body) > MAX_PAYLOAD_BYTES:
        return JSONResponse(
            {"error": "Request body too large"},
            status_code=413,
        )

    async def receive():
        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    request._receive = receive
    response = await call_next(request)

    response_body = bytearray()
    async for chunk in response.body_iterator:
        response_body.extend(chunk)
        if len(response_body) > MAX_RESPONSE_BYTES:
            return JSONResponse(
                {"error": "Response body too large"},
                status_code=500,
            )

    headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower() != "content-length"
    }

    return Response(
        content=bytes(response_body),
        status_code=response.status_code,
        headers=headers,
        background=response.background,
    )

@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/")
def home():
    return {"message": "Safe AI Mailroom Agent is running!"}


@app.get("/health")
def health():
    return {"status": "healthy"}


def make_fingerprint(dossier: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(dossier)).hexdigest()


def make_call_id(partition: str, evaluation_id: str, fingerprint: str) -> str:
    if partition == "stable_core":
        return "core:" + fingerprint

    value = evaluation_id + ":" + fingerprint
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return "audit:" + digest


async def create_one_proposal(
    dossier: dict,
    allowed_actions: list[str],
    evaluation_id: str,
    semaphore: asyncio.Semaphore,
):
    fingerprint = make_fingerprint(dossier)
    call_id = make_call_id(
        dossier["partition"],
        evaluation_id,
        fingerprint,
    )

    # Only stable core decisions are reused across evaluations.
    if dossier["partition"] == "stable_core":
        cached = get_cached_decision(fingerprint)
        if cached is not None:
            cached = dict(cached)

            # Remove evaluation-specific identifiers before validation.
            cached.pop("dossierId", None)
            cached.pop("callId", None)

            # Revalidate the semantic decision against the current dossier.
            validate_proposal(cached, dossier, allowed_actions)
            validate_exact_schema(cached, dossier)

            cached["dossierId"] = dossier["dossierId"]
            cached["callId"] = call_id
            return {
                "dossierId": dossier["dossierId"],
                "callId": call_id,
                "contentFingerprint": fingerprint,
                "proposal": cached,
            }

    async with semaphore:
        raw = await propose_for_dossier(dossier, allowed_actions)

    validate_proposal(raw, dossier, allowed_actions)
    validate_exact_schema(raw, dossier)

    proposal = {
        "dossierId": dossier["dossierId"],
        "callId": call_id,
        "action": raw["action"],
        "target": raw["target"],
        "payload": raw["payload"],
        "evidence": raw["evidence"],
    }

    return {
        "dossierId": dossier["dossierId"],
        "callId": call_id,
        "contentFingerprint": fingerprint,
        "proposal": proposal,
    }


@app.post("/propose")
async def propose(request: ProposeRequest):
    dossiers = [
        dossier.model_dump(mode="json")
        for dossier in request.dossiers
    ]

    input_digest = calculate_input_digest(dossiers)

    # Exact replay: return the original response without calling the model.
    existing = get_evaluation(request.evaluationId)

    if existing:
        if existing["input_digest"] != input_digest:
            raise HTTPException(
                status_code=409,
                detail="Evaluation ID already exists with different input.",
            )

        if existing["propose_response"]:
            return json.loads(existing["propose_response"])

        raise HTTPException(
            status_code=409,
            detail="This evaluation is already being processed.",
        )

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_AI_CALLS)

    async def build_all_proposals():
        tasks = [
            create_one_proposal(
                dossier,
                request.allowedActions,
                request.evaluationId,
                semaphore,
            )
            for dossier in dossiers
        ]
        return await asyncio.gather(*tasks)

    try:
        items = await asyncio.wait_for(
            build_all_proposals(),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail="Proposal processing timed out. Retry with the same evaluation ID.",
        )
    except ValueError as exc:
        logger.exception("Proposal ValueError: %s", str(exc))
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.exception(
            "Proposal processing failed: %s",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Proposal processing failed.",
        )

    proposals = [item["proposal"] for item in items]

    response = {
        "profile": PROFILE,
        "evaluationId": request.evaluationId,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals,
    }

    verifier_json = json.dumps(
        request.receiptVerifier.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )

    try:
        saved_response = save_propose_result(
            request.evaluationId,
            input_digest,
            verifier_json,
            response,
            items,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return saved_response


@app.post("/commit")
def commit(request: CommitRequest):
    from fastapi import HTTPException
    from app.security import (
        calculate_proposal_digest,
        verify_receipt_signature,
    )
    from app.storage import (
        get_evaluation,
        get_proposals,
        save_commit_result,
    )

    # Enforce a cooperative deadline for receipt verification and saving.
    deadline = time.monotonic() + COMMIT_TIMEOUT_SECONDS

    # Validate the incoming request against the strict Pydantic schema.
    data = request

    evaluation = get_evaluation(data.evaluationId)

    if evaluation is None:
        raise HTTPException(status_code=404, detail="Unknown evaluation.")

    if data.inputDigest != evaluation["input_digest"]:
        raise HTTPException(status_code=409, detail="Input digest mismatch.")

    stored_items = get_proposals(data.evaluationId)
    stored_by_id = {
        item["dossierId"]: item["proposal"]
        for item in stored_items
    }

    if len(data.receipts) != len(stored_items):
        raise HTTPException(
            status_code=422,
            detail="Exactly one receipt is required for every proposal.",
        )

    verifier = json.loads(evaluation["verifier_json"])
    public_key_jwk = verifier["publicKeyJwk"]

    outcomes = []
    verified_receipts = []

    # Verify every receipt before saving any receipt or outcome.
    for receipt_model in data.receipts:
        if time.monotonic() >= deadline:
            raise HTTPException(
                status_code=504,
                detail="Commit verification deadline exceeded.",
            )

        receipt = receipt_model.model_dump()
        dossier_id = receipt["dossierId"]

        proposal = stored_by_id.get(dossier_id)

        if proposal is None:
            raise HTTPException(
                status_code=422,
                detail="Receipt refers to an unknown dossier.",
            )

        if (
            receipt["callId"] != proposal["callId"]
            or receipt["action"] != proposal["action"]
        ):
            raise HTTPException(
                status_code=422,
                detail="Receipt does not match its proposal.",
            )

        expected_digest = calculate_proposal_digest(proposal)

        if receipt["proposalDigest"] != expected_digest:
            raise HTTPException(
                status_code=422,
                detail="Proposal digest mismatch.",
            )

        valid_signature = verify_receipt_signature(
            public_key_jwk,
            receipt["receiptSignature"],
            PROFILE,
            data.evaluationId,
            data.inputDigest,
            receipt,
        )

        if not valid_signature:
            raise HTTPException(
                status_code=422,
                detail="Invalid receipt signature.",
            )

        verified_receipts.append(receipt)

        outcomes.append({
            "dossierId": dossier_id,
            "callId": receipt["callId"],
            "action": receipt["action"],
            "proposalDigest": expected_digest,
            "receiptId": receipt["receiptId"],
            "status": "executed" if receipt["accepted"] else "rejected",
        })

    response = {
        "profile": PROFILE,
        "evaluationId": data.evaluationId,
        "status": "completed",
        "inputDigest": data.inputDigest,
        "outcomes": outcomes,
    }

    if time.monotonic() >= deadline:
        raise HTTPException(
            status_code=504,
            detail="Commit verification deadline exceeded.",
        )

    try:
        return save_commit_result(
            data.evaluationId,
            verified_receipts,
            response,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.post("/")
async def gateway(payload: dict = Body(...)):
    operation = payload.get("operation")

    try:
        if operation == "propose":
            request = ProposeRequest.model_validate(payload)
            return await propose(request)

        elif operation == "commit":
            request = CommitRequest.model_validate(payload)
            return await run_in_threadpool(commit, request)

        else:
            raise HTTPException(
                status_code=422,
                detail="operation must be propose or commit.",
            )

    except ValidationError:
        raise HTTPException(
            status_code=422,
            detail="Invalid request schema.",
        )
