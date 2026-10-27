
import base64
import json
import httpx

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from app.security import (
    calculate_proposal_digest,
    build_receipt_message,
)

BASE_URL = "http://127.0.0.1:8000"

# Load the same private key used in test_propose.py
private_key = serialization.load_pem_private_key(
    Path("test_private_key.pem").read_bytes(),
    password=None,
)

public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
public_key_x = base64.urlsafe_b64encode(public_bytes).decode().rstrip("=")

dossier = json.loads(Path("sample_dossier.json").read_text())

request_data = {
    "profile": "ga5-mailroom-action-gate/v2",
    "operation": "propose",
    "evaluationId": "LOCAL-REJECT-TEST-001",
    "receiptVerifier": {
        "algorithm": "Ed25519",
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_key_x,
        },
    },
    "corpus": {
        "coreId": "LOCAL-CORE",
        "auditId": "LOCAL-AUDIT",
        "stableCount": 1,
        "freshCount": 0,
    },
    "allowedActions": [
        "create_draft",
        "update_internal_record",
        "send_approved_notice",
        "request_confirmation",
        "quarantine_item",
        "no_action",
    ],
    "dossiers": [dossier],
}

with httpx.Client(timeout=60) as client:

    # Test 1: Get proposal
    propose_response = client.post(
        BASE_URL + "/propose",
        json=request_data,
    )

    print("Propose status:", propose_response.status_code)
    propose_response.raise_for_status()

    result = propose_response.json()
    proposal = result["proposals"][0]

    # Test 2: Create a rejected receipt
    receipt = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "accepted": False,
        "proposalDigest": calculate_proposal_digest(proposal),
        "receiptId": "LOCAL-REJECT-RECEIPT-001",
    }

    # Sign the receipt
    message = build_receipt_message(
        request_data["profile"],
        result["evaluationId"],
        result["inputDigest"],
        receipt,
    )

    signature = private_key.sign(message)
    receipt["receiptSignature"] = base64.b64encode(
        signature
    ).decode()

    commit_data = {
        "profile": request_data["profile"],
        "operation": "commit",
        "evaluationId": result["evaluationId"],
        "inputDigest": result["inputDigest"],
        "receipts": [receipt],
    }

    # Test 3: Invalid signature must fail
    bad_data = json.loads(json.dumps(commit_data))
    bad_data["receipts"][0]["receiptSignature"] = "AAAA"

    bad_response = client.post(
        BASE_URL + "/commit",
        json=bad_data,
    )

    print(
        "Invalid signature status (expected 422):",
        bad_response.status_code,
    )

    # Test 4: Valid signature with accepted=False
    good_response = client.post(
        BASE_URL + "/commit",
        json=commit_data,
    )

    print("Valid rejected-receipt commit status:", good_response.status_code)
    good_response.raise_for_status()

    response_data = good_response.json()
    print(json.dumps(response_data, indent=2))

    # Verify accepted=False produces rejected outcome
    outcome = response_data["outcomes"][0]

    print("Rejected receipt outcome:", outcome["status"])

    assert outcome["status"] == "rejected", (
        "Expected rejected, got " + outcome["status"]
    )

    print("PASS: accepted=False produces rejected outcome.")

    # Test 5: Exact commit replay
    replay_response = client.post(
        BASE_URL + "/commit",
        json=commit_data,
    )

    print("Commit replay status:", replay_response.status_code)

    assert replay_response.json() == good_response.json()

    print("Replay response identical: True")

    # Test 6: Changed receipt must return 409
    changed_data = json.loads(json.dumps(commit_data))
    changed_data["receipts"][0]["receiptId"] = (
        "LOCAL-DIFFERENT-RECEIPT"
    )

    changed_receipt = changed_data["receipts"][0]

    changed_message = build_receipt_message(
        request_data["profile"],
        result["evaluationId"],
        result["inputDigest"],
        changed_receipt,
    )

    changed_signature = private_key.sign(changed_message)

    changed_receipt["receiptSignature"] = base64.b64encode(
        changed_signature
    ).decode()

    changed_response = client.post(
        BASE_URL + "/commit",
        json=changed_data,
    )

    print(
        "Changed receipt status (expected 409):",
        changed_response.status_code,
    )

    assert changed_response.status_code == 409

    print("PASS: Changed receipt rejected.")

