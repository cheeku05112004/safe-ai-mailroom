import base64
import binascii
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_json_bytes(data) -> bytes:
    """Return recursively sorted, compact UTF-8 JSON."""
    canonical = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def calculate_input_digest(dossiers: list) -> str:
    return sha256_hex(canonical_json_bytes(dossiers))


def calculate_proposal_digest(proposal: dict) -> str:
    normalized = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal["payload"],
        "evidence": sorted(proposal["evidence"]),
    }
    return sha256_hex(canonical_json_bytes(normalized))


def build_receipt_message(
    profile: str,
    evaluation_id: str,
    input_digest: str,
    receipt: dict,
) -> bytes:
    signed_receipt = {
        "dossierId": receipt["dossierId"],
        "callId": receipt["callId"],
        "action": receipt["action"],
        "accepted": receipt["accepted"],
        "proposalDigest": receipt["proposalDigest"],
        "receiptId": receipt["receiptId"],
    }

    message = {
        "profile": profile,
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipt": signed_receipt,
    }

    return canonical_json_bytes(message)


def verify_receipt_signature(
    public_key_jwk: dict,
    signature_b64: str,
    profile: str,
    evaluation_id: str,
    input_digest: str,
    receipt: dict,
) -> bool:
    """Verify one Ed25519 receipt signature."""
    try:
        if public_key_jwk.get("kty") != "OKP":
            return False

        if public_key_jwk.get("crv") != "Ed25519":
            return False

        encoded_key = public_key_jwk["x"]
        encoded_signature = signature_b64

        key_bytes = base64.urlsafe_b64decode(
            encoded_key + "=" * (-len(encoded_key) % 4)
        )
        signature_bytes = base64.b64decode(
            encoded_signature,
            validate=True,
        )

        if len(key_bytes) != 32 or len(signature_bytes) != 64:
            return False

        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)

        message = build_receipt_message(
            profile,
            evaluation_id,
            input_digest,
            receipt,
        )

        public_key.verify(signature_bytes, message)
        return True

    except (
        InvalidSignature,
        ValueError,
        KeyError,
        TypeError,
        binascii.Error,
    ):
        return False
