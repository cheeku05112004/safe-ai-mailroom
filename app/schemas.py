import base64
import re

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


PROFILE = "ga5-mailroom-action-gate/v2"

ALL_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}

Action = Literal[
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Line(StrictModel):
    lineId: str = Field(min_length=1, max_length=200)
    text: str = Field(max_length=20000)


class Source(StrictModel):
    sourceId: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=100)
    provenance: str = Field(min_length=1, max_length=500)
    title: str = Field(max_length=1000)
    lines: list[Line] = Field(max_length=500)


class Dossier(StrictModel):
    dossierId: str = Field(min_length=1, max_length=200)
    partition: Literal["stable_core", "fresh_audit"]
    receivedAt: str = Field(min_length=1, max_length=100)
    mailbox: str = Field(min_length=1, max_length=500)
    objective: str = Field(max_length=5000)
    sources: list[Source] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def check_line_ids(self):
        ids = [
            line.lineId
            for source in self.sources
            for line in source.lines
        ]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate lineId in dossier")
        return self


class PublicKeyJWK(StrictModel):
    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")

    @model_validator(mode="after")
    def check_public_key(self):
        try:
            raw = base64.urlsafe_b64decode(
                self.x + "=" * (-len(self.x) % 4)
            )
        except Exception as exc:
            raise ValueError("Invalid Ed25519 public key") from exc

        if len(raw) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")

        canonical = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        if canonical != self.x:
            raise ValueError("Non-canonical Ed25519 public key")

        return self


class ReceiptVerifier(StrictModel):
    algorithm: Literal["Ed25519"]
    publicKeyJwk: PublicKeyJWK


class Corpus(StrictModel):
    coreId: str = Field(min_length=1, max_length=200)
    auditId: str = Field(min_length=1, max_length=200)
    stableCount: int = Field(ge=0, le=100)
    freshCount: int = Field(ge=0, le=100)


class ProposeRequest(StrictModel):
    profile: Literal[PROFILE]
    operation: Literal["propose"]
    evaluationId: str = Field(min_length=1, max_length=200)
    receiptVerifier: ReceiptVerifier
    corpus: Corpus
    allowedActions: list[Action]
    dossiers: list[Dossier] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def check_request(self):
        ids = [d.dossierId for d in self.dossiers]

        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate dossierId")

        if len(self.allowedActions) != len(set(self.allowedActions)):
            raise ValueError("Duplicate allowed action")

        if set(self.allowedActions) != ALL_ACTIONS:
            raise ValueError("allowedActions must contain all six actions")

        stable = sum(
            d.partition == "stable_core" for d in self.dossiers
        )
        fresh = sum(
            d.partition == "fresh_audit" for d in self.dossiers
        )

        if stable != self.corpus.stableCount:
            raise ValueError("stableCount does not match dossiers")

        if fresh != self.corpus.freshCount:
            raise ValueError("freshCount does not match dossiers")

        if len(self.dossiers) != stable + fresh:
            raise ValueError("Invalid dossier count")

        return self


class Receipt(StrictModel):
    dossierId: str = Field(min_length=1, max_length=200)
    callId: str = Field(
        min_length=12,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    action: Action
    accepted: bool
    proposalDigest: str = Field(pattern=r"^[0-9a-f]{64}$")
    receiptId: str = Field(min_length=1, max_length=200)
    receiptSignature: str = Field(min_length=1, max_length=500)


class CommitRequest(StrictModel):
    profile: Literal[PROFILE]
    operation: Literal["commit"]
    evaluationId: str = Field(min_length=1, max_length=200)
    inputDigest: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipts: list[Receipt] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def check_unique_receipts(self):
        dossier_ids = [r.dossierId for r in self.receipts]
        call_ids = [r.callId for r in self.receipts]
        receipt_ids = [r.receiptId for r in self.receipts]

        if len(dossier_ids) != len(set(dossier_ids)):
            raise ValueError("Duplicate receipt dossierId")

        if len(call_ids) != len(set(call_ids)):
            raise ValueError("Duplicate receipt callId")

        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("Duplicate receiptId")

        return self
