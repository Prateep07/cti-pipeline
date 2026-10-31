"""Output schema shared by every extractor (regex, zero-shot LLM, later the fine-tuned model)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

IOC_TYPES = [
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
    "cve",
    "attack_technique",
]

IocType = Literal[
    "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve", "attack_technique"
]


class ExtractedItem(BaseModel):
    type: IocType
    value: str
    # Short span copied verbatim from the report that contains the value.
    # Used for grounding checks; the regex baseline leaves it empty.
    quote: str = ""


class Extraction(BaseModel):
    items: list[ExtractedItem] = Field(default_factory=list)


# Hand-written so it satisfies strict structured-output modes
# (all fields required, additionalProperties false).
EXTRACTION_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": IOC_TYPES},
                    "value": {"type": "string"},
                    "quote": {"type": "string"},
                },
                "required": ["type", "value", "quote"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["items"],
    "additionalProperties": False,
}
