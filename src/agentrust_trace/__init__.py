"""agentrust-trace — TRACE Trust Record models, validation, and signing."""

from agentrust_trace.adapters import AGTSessionResult, TraceAGTAdapter
from agentrust_trace.models import (
    Appraisal,
    BuildProvenance,
    ConfirmationKey,
    Delegation,
    JWK,
    ModelInfo,
    PolicyInfo,
    RuntimeInfo,
    ToolTranscript,
    TrustRecord,
)
from agentrust_trace.sign import (
    RevocationStore,
    generate_key,
    jwk_thumbprint,
    key_to_jwk,
    load_key,
    load_signing_key,
    sign_record,
    verify_record,
)
from agentrust_trace.validate import (
    iter_errors,
    SCHEMA,
    validate_json,
)

__version__ = "0.5.1"
"""Distribution version, kept in step with ``pyproject.toml``.

Not the spec version: this library implements TRACE v0.2, identified on the wire
by the ``eat_profile`` URI, and the two version lines move independently.
"""

__all__ = [
    "__version__",
    "AGTSessionResult",
    "TraceAGTAdapter",
    "Appraisal",
    "BuildProvenance",
    "ConfirmationKey",
    "Delegation",
    "JWK",
    "ModelInfo",
    "PolicyInfo",
    "RuntimeInfo",
    "ToolTranscript",
    "TrustRecord",
    "RevocationStore",
    "SCHEMA",
    "iter_errors",
    "validate_json",
    "generate_key",
    "jwk_thumbprint",
    "key_to_jwk",
    "load_key",
    "load_signing_key",
    "sign_record",
    "verify_record",
]
