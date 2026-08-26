"""Package-level invariants: version and spec-profile identifiers."""

from importlib.metadata import version as dist_version

import agentrust_trace
from agentrust_trace import SCHEMA
from agentrust_trace.models import TrustRecord

EAT_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"


def test_version_matches_distribution_metadata() -> None:
    """``__version__`` must track the version in ``pyproject.toml``.

    The two drifted once (the module said 0.2.0 while the published distribution
    was 0.5.1), which makes a bug report citing ``agentrust_trace.__version__``
    point at the wrong release.
    """
    assert agentrust_trace.__version__ == dist_version("agentrust-trace")


def test_schema_and_model_agree_on_eat_profile() -> None:
    """The wire profile URI is fixed by the spec; both validators must require it."""
    assert SCHEMA["properties"]["eat_profile"]["const"] == EAT_PROFILE
    field = TrustRecord.model_fields["eat_profile"]
    assert field.annotation.__args__ == (EAT_PROFILE,)  # type: ignore[union-attr]
