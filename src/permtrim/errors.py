"""Provider-neutral exception hierarchy for permtrim.

Every failure raised by a collector is translated into one of these
exceptions, so upper layers (CLI, analyzer, graph, LLM) never need to
know about provider SDK internals such as ``botocore.ClientError``.
"""

from __future__ import annotations

__all__ = [
    "PermTrimError",
    "CollectorError",
    "CollectorConfigError",
    "AuthenticationError",
    "ThrottlingError",
    "ProviderNotSupportedError",
    "CollectorOperationError",
]


class PermTrimError(Exception):
    """Base class for every error raised by permtrim."""


class CollectorError(PermTrimError):
    """Base class for data-collection failures."""


class CollectorConfigError(CollectorError):
    """Invalid configuration (bad profile, out-of-range parameters, ...)."""


class AuthenticationError(CollectorError):
    """Credentials were rejected by the provider, or missing permissions."""


class ThrottlingError(CollectorError):
    """Provider API kept throttling even after the configured retries."""


class ProviderNotSupportedError(CollectorError):
    """The requested cloud provider is unknown or not implemented yet."""


class CollectorOperationError(CollectorError):
    """A provider API call failed for a reason other than auth/throttling."""
