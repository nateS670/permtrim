"""Collector registry: the extension point for new cloud providers."""

from __future__ import annotations

from typing import TypeVar

from ..errors import ProviderNotSupportedError
from .aws_collector import AWSCollector
from .azure_collector import AzureCollector
from .base import BaseCollector, CollectorConfig

__all__ = ["create_collector", "SUPPORTED_PROVIDERS"]

T = TypeVar("T", bound=BaseCollector)

_REGISTRY: dict[str, type[BaseCollector]] = {
    AWSCollector.provider: AWSCollector,
    AzureCollector.provider: AzureCollector,
}
SUPPORTED_PROVIDERS: tuple[str, ...] = tuple(sorted(_REGISTRY))


def create_collector(provider: str, config: CollectorConfig | None = None) -> BaseCollector:
    """Instantiate the collector registered for ``provider``.

    Args:
        provider: Provider key: ``"aws"`` or ``"azure"``.
        config: Collector configuration matching the provider's class.

    Raises:
        ProviderNotSupportedError: Unknown or not-yet-implemented provider.

    Returns:
        A ready-to-use collector instance.
    """
    try:
        collector_cls = _REGISTRY[provider.lower()]
    except KeyError:
        raise ProviderNotSupportedError(
            f"Provider {provider!r} is not supported yet. Available: "
            f"{', '.join(SUPPORTED_PROVIDERS)} — see docs/roadmap.md."
        ) from None
    return collector_cls(config)  # type: ignore[call-arg, misc]
