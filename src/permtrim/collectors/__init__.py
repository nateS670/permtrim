"""Cloud provider collectors.

Public surface: :func:`create_collector` plus the base/impl classes needed
to add a new provider (see :mod:`permtrim.collectors.base`).
"""

from .aws_collector import AWSCollector, AWSCollectorConfig
from .azure_collector import (
    AzureCollector,
    AzureCollectorConfig,
    StaticPrincipalResolver,
)
from .base import BaseCollector, CollectorConfig, write_json_document
from .factory import SUPPORTED_PROVIDERS, create_collector

__all__ = [
    "AWSCollector",
    "AWSCollectorConfig",
    "AzureCollector",
    "AzureCollectorConfig",
    "StaticPrincipalResolver",
    "BaseCollector",
    "CollectorConfig",
    "write_json_document",
    "create_collector",
    "SUPPORTED_PROVIDERS",
]
