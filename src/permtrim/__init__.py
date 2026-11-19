"""permtrim — LLM-powered multi-cloud IAM least-privilege detector.

Static IAM snapshots and audit-log activity are collected per provider,
merged into a unified JSON schema, and later fed to a permission analyzer,
a graph database and an LLM that produces tightened Terraform.
"""

from . import errors, models
from .collectors import (
    SUPPORTED_PROVIDERS,
    AWSCollector,
    AWSCollectorConfig,
    BaseCollector,
    CollectorConfig,
    create_collector,
    write_json_document,
)

__version__ = "1.0.0"

__all__ = [
    "errors",
    "models",
    "AWSCollector",
    "AWSCollectorConfig",
    "BaseCollector",
    "CollectorConfig",
    "SUPPORTED_PROVIDERS",
    "create_collector",
    "write_json_document",
    "__version__",
]
