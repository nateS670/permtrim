"""Generate the bundled Azure sample snapshot (data/sample_azure_snapshot.json).

Runs the REAL collector pipeline over the mock SDK fixtures (the same
azure_fixtures used by the test suite): fake clients return genuine
azure-mgmt model instances, so the produced document is exactly what a live
collection would return for this topology. No Azure account required.

Regenerate after changing the fixtures:
    python scripts/make_azure_sample.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from azure_fixtures import (  # noqa: E402
    GUID_ZEYNEP,
    FakeAuthorizationClient,
    FakeMonitorClient,
    StaticPrincipalResolverMapping,
)
from permtrim.collectors.azure_collector import (  # noqa: E402
    AzureCollector,
    AzureCollectorConfig,
)
from permtrim.collectors.base import write_json_document  # noqa: E402


def main() -> int:
    config = AzureCollectorConfig(
        subscription_id="00000000-1111-2222-3333-444444444444",
        clock=lambda: __import__("azure_fixtures").FIXED_NOW,
        default_lookback_days=30,
    )
    collector = AzureCollector(
        config,
        authorization_client=FakeAuthorizationClient(),
        monitor_client=FakeMonitorClient(),
        principal_resolver=StaticPrincipalResolverMapping(),
        group_memberships=lambda oid: ["platform-team"] if oid == GUID_ZEYNEP else [],
    )
    document = collector.collect()

    target = ROOT / "src" / "permtrim" / "data" / "sample_azure_snapshot.json"
    write_json_document(document, target)

    counts = {
        "principals": len(document["principals"]),
        "users": sum(1 for p in document["principals"] if p["kind"] == "user"),
        "roles": sum(1 for p in document["principals"] if p["kind"] == "role"),
        "groups": sum(1 for p in document["principals"] if p["kind"] == "group"),
        "usage_principals": len(document["activity"]["usage"]),
        "unmatched": len(document["unmatched_activity"]),
    }
    print(f"wrote {target}")
    print(f"  {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
