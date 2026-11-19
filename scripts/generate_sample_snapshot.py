"""Generate data/sample_snapshot.json via the Stubber fixtures (no AWS needed).

Run from the repo root after `pip install -e ".[dev]"`:
    python scripts/generate_sample_snapshot.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
# Import the canned AWS responses from the test fixtures.
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "tests"))

from conftest import (  # noqa: E402
    FIXED_NOW,
    GET_CALLER_IDENTITY,
    RAW_EVENTS,
    REGION,
    WINDOW_END,
    WINDOW_START_30D,
    auth_details_payload,
    stub_client,
)
from permtrim.collectors import write_json_document  # noqa: E402
from permtrim.collectors.aws_collector import AWSCollector, AWSCollectorConfig  # noqa: E402

ADMIN_DOC_STRING = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
)


def main() -> None:
    collector = AWSCollector(AWSCollectorConfig(region=REGION, clock=lambda: FIXED_NOW))

    iam_client, iam_stubber = stub_client("iam")
    sts_client, sts_stubber = stub_client("sts")
    ct_client, ct_stubber = stub_client("cloudtrail")

    sts_stubber.add_response("get_caller_identity", GET_CALLER_IDENTITY, expected_params={})
    iam_stubber.add_response("get_account_authorization_details", auth_details_payload(), expected_params={})
    iam_stubber.add_response(
        "get_policy",
        {
            "Policy": {
                "PolicyName": "AdministratorAccess",
                "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "DefaultVersionId": "v1",
            }
        },
        expected_params={"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    iam_stubber.add_response(
        "get_policy_version",
        {"PolicyVersion": {"Document": ADMIN_DOC_STRING, "VersionId": "v1", "IsDefaultVersion": True}},
        expected_params={"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "VersionId": "v1"},
    )
    ct_stubber.add_response(
        "lookup_events",
        {"Events": RAW_EVENTS},
        expected_params={"StartTime": WINDOW_START_30D, "EndTime": WINDOW_END, "MaxResults": 50},
    )

    # Same wiring the unit tests use: pre-seed the client cache with stubs.
    collector._client_cache["sts"] = sts_client
    collector._client_cache["iam"] = iam_client
    collector._client_cache["cloudtrail"] = ct_client
    sts_stubber.activate()
    iam_stubber.activate()
    ct_stubber.activate()

    document = collector.collect(lookback_days=30)
    target = write_json_document(document, _REPO_ROOT / "data" / "sample_snapshot.json")
    print(f"sample snapshot written -> {target}")


if __name__ == "__main__":
    main()
