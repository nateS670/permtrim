"""AWS collector: static IAM snapshot + CloudTrail activity (Task 1).

Pipeline
--------
1. **Static side** — one atomic read of the account via IAM
   ``get_account_authorization_details`` (users, roles, groups, customer-managed
   policies with their default-version documents), followed by on-demand
   ``get_policy`` / ``get_policy_version`` calls for attached *AWS-managed*
   policies, whose documents are not part of the authorization-details
   response.
2. **Dynamic side** — ``cloudtrail.lookup_events`` over the requested window;
   every event is normalized into ``(principal, service:action, is_error)``.
   Assumed-role sessions are folded back onto the IAM *role* entity so that
   usage joins the static snapshot by role name.
3. **Merge** — performed by :meth:`BaseCollector._assemble_unified`, producing
   the provider-neutral JSON consumed by the analyzer / graph / LLM stages.

Operational limits of ``lookup_events`` (constraints of the AWS API itself)
--------------------------------------------------------------------------
* History is limited to the **last 90 days** → ``lookback_days`` must be <= 90.
  Longer windows require a CloudTrail → S3 → Athena pipeline (planned seam:
  :meth:`_fetch_lookup_events`).
* At most **10,000 events** are returned → the result is marked
  ``window.truncated = true`` when the cap is hit. NOTE: ``truncated=false``
  only means the event-count cap was not hit — it is NOT a completeness
  guarantee (see the data-events point below).
* Event history is **regional** → one collector instance queries one region;
  instantiate per region and merge for multi-region coverage.
* ``lookup_events`` searches **management events only**. Data-plane actions
  (``s3:GetObject``, Lambda invokes, DynamoDB item ops, QLDB) are NEVER
  returned by this API — not even when a trail records data events (those go
  to S3 / CloudTrail Lake, a different pipeline). The analyzer therefore
  treats unused-looking data-plane grants as *unknown usage* rather than
  confirmed excess, and the tightener stops for principals holding them
  (see ``PrincipalFinding.unknown_usage_actions``).
* Events lag ~15 minutes behind → a safety buffer is subtracted from ``end``.

Required IAM permissions (read-only)
------------------------------------
``sts:GetCallerIdentity``, ``iam:GetAccountAuthorizationDetails``,
``iam:GetPolicy``, ``iam:GetPolicyVersion``, ``cloudtrail:LookupEvents``
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import boto3
from botocore.client import BaseClient
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)

from ..errors import (
    AuthenticationError,
    CollectorConfigError,
    CollectorError,
    CollectorOperationError,
    ThrottlingError,
)
from ..models.activity import (
    ActivityEvent,
    ActivityLog,
    ActivityWindow,
    PrincipalKind,
    PrincipalRef,
    summarize_usage,
)
from ..models.iam import (
    IAMGroup,
    IAMRole,
    IaMSnapshot,
    IAMUser,
    ManagedPolicy,
    ManagedPolicyRef,
    PolicyKind,
)
from .base import BaseCollector, CollectorConfig

__all__ = ["AWSCollectorConfig", "AWSCollector"]

LOGGER = logging.getLogger(__name__)

CLOUDTRAIL_MAX_LOOKBACK_DAYS = 90
"""lookup_events only covers the last 90 days of event history."""

CLOUDTRAIL_EVENT_CAP = 10_000
"""lookup_events returns at most 10,000 events per query."""

LOOKUP_PAGE_SIZE = 50
"""lookup_events MaxResults upper bound is 50."""

CLOUDTRAIL_INGESTION_LAG = timedelta(minutes=15)
"""Safety buffer subtracted from the window end (event ingestion delay)."""

_AUTH_ERROR_CODES = frozenset(
    {
        "AuthFailure",
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "SignatureDoesNotMatch",
        "MissingAuthenticationToken",
        "AccessDenied",
    }
)
_THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "PriorRequestNotComplete",
        "ProvisionedThroughputExceededException",
    }
)


# --------------------------------------------------------------------------- #
# Module-level helpers (pure functions — easy to unit-test in isolation)
# --------------------------------------------------------------------------- #


def _parse_iso_utc(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp (CloudTrail ``eventTime`` style) to aware UTC.

    Handles the ``Z`` suffix on Python versions where ``fromisoformat``
    does not (>= 3.10 support matrix) and treats naive input as UTC.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _service_from_event_source(event_source: str) -> str:
    """Map a CloudTrail ``eventSource`` (``s3.amazonaws.com``) to a service prefix (``s3``)."""
    source = event_source.strip().lower()
    for suffix in (".amazonaws.com.cn", ".amazonaws.com"):
        if source.endswith(suffix):
            return source[: -len(suffix)]
    return source.split(".", 1)[0]


def _resource_name_from_arn(arn: Any) -> str | None:
    """Extract the entity name from an IAM/STS ARN (last path segment)."""
    if not isinstance(arn, str) or not arn:
        return None
    resource = arn.split(":", 5)[-1]  # e.g. "user/path/alice", "assumed-role/Role/Session"
    name = resource.rsplit("/", 1)[-1]
    return name or None


def _session_name_from_identity(user_identity: dict[str, Any]) -> str | None:
    """Best-effort session name for temporary credentials (assumed-role / federated)."""
    arn = user_identity.get("arn")
    if isinstance(arn, str) and "/" in arn:
        tail = arn.rsplit("/", 1)[-1]
        if tail:
            return tail
    principal_id = user_identity.get("principalId")
    if isinstance(principal_id, str) and ":" in principal_id:
        tail = principal_id.rsplit(":", 1)[-1]
        if tail:
            return tail
    return None


def _coerce_bool(value: Any) -> bool | None:
    """Normalize truthy API fields (CloudTrail sends ``"true"``/``"false"`` strings)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def _coerce_policy_document(raw: Any, context: str) -> dict[str, Any] | None:
    """Normalize an IAM policy document as returned by the AWS API.

    boto3 hands policy documents back either as a parsed ``dict`` (most
    modern APIs) or as a string — occasionally URL-encoded, e.g.
    ``get_policy_version``. All three shapes are handled here; anything
    else logs a warning and yields ``None`` so the caller can mark the
    policy as ``document_status: unavailable`` instead of failing the
    whole snapshot.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        text = urllib.parse.unquote(raw).strip()
        if not text:
            LOGGER.warning("Empty policy document for %s", context)
            return None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            LOGGER.warning("Malformed policy document JSON for %s: %s", context, exc)
            return None
        if isinstance(parsed, dict):
            return parsed
    LOGGER.warning("Unrecognized policy document shape for %s (type=%s)", context, type(raw).__name__)
    return None


def _policy_kind_for_arn(arn: str) -> PolicyKind:
    """Classify a policy ARN as AWS-managed (``arn:...:iam::aws:policy/...``) or customer-managed."""
    parts = arn.split(":", 5)
    if len(parts) >= 5 and parts[4] == "aws":
        return PolicyKind.AWS_MANAGED
    return PolicyKind.CUSTOMER_MANAGED


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass
class AWSCollectorConfig(CollectorConfig):
    """Settings for :class:`AWSCollector`.

    Attributes:
        region: Query region. CloudTrail event history is regional, so one
            collector instance covers one region.
        profile: Named AWS profile; ``None`` uses the default chain
            (environment, ``~/.aws/credentials``, instance role, ...).
        endpoint_url: Custom endpoint (useful for LocalStack in dev).
        max_events: Stop after this many CloudTrail events (service cap 10k).
        lookup_page_size: Page size for ``lookup_events`` (1..50).
        request_timeout_s: Per-request connect/read timeout.
        max_attempts: Total attempts per call for botocore adaptive retries.
    """

    region: str | None = None
    profile: str | None = None
    endpoint_url: str | None = None
    max_events: int = CLOUDTRAIL_EVENT_CAP
    lookup_page_size: int = LOOKUP_PAGE_SIZE
    request_timeout_s: int = 30
    max_attempts: int = 8

    def __post_init__(self) -> None:
        if not 1 <= self.default_lookback_days <= CLOUDTRAIL_MAX_LOOKBACK_DAYS:
            raise CollectorConfigError(
                f"default_lookback_days must be within 1..{CLOUDTRAIL_MAX_LOOKBACK_DAYS} "
                f"(CloudTrail lookup_events history limit); got {self.default_lookback_days}"
            )
        if not 1 <= self.lookup_page_size <= 50:
            raise CollectorConfigError(
                f"lookup_page_size must be within 1..50 (LookupEvents MaxResults bound); "
                f"got {self.lookup_page_size}"
            )
        if self.max_events < 1:
            raise CollectorConfigError(f"max_events must be >= 1; got {self.max_events}")
        if self.request_timeout_s <= 0:
            raise CollectorConfigError(f"request_timeout_s must be > 0; got {self.request_timeout_s}")
        if self.max_attempts < 1:
            raise CollectorConfigError(f"max_attempts must be >= 1; got {self.max_attempts}")


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #


class AWSCollector(BaseCollector):
    """AWS implementation of the collector contract (static IAM + CloudTrail)."""

    provider: ClassVar[str] = "aws"

    def __init__(self, config: AWSCollectorConfig | None = None) -> None:
        super().__init__(config or AWSCollectorConfig())
        # Narrowing helper: base stores CollectorConfig, we always receive the AWS subclass.
        self._aws_config: AWSCollectorConfig = self._config  # type: ignore[assignment]
        self._session: boto3.Session | None = None
        self._client_cache: dict[str, BaseClient] = {}
        self._account: dict[str, str] | None = None

    # ------------------------------------------------------------- plumbing

    def _make_session(self) -> boto3.Session:
        """Create the boto3 session from the configured profile/region."""
        return boto3.Session(profile_name=self._aws_config.profile, region_name=self._aws_config.region)

    def _client(self, service: str) -> BaseClient:
        """Return a (cached) boto3 client for ``service``.

        Clients are lazily created and injected via ``_client_cache`` in
        tests (botocore Stubber), which is why creation lives in a single
        chokepoint.
        """
        if service not in self._client_cache:
            if self._session is None:
                self._session = self._make_session()
            botocore_config = BotocoreConfig(
                retries={"max_attempts": self._aws_config.max_attempts, "mode": "adaptive"},
                connect_timeout=self._aws_config.request_timeout_s,
                read_timeout=self._aws_config.request_timeout_s,
            )
            try:
                self._client_cache[service] = self._session.client(
                    service,
                    endpoint_url=self._aws_config.endpoint_url,
                    config=botocore_config,
                )
            except ProfileNotFound as exc:
                raise CollectorConfigError(
                    f"AWS profile {self._aws_config.profile!r} not found — check the "
                    "profile name in ~/.aws/config or run 'aws configure'."
                ) from exc
            except NoRegionError as exc:
                raise CollectorConfigError(
                    "No AWS region configured — pass AWSCollectorConfig(region=...) "
                    "or set AWS_DEFAULT_REGION."
                ) from exc
        return self._client_cache[service]

    def _call_api(self, operation: str, service: str, **kwargs: Any) -> dict[str, Any]:
        """Invoke a boto3 operation with uniform error translation.

        Raises:
            AuthenticationError: credentials rejected or missing permissions.
            ThrottlingError: rate-limited even after adaptive retries.
            CollectorConfigError: unusable configuration (no region, ...).
            CollectorOperationError: any other provider-side failure.
        """
        client = self._client(service)
        self._log.debug("%s.%s(%s)", service, operation, kwargs)
        try:
            return getattr(client, operation)(**kwargs)
        except ClientError as exc:
            raise self._translate_client_error(exc, operation) from exc
        except NoCredentialsError as exc:
            raise AuthenticationError(
                f"No AWS credentials found for {operation!r} — run 'aws configure', "
                "set AWS_PROFILE, or attach an instance role."
            ) from exc
        except NoRegionError as exc:
            raise CollectorConfigError(
                f"No AWS region configured for {operation!r} — pass "
                "AWSCollectorConfig(region=...) or set AWS_DEFAULT_REGION."
            ) from exc
        except BotoCoreError as exc:
            raise CollectorOperationError(f"AWS {operation!r} transport error: {exc}") from exc

    @staticmethod
    def _translate_client_error(exc: ClientError, operation: str) -> CollectorError:
        """Map a ``ClientError`` onto the provider-neutral hierarchy."""
        error = exc.response.get("Error", {})
        code = error.get("Code", "Unknown")
        message = error.get("Message", str(exc))
        detail = f"AWS API call {operation!r} failed ({code}): {message}"
        if code in _AUTH_ERROR_CODES:
            return AuthenticationError(detail)
        if code in _THROTTLE_CODES:
            return ThrottlingError(detail + " — adaptive retries exhausted")
        return CollectorOperationError(detail)

    def _ensure_account_context(self) -> dict[str, str]:
        """Fetch (once) the caller identity: validates credentials early and
        provides the account ID that tags every snapshot."""
        if self._account is None:
            response = self._call_api("get_caller_identity", "sts")
            self._account = {
                "account_id": response["Account"],
                "arn": response["Arn"],
                "user_id": response["UserId"],
            }
            self._log.info(
                "Authenticated as %s (account %s)",
                self._account["arn"],
                self._account["account_id"],
            )
        return self._account

    # ------------------------------------------------------ BaseCollector API

    def collect_iam_snapshot(self) -> IaMSnapshot:
        """Fetch the static IAM state of the account.

        Uses a single ``get_account_authorization_details`` sweep (the same
        data source IAM Access Analyzer builds on) instead of per-identity
        list calls: one consistent snapshot, far fewer API round-trips.
        """
        account = self._ensure_account_context()
        pages = self._fetch_authorization_details()
        snapshot = self._build_iam_snapshot(pages, account)
        self._log.info(
            "IAM snapshot built: %d users, %d roles, %d groups, %d policies (%d fetched on demand)",
            len(snapshot.users),
            len(snapshot.roles),
            len(snapshot.groups),
            len(snapshot.policies),
            sum(
                1
                for p in snapshot.policies.values()
                if p.fetch_error is None and p.kind is PolicyKind.AWS_MANAGED
            ),
        )
        return snapshot

    def collect_activity(self, lookback_days: int | None = None) -> ActivityLog:
        """Fetch observed API activity from CloudTrail event history.

        Args:
            lookback_days: Window length; defaults to
                ``config.default_lookback_days``. Must be within 1..90.

        Returns:
            An :class:`ActivityLog` whose ``usage`` maps ``(kind, name)``
            principals to aggregated action counts.
        """
        days = lookback_days if lookback_days is not None else self._aws_config.default_lookback_days
        window = self._resolve_window(days)
        raw_events, truncated = self._fetch_lookup_events(window)
        window.truncated = truncated
        events: list[ActivityEvent] = []
        for raw in raw_events:
            parsed = self._parse_cloudtrail_event(raw)
            if parsed is not None:
                events.append(parsed)
        self._log.info(
            "CloudTrail: %d raw events, %d parsed, window %s..%s (truncated=%s)",
            len(raw_events),
            len(events),
            window.start.isoformat(),
            window.end.isoformat(),
            truncated,
        )
        return ActivityLog(window=window, events=events, usage=summarize_usage(events))

    def _provider_meta(self) -> dict[str, Any]:
        """Metadata block for the unified document."""
        account = self._ensure_account_context()
        region = self._aws_config.region or (self._session.region_name if self._session else None)
        return {
            "account_id": account["account_id"],
            "region": region,
            "collector_identity_arn": account["arn"],
        }

    # --------------------------------------------------------- IAM internals

    def _fetch_authorization_details(self) -> list[dict[str, Any]]:
        """Page through ``get_account_authorization_details`` (manual marker loop)."""
        pages: list[dict[str, Any]] = []
        marker: str | None = None
        while True:
            kwargs: dict[str, Any] = {"Marker": marker} if marker else {}
            page = self._call_api("get_account_authorization_details", "iam", **kwargs)
            pages.append(page)
            marker = page.get("Marker") if page.get("IsTruncated") else None
            if not marker:
                return pages

    def _build_iam_snapshot(self, pages: list[dict[str, Any]], account: dict[str, str]) -> IaMSnapshot:
        """Map authorization-details pages onto the neutral IAM models."""
        users: list[IAMUser] = []
        roles: list[IAMRole] = []
        groups: list[IAMGroup] = []
        policies: dict[str, ManagedPolicy] = {}

        for page in pages:
            for user_detail in page.get("UserDetailList", []):
                users.append(self._map_user(user_detail))
            for role_detail in page.get("RoleDetailList", []):
                roles.append(self._map_role(role_detail))
            for group_detail in page.get("GroupDetailList", []):
                groups.append(self._map_group(group_detail))
            for policy_detail in page.get("Policies", []):
                policy = self._map_customer_policy(policy_detail)
                policies[policy.arn] = policy

        # AWS-managed attachments are not part of authorization details;
        # fetch their documents on demand (degrade gracefully on failure).
        identities: list[IAMUser | IAMRole | IAMGroup] = [*users, *roles, *groups]
        aws_managed_arns = {
            ref.arn
            for identity in identities
            for ref in identity.attached_policies
            if ref.kind is PolicyKind.AWS_MANAGED and ref.arn not in policies
        }
        if aws_managed_arns:
            self._log.info("Fetching %d AWS-managed policy documents on demand", len(aws_managed_arns))
            for arn in sorted(aws_managed_arns):
                policies[arn] = self._fetch_aws_managed_policy(arn)

        # Cross-reference attachments so the catalog knows who uses each policy.
        for identity in identities:
            for ref in identity.attached_policies:
                catalog_entry = policies.get(ref.arn)
                if catalog_entry is not None and identity.name not in catalog_entry.attached_to:
                    catalog_entry.attached_to.append(identity.name)

        return IaMSnapshot(
            account_id=account["account_id"],
            collector_identity_arn=account["arn"],
            collected_at=self._aws_config.clock(),
            users=users,
            roles=roles,
            groups=groups,
            policies=policies,
        )

    def _map_user(self, detail: dict[str, Any]) -> IAMUser:
        """Map one ``UserDetailList`` entry."""
        name = detail["UserName"]
        inline = self._map_inline_policies(detail.get("UserPolicyList", []), f"user {name!r}")
        attached = self._map_attachments(detail.get("AttachedManagedPolicies", []))
        return IAMUser(
            name=name,
            arn=detail["Arn"],
            path=detail.get("Path", ""),
            created_at=detail.get("CreateDate"),
            groups=list(detail.get("GroupList", [])),
            inline_policies=inline,
            attached_policies=attached,
            permission_boundary_arn=(detail.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
            tags=self._map_tags(detail.get("Tags", [])),
        )

    def _map_role(self, detail: dict[str, Any]) -> IAMRole:
        """Map one ``RoleDetailList`` entry."""
        name = detail["RoleName"]
        trust = (
            _coerce_policy_document(detail.get("AssumeRolePolicyDocument"), f"trust policy of role {name!r}")
            or {}
        )
        inline = self._map_inline_policies(detail.get("RolePolicyList", []), f"role {name!r}")
        attached = self._map_attachments(detail.get("AttachedManagedPolicies", []))
        return IAMRole(
            name=name,
            arn=detail["Arn"],
            path=detail.get("Path", ""),
            created_at=detail.get("CreateDate"),
            trust_policy=trust,
            inline_policies=inline,
            attached_policies=attached,
            permission_boundary_arn=(detail.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
            max_session_duration=detail.get("MaxSessionDuration"),
            tags=self._map_tags(detail.get("Tags", [])),
        )

    def _map_group(self, detail: dict[str, Any]) -> IAMGroup:
        """Map one ``GroupDetailList`` entry."""
        name = detail["GroupName"]
        inline = self._map_inline_policies(detail.get("GroupPolicyList", []), f"group {name!r}")
        attached = self._map_attachments(detail.get("AttachedManagedPolicies", []))
        return IAMGroup(
            name=name,
            arn=detail["Arn"],
            created_at=detail.get("CreateDate"),
            inline_policies=inline,
            attached_policies=attached,
        )

    @staticmethod
    def _map_inline_policies(entries: list[dict[str, Any]], context: str) -> dict[str, dict[str, Any]]:
        """Map ``InlinePolicies`` entries to ``{name: document}``."""
        inline: dict[str, dict[str, Any]] = {}
        for entry in entries:
            name = entry.get("PolicyName")
            if not name:
                continue
            document = _coerce_policy_document(
                entry.get("PolicyDocument"), f"inline policy {name!r} of {context}"
            )
            if document is not None:
                inline[name] = document
        return inline

    @staticmethod
    def _map_attachments(entries: list[dict[str, Any]]) -> list[ManagedPolicyRef]:
        """Map ``AttachedManagedPolicies`` entries to refs (documents resolved later)."""
        return [
            ManagedPolicyRef(
                name=entry["PolicyName"],
                arn=entry["PolicyArn"],
                kind=_policy_kind_for_arn(entry["PolicyArn"]),
            )
            for entry in entries
            if entry.get("PolicyArn")
        ]

    @staticmethod
    def _map_tags(entries: list[dict[str, Any]]) -> dict[str, str]:
        """Map ``Tags`` entries to ``{key: value}``."""
        return {entry["Key"]: entry["Value"] for entry in entries if "Key" in entry}

    def _map_customer_policy(self, detail: dict[str, Any]) -> ManagedPolicy:
        """Map one ``Policies`` entry (customer-managed, all versions included)."""
        default_version_id = detail.get("DefaultVersionId")
        document: dict[str, Any] | None = None
        versions = detail.get("PolicyVersionList", [])
        chosen = next((v for v in versions if v.get("IsDefaultVersion")), None)
        if chosen is None and default_version_id:
            chosen = next((v for v in versions if v.get("VersionId") == default_version_id), None)
        if chosen is not None:
            document = _coerce_policy_document(
                chosen.get("Document"),
                f"customer-managed policy {detail.get('PolicyName')!r}",
            )
        if document is None:
            self._log.warning(
                "Customer-managed policy %s has no readable default document",
                detail.get("PolicyName"),
            )
        return ManagedPolicy(
            name=detail["PolicyName"],
            arn=detail["Arn"],
            kind=PolicyKind.CUSTOMER_MANAGED,
            default_version_id=default_version_id,
            document=document,
        )

    def _fetch_aws_managed_policy(self, arn: str) -> ManagedPolicy:
        """Fetch the default document of one AWS-managed policy (two API calls).

        A failure here degrades the document to ``None`` instead of failing
        the snapshot: the attachment itself is still recorded, and the
        analyzer can flag the policy as unverifiable.
        """
        try:
            policy_response = self._call_api("get_policy", "iam", PolicyArn=arn)
            policy = policy_response["Policy"]
            default_version_id = policy.get("DefaultVersionId")
            if not default_version_id:
                raise CollectorOperationError(f"policy {arn} has no default version")
            version_response = self._call_api(
                "get_policy_version", "iam", PolicyArn=arn, VersionId=default_version_id
            )
            document = _coerce_policy_document(
                version_response["PolicyVersion"].get("Document"),
                f"AWS-managed policy {arn}",
            )
            return ManagedPolicy(
                name=policy.get("PolicyName", arn.rsplit("/", 1)[-1]),
                arn=arn,
                kind=PolicyKind.AWS_MANAGED,
                default_version_id=default_version_id,
                document=document,
            )
        except CollectorError as exc:
            self._log.warning(
                "Could not fetch AWS-managed policy %s (%s: %s); recorded without document",
                arn,
                type(exc).__name__,
                exc,
            )
            return ManagedPolicy(
                name=arn.rsplit("/", 1)[-1],
                arn=arn,
                kind=PolicyKind.AWS_MANAGED,
                default_version_id=None,
                document=None,
                fetch_error=f"{type(exc).__name__}: {exc}",
            )

    # ---------------------------------------------------- CloudTrail internals

    def _resolve_window(self, days: int) -> ActivityWindow:
        """Build the lookup window, validating the 90-day history limit."""
        if not isinstance(days, int) or isinstance(days, bool):
            raise CollectorConfigError(f"lookback_days must be an int; got {type(days).__name__}")
        if not 1 <= days <= CLOUDTRAIL_MAX_LOOKBACK_DAYS:
            raise CollectorConfigError(
                f"lookback_days must be within 1..{CLOUDTRAIL_MAX_LOOKBACK_DAYS} "
                f"(CloudTrail lookup_events history limit); got {days}. For longer "
                "windows, read CloudTrail deliveries from S3 instead (planned)."
            )
        now = self._aws_config.clock()
        end = now - CLOUDTRAIL_INGESTION_LAG
        start = end - timedelta(days=days)
        return ActivityWindow(start=start, end=end, lookback_days=days)

    def _fetch_lookup_events(self, window: ActivityWindow) -> tuple[list[dict[str, Any]], bool]:
        """Page through ``lookup_events`` for the window.

        Returns:
            ``(raw_events, truncated)`` — ``truncated`` is ``True`` when
            ``config.max_events`` cut the scan short.
        """
        raw_events: list[dict[str, Any]] = []
        truncated = False
        next_token: str | None = None
        while True:
            kwargs: dict[str, Any] = {
                "StartTime": window.start,
                "EndTime": window.end,
                "MaxResults": self._aws_config.lookup_page_size,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            response = self._call_api("lookup_events", "cloudtrail", **kwargs)
            raw_events.extend(response.get("Events", []))
            next_token = response.get("NextToken")
            if not next_token:
                break
            if len(raw_events) >= self._aws_config.max_events:
                truncated = True
                break
        if len(raw_events) > self._aws_config.max_events:
            raw_events = raw_events[: self._aws_config.max_events]
            truncated = True
        if truncated:
            self._log.warning(
                "CloudTrail scan stopped at max_events=%d; results are truncated",
                self._aws_config.max_events,
            )
        truncated = truncated or bool(next_token)
        return raw_events, truncated

    def _parse_cloudtrail_event(self, raw: dict[str, Any]) -> ActivityEvent | None:
        """Normalize one ``lookup_events`` entry into an :class:`ActivityEvent`.

        Returns ``None`` (with a log line) for records that carry no
        principal action: non-API events (``AwsServiceEvent``), events
        missing a source/action, or events whose embedded JSON is corrupt.
        """
        raw_payload = raw.get("CloudTrailEvent")
        try:
            parsed = json.loads(raw_payload) if isinstance(raw_payload, str) else (raw_payload or {})
        except json.JSONDecodeError:
            self._log.warning("Corrupt CloudTrailEvent JSON (event id=%s)", raw.get("EventId"))
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}

        event_type = parsed.get("eventType")
        if event_type is not None and event_type != "AwsApiCall":
            self._log.debug("Skipping non-API event %s (eventType=%s)", raw.get("EventId"), event_type)
            return None

        event_source = (raw.get("EventSource") or parsed.get("eventSource") or "").strip()
        event_name = (raw.get("EventName") or parsed.get("eventName") or "").strip()
        if not event_source or not event_name:
            self._log.warning("Event %s has no source/action; skipped", raw.get("EventId"))
            return None

        event_time = raw.get("EventTime") or _parse_iso_utc(parsed.get("eventTime"))
        if event_time is None:
            self._log.warning("Event %s has no usable timestamp; skipped", raw.get("EventId"))
            return None
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        error_code = parsed.get("errorCode")
        is_error = bool(error_code or parsed.get("errorMessage"))
        service = _service_from_event_source(event_source)
        return ActivityEvent(
            event_id=raw.get("EventId"),
            time=event_time,
            principal=self._resolve_principal(parsed, raw.get("Username")),
            service=service,
            action=f"{service}:{event_name}",
            event_source=event_source,
            event_name=event_name,
            is_error=is_error,
            error_code=error_code if isinstance(error_code, str) else None,
            read_only=_coerce_bool(raw.get("ReadOnly")),
        )

    def _resolve_principal(self, parsed: dict[str, Any], fallback: str | None) -> PrincipalRef:
        """Derive a durable :class:`PrincipalRef` from a CloudTrail ``userIdentity``.

        Assumed-role sessions are attributed to the *role* (the analyzable
        entity); the ephemeral session name is kept in ``PrincipalRef.session``.
        ``fallback`` is the flat ``Username`` column of lookup_events, used
        when the embedded identity block is missing.
        """
        identity = parsed.get("userIdentity")
        if not isinstance(identity, dict):
            identity = {}
        identity_type = identity.get("type")
        account_id = identity.get("accountId") if isinstance(identity.get("accountId"), str) else None

        if identity_type == "IAMUser":
            name = (
                identity.get("userName")
                or _resource_name_from_arn(identity.get("arn"))
                or fallback
                or "unknown"
            )
            return PrincipalRef(PrincipalKind.USER, name, identity.get("arn"), None, account_id)

        if identity_type == "AssumedRole":
            issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
            role_arn = issuer.get("arn") or identity.get("arn")
            name = issuer.get("userName") or _resource_name_from_arn(role_arn) or fallback or "unknown"
            session = _session_name_from_identity(identity)
            return PrincipalRef(PrincipalKind.ROLE, name, role_arn, session, account_id)

        if identity_type == "Root":
            root_arn = identity.get("arn") or f"arn:aws:iam::{account_id}:root"
            return PrincipalRef(PrincipalKind.ROOT, "root", root_arn, None, account_id)

        if identity_type in {"FederatedUser", "SAMLUser", "OIDCUser"}:
            name = fallback or identity.get("userName") or "unknown"
            return PrincipalRef(
                PrincipalKind.FEDERATED,
                name,
                identity.get("arn"),
                _session_name_from_identity(identity),
                account_id,
            )

        name = (
            fallback
            or identity.get("userName")
            or _resource_name_from_arn(identity.get("arn"))
            or (identity.get("principalId") or "unknown")
        )
        return PrincipalRef(PrincipalKind.UNKNOWN, name, identity.get("arn"), None, account_id)
