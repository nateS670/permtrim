"""Analysis engine: permission-vs-usage deltas per principal (Task 2).

For every user/role in the unified snapshot the engine answers:
*Which concrete actions is this principal allowed, and which of those did it
actually use in the audit window?*

How the pieces fit together
---------------------------
* :class:`~permtrim.analyzer.matcher.PolicySet` evaluates statements (wildcards,
  NotAction, explicit Deny) for existence questions.
* For *counting* what a wildcard grants, IAM patterns are expanded against the
  bundled action dataset (:mod:`permtrim.analyzer.action_registry`) — ``ec2:*``
  becomes its ~550 concrete actions, each counted as granted.
* Group-inherited permissions are folded into each user's effective policy set
  (a user's permissions = own policies ∪ policies of its groups).
* Error-only usage (every observed call failed, e.g. ``AccessDenied``) does
  **not** count as working usage: those actions are reported as granted-but-
  non-functional, prime candidates for removal.

Resource/Condition elements are not evaluated (the audit view is
action-level); the tightened policies keep original Resource scoping where
known, and full-fidelity simulation is delegated to the Task 4 guardrail.

Risk score (0..100) prioritizes which principal to tighten first: idle
principals, breadth of unused permissions weighted by access level, wildcard
grants and permissions-management actions all add to it.
"""

from __future__ import annotations

import logging
from typing import Any

from ..models.activity import ActivityLog
from ..models.iam import IAMGroup, IAMRole, IaMSnapshot, IAMUser, ManagedPolicyRef
from .action_registry import ActionRegistry, load_default_registry
from .azure_registry import build_azure_registry
from .findings import AnalysisReport, GrantedAction, PrincipalFinding
from .matcher import PolicySet, Statement

__all__ = ["Analyzer", "AnalyzerConfig"]

LOGGER = logging.getLogger(__name__)

_WILDCARD_EXAMPLES_LIMIT = 5

# ---------------------------------------------------------------------------
# AWS data-plane classification (ACTION level — not service prefixes)
# ---------------------------------------------------------------------------
# CloudTrail records two event categories that matter here:
#
#   management events — control-plane APIs. Returned by ``lookup_events`` (the
#       collector's only activity source on AWS).
#   data events      — resource-level APIs (object reads/writes, queue
#       message send/receive, item-level DynamoDB access, Lambda invokes,
#       ...). NOT searchable via ``lookup_events``.
#
# So for a DATA-event action, absence of observed usage does NOT prove
# non-use: the analyzer must treat such grants as "unknown usage" instead of
# unused. For a MANAGEMENT-event action, ``lookup_events`` visibility makes
# absence of usage real evidence of non-use — they are analyzed (and can be
# removed) like any other unused grant. A blanket per-SERVICE rule cannot
# express this: S3 mixes object-level data events (GetObject) with bucket
# management events (CreateBucket), SNS mixes Publish with CreateTopic, etc.
#
# Classification is therefore three-valued and ACTION-level:
#
#   "data"         — documented CloudTrail data event
#   "management"   — documented management event
#   "unclassified" — lives in a service that mixes both categories but is in
#       neither list (new/obscure actions). Conservative default: treated
#       like a data event (unknown usage, never silently removed) AND
#       surfaced on ``PrincipalFinding.unclassified_actions`` so reviewers
#       can see exactly which actions the table could not classify.
#
# This is a CLASSIFICATION table, not a denial list: ``is_data_plane_action``
# is the single decision point, and the tightener stops for any principal
# whose data-plane grants have no observed usage. Adding entries here reduces
# review noise; an OUTDATED table errs on the safe side (unclassified grants
# default to data-plane), never to silent removal. CloudTrail Lake / S3
# data-event ingestion (planned) will lift the whole limitation.
#
# Transcribed (2026-11) from:
#   - CloudTrail User Guide, "Logging data events" (resource-type table)
#   - S3 User Guide, "Logging Amazon S3 API calls using AWS CloudTrail"
#     (per-resource-type Data APIs + the bucket-level management list)
#   - DynamoDB Developer Guide, "Logging DynamoDB API calls using CloudTrail"
#   - SQS / SNS Developer Guides, "Logging ... API calls using AWS CloudTrail"
#   - Lambda Developer Guide, "Logging Lambda API calls using CloudTrail"
#   - S3 Tables / S3 Vectors User Guides, "... information in CloudTrail"
# QLDB is deliberately ABSENT: it has no CloudTrail data events (all qldb:*
# calls are management events, visible to lookup_events).
_DATA = "data"
_MANAGEMENT = "management"
_UNCLASSIFIED = "unclassified"

# Services that contribute CloudTrail data events (from the resource-type
# table). Actions of every OTHER service are management events by definition.
_AWS_DATA_EVENT_SERVICES: frozenset[str] = frozenset(
    {
        "s3",
        "s3express",
        "s3-object-lambda",
        "s3tables",
        "s3vectors",
        "lambda",
        "dynamodb",
        "sns",
        "sqs",
        "ebs",
    }
)

# Services where EVERY action outside ``_AWS_DATA_EVENT_ACTIONS`` is a
# management event (the service documents a closed data-event set):
# Lambda logs only Invoke-family calls as data events and everything else as
# management events; the EBS direct APIs are all snapshot-block operations.
_AWS_MANAGEMENT_BY_DEFAULT_SERVICES: frozenset[str] = frozenset({"lambda", "ebs"})

_EMPTY: frozenset[str] = frozenset()

# Data-event actions per service, as IAM action names (lowercase). Entries
# that are CloudTrail event names rather than IAM actions (ListObjectsV2,
# UploadPart, ...) are harmless: they simply never match a policy action.
_AWS_DATA_EVENT_ACTIONS: dict[str, frozenset[str]] = {
    # S3 object-level operations (AWS::S3::Object) + the Object Lambda and
    # Access Point variants, mapped onto IAM action names. Note ListBucket:
    # the underlying APIs (ListObjects / ListObjectsV2 / ListObjectVersions /
    # ListParts / HeadBucket) ARE data events. Versioned object operations
    # are included (object plane); s3:CreateBucket and friends are NOT here.
    "s3": frozenset(
        {
            "abortmultipartupload",
            "bypassgovernanceretention",  # only exercised via data-event calls
            "completemultipartupload",
            "copyobject",
            "createmultipartupload",
            "deleteobject",
            "deleteobjecttagging",
            "deleteobjectversion",
            "deleteobjectversiontagging",
            "deleteobjects",
            "getobject",
            "getobjectacl",
            "getobjectannotation",
            "getobjectattributes",
            "getobjectlegalhold",
            "getobjectretention",
            "getobjecttagging",
            "getobjecttorrent",
            "getobjectversion",
            "getobjectversionacl",
            "getobjectversionattributes",
            "getobjectversionforreplication",
            "getobjectversiontagging",
            "getobjectversiontorrent",
            "headbucket",  # doc note: supported as an S3 data event
            "headobject",
            "initiatereplication",  # batch replication data movement
            "listbucket",  # ListObjects / ListObjectsV2 / HeadBucket APIs
            "listbucketversions",  # ListObjectVersions API
            "listmultipartuploadparts",  # ListParts API
            "listobjectversions",
            "listobjects",
            "listobjectsv2",
            "listparts",
            "objectowneroverridetobucketowner",
            "pausereplication",
            "putobject",
            "putobjectacl",
            "putobjectannotation",
            "putobjectlegalhold",
            "putobjectretention",
            "putobjecttagging",
            "putobjectversionacl",
            "putobjectversiontagging",
            "replicatedelete",
            "replicateobject",
            "replicatetags",
            "restoreobject",
            "selectobjectcontent",
            "updateobjectencryption",
            "uploadpart",
            "uploadpartcopy",
        }
    ),
    # Directory buckets: object APIs are session-gated; CreateSession IS the
    # data-plane entry point (listed under AWS::S3Express::Object data APIs).
    "s3express": frozenset({"createsession"}),
    # Calls THROUGH an Object Lambda access point (AWS::S3ObjectLambda::
    # AccessPoint data APIs). Versioned ops are not offered by OLAPs — they
    # stay unclassified (conservative) rather than guessed.
    "s3-object-lambda": frozenset(
        {
            "abortmultipartupload",
            "deleteobject",
            "deleteobjecttagging",
            "getobject",
            "getobjectacl",
            "getobjectlegalhold",
            "getobjectretention",
            "getobjecttagging",
            "listbucket",
            "listbucketmultipartuploads",
            "listbucketversions",
            "listmultipartuploadparts",
            "putobject",
            "putobjectacl",
            "putobjectlegalhold",
            "putobjectretention",
            "putobjecttagging",
            "restoreobject",
            "writegetobjectresponse",
        }
    ),
    # S3 Tables: the Iceberg catalog data path (AWS::S3Tables::Table);
    # metadata-location and all config/policy ops are management events.
    "s3tables": frozenset({"gettabledata", "puttabledata"}),
    # S3 Vectors: vector-data APIs on an index (AWS::S3Vectors::Index);
    # bucket/index config and policy ops are management events.
    "s3vectors": frozenset({"deletevectors", "getvectors", "listvectors", "putvectors", "queryvectors"}),
    # Lambda execution plane. The docs table lists only Invoke; the other
    # invoke variants are the same execution plane and stay on the safe side.
    "lambda": frozenset(
        {
            "invokeasync",
            "invokefunction",
            "invokefunctionurl",
            "invokewithresponsestream",
        }
    ),
    # DynamoDB item-level APIs (AWS::DynamoDB::Table) + Streams
    # (AWS::DynamoDB::Stream). ConditionCheckItem and the legacy PartiQL
    # single-statement actions are not in the docs table but are item-level
    # activity — kept on the safe side. Replication data movement likewise.
    "dynamodb": frozenset(
        {
            "batchexecutestatement",
            "batchgetitem",
            "batchwriteitem",
            "conditioncheckitem",
            "deleteitem",
            "executestatement",
            "executetransaction",
            "getitem",
            "getrecords",
            "getsharditerator",
            "partiqldelete",
            "partiqlinsert",
            "partiqlselect",
            "partiqlupdate",
            "putitem",
            "query",
            "readdataforreplication",
            "scan",
            "searchvectors",
            "transactgetitems",
            "transactwriteitems",
            "updateitem",
            "writedataforreplication",
        }
    ),
    "sns": frozenset({"publish", "publishbatch"}),
    # SQS message activity (AWS::SQS::Queue data APIs).
    "sqs": frozenset(
        {
            "changemessagevisibility",
            "changemessagevisibilitybatch",
            "deletemessage",
            "deletemessagebatch",
            "getqueueattributes",
            "getqueueurl",
            "listdeadlettersourcequeues",
            "listqueues",
            "listqueuetags",
            "receivemessage",
            "sendmessage",
            "sendmessagebatch",
        }
    ),
    # EBS direct APIs (AWS::EC2::Snapshot) — the whole service is
    # snapshot-block data operations.
    "ebs": frozenset(
        {
            "completesnapshot",
            "getsnapshotblock",
            "listchangedblocks",
            "listsnapshotblocks",
            "putsnapshotblock",
            "startsnapshot",
        }
    ),
}

# KNOWN management-event actions for the services that ALSO have data events
# (from the same docs, control-plane lists). Actions of these services that
# are in neither table classify as "unclassified" (conservative data-plane).
_AWS_MANAGEMENT_EVENT_ACTIONS: dict[str, frozenset[str]] = {
    "s3": frozenset(
        {
            # bucket-level operations (official CloudTrail management list)
            "createbucket",
            "createbucketmetadataconfiguration",
            "createbucketmetadatatableconfiguration",
            "deletebucket",
            "deletebucketanalyticsconfiguration",
            "deletebucketcors",
            "deletebucketencryption",
            "deletebucketintelligenttieringconfiguration",
            "deletebucketinventoryconfiguration",
            "deletebucketlifecycle",
            "deletebucketmetadataconfiguration",
            "deletebucketmetadatatableconfiguration",
            "deletebucketmetricsconfiguration",
            "deletebucketownershipcontrols",
            "deletebucketpolicy",
            "deletebucketpublicaccessblock",
            "deletebucketreplication",
            "deletebuckettagging",
            "getaccelerateconfiguration",
            "getbucketacl",
            "getbucketanalyticsconfiguration",
            "getbucketcors",
            "getbucketencryption",
            "getbucketintelligenttieringconfiguration",
            "getbucketinventoryconfiguration",
            "getbucketlifecycle",
            "getbucketlocation",
            "getbucketlogging",
            "getbucketmetadataconfiguration",
            "getbucketmetadatatableconfiguration",
            "getbucketmetricsconfiguration",
            "getbucketnotification",
            "getbucketobjectlockconfiguration",
            "getbucketownershipcontrols",
            "getbucketpolicy",
            "getbucketpolicystatus",
            "getbucketpublicaccessblock",
            "getbucketreplication",
            "getbucketrequestpayment",
            "getbuckettagging",
            "getbucketversioning",
            "getbucketwebsite",
            "listallmybuckets",  # ListBuckets API
            "listbuckets",
            "putaccelerateconfiguration",
            "putbucketacl",
            "putbucketanalyticsconfiguration",
            "putbucketcors",
            "putbucketencryption",
            "putbucketintelligenttieringconfiguration",
            "putbucketinventoryconfiguration",
            "putbucketlifecycle",
            "putbucketlogging",
            "putbucketmetricsconfiguration",
            "putbucketnotification",
            "putbucketobjectlockconfiguration",
            "putbucketownershipcontrols",
            "putbucketpolicy",
            "putbucketpublicaccessblock",
            "putbucketreplication",
            "putbucketrequestpayment",
            "putbuckettagging",
            "putbucketversioning",
            "putbucketwebsite",
            "updatebucketmetadataannotationtableconfiguration",
            "updatebucketmetadatainventorytableconfiguration",
            "updatebucketmetadatajournaltableconfiguration",
            # access point / Object Lambda access point configuration
            "createaccesspoint",
            "createaccesspointforobjectlambda",
            "deleteaccesspoint",
            "deleteaccesspointforobjectlambda",
            "deleteaccesspointpolicy",
            "deleteaccesspointpolicyforobjectlambda",
            "getaccesspoint",
            "getaccesspointpolicy",
            "getaccesspointpolicyforobjectlambda",
            "getaccesspointpolicystatus",
            "getaccesspointpolicystatusforobjectlambda",
            "listaccesspoints",
            "listaccesspointsforobjectlambda",
            "putaccesspointpolicy",
            "putaccesspointpolicyforobjectlambda",
            # access grants configuration (GetDataAccess stays unclassified —
            # not documented as a data event in the sources above)
            "associateaccessgrantsidentitycenter",
            "createaccessgrant",
            "createaccessgrantsinstance",
            "createaccessgrantslocation",
            "deleteaccessgrant",
            "deleteaccessgrantsinstance",
            "deleteaccessgrantsinstanceresourcepolicy",
            "deleteaccessgrantslocation",
            "dissociateaccessgrantsidentitycenter",
            "getaccessgrant",
            "getaccessgrantsinstance",
            "getaccessgrantsinstanceforprefix",
            "getaccessgrantsinstanceidentitycenterconfiguration",
            "getaccessgrantsinstanceresourcepolicy",
            "getaccessgrantslocation",
            "listaccessgrants",
            "listaccessgrantsinstances",
            "listaccessgrantslocations",
            "listaccessgrantsresourceregistrations",
            "listcalleraccessgrants",
            "putaccessgrantsinstanceresourcepolicy",
            "updateaccessgrantslocation",
            # multi-region access points
            "createmultiregionaccesspoint",
            "deletemultiregionaccesspoint",
            "describemultiregionaccesspointoperation",
            "getmultiregionaccesspoint",
            "getmultiregionaccesspointpolicy",
            "getmultiregionaccesspointpolicystatus",
            "getmultiregionaccesspointroutes",
            "listmultiregionaccesspoints",
            "putmultiregionaccesspointpolicy",
            "submitmultiregionaccesspointroutes",
            # Storage Lens / batch jobs / account-level config
            "createstoragelensconfiguration",
            "createstoragelensgroup",
            "deletestoragelensconfiguration",
            "deletestoragelensconfigurationtagging",
            "deletestoragelensgroup",
            "getstoragelensconfiguration",
            "getstoragelensconfigurationtagging",
            "getstoragelensdashboard",
            "getstoragelensgroup",
            "listbucketmultipartuploads",  # ListMultipartUploads API (bucket-level)
            "liststoragelensconfigurations",
            "liststoragelensgroups",
            "putstoragelensconfiguration",
            "putstoragelensconfigurationtagging",
            "putstoragelensgroup",
            "updatestoragelensgroup",
            "createjob",
            "deletejobtagging",
            "describejob",
            "getjobtagging",
            "listjobs",
            "putjobtagging",
            "updatejobpriority",
            "updatejobstatus",
            "deleteaccountpublicaccessblock",
            "getaccountpublicaccessblock",
            "putaccountpublicaccessblock",
            "deletebucketwebsite",
            "getaccesspointconfigurationforobjectlambda",
            "getaccesspointforobjectlambda",
            "getanalyticsconfiguration",
            "getbucketabac",
            # getdataaccess (the access-grants credential exchange) is NOT in
            # either table — it classifies as "unclassified" and defaults to
            # the conservative data-plane side.
            "getencryptionconfiguration",
            "getintelligenttieringconfiguration",
            "getinventoryconfiguration",
            "getlifecycleconfiguration",
            "getmetricsconfiguration",
            "getreplicationconfiguration",
            "putaccesspointconfigurationforobjectlambda",
            "putaccesspointpublicaccessblock",
            "putanalyticsconfiguration",
            "putbucketabac",
            "putencryptionconfiguration",
            "putintelligenttieringconfiguration",
            "putinventoryconfiguration",
            "putlifecycleconfiguration",
            "putmetricsconfiguration",
            "putreplicationconfiguration",
            "listtagsforresource",
            "tagresource",
            "untagresource",
        }
    ),
    "s3express": frozenset(
        {
            "createaccesspoint",
            "createbucket",
            "deleteaccesspoint",
            "deleteaccesspointpolicy",
            "deleteaccesspointscope",
            "deletebucket",
            "deletebucketpolicy",
            "getaccesspoint",
            "getaccesspointpolicy",
            "getaccesspointscope",
            "getbucketpolicy",
            "getencryptionconfiguration",
            "getlifecycleconfiguration",
            "listaccesspointsfordirectorybuckets",
            "listallmydirectorybuckets",
            "listtagsforresource",
            "putaccesspointpolicy",
            "putaccesspointscope",
            "putbucketpolicy",
            "putencryptionconfiguration",
            "putlifecycleconfiguration",
            "tagresource",
            "untagresource",
        }
    ),
    # Object Lambda access point configuration lives under the s3 service in
    # IAM; nothing else in this service is control-plane.
    "s3-object-lambda": _EMPTY,
    "s3tables": frozenset(
        {
            "createnamespace",
            "createtable",
            "createtablebucket",
            "deletenamespace",
            "deletetable",
            "deletetablebucket",
            "deletetablebucketencryption",
            "deletetablebucketmetricsconfiguration",
            "deletetablebucketpolicy",
            "deletetablebucketreplication",
            "deletetablepolicy",
            "deletetablereplication",
            "getnamespace",
            "gettable",
            "gettablebucket",
            "gettablebucketencryption",
            "gettablebucketmaintenanceconfiguration",
            "gettablebucketmetricsconfiguration",
            "gettablebucketpolicy",
            "gettablebucketreplication",
            "gettablebucketstorageclass",
            "gettableencryption",
            "gettablemaintenanceconfiguration",
            "gettablemaintenancejobstatus",
            "gettablemetadatalocation",
            "gettablepolicy",
            "gettablerecordexpirationconfiguration",
            "gettablerecordexpirationjobstatus",
            "gettablereplication",
            "gettablereplicationstatus",
            "gettablestorageclass",
            "listnamespaces",
            "listtablebuckets",
            "listtables",
            "listtagsforresource",
            "puttablebucketencryption",
            "puttablebucketmaintenanceconfiguration",
            "puttablebucketmetricsconfiguration",
            "puttablebucketpolicy",
            "puttablebucketreplication",
            "puttablebucketstorageclass",
            "puttableencryption",
            "puttablemaintenanceconfiguration",
            "puttablepolicy",
            "puttablerecordexpirationconfiguration",
            "puttablereplication",
            "puttablestorageclass",
            "renametable",
            "tagresource",
            "untagresource",
            "updatetablemetadatalocation",
        }
    ),
    "s3vectors": frozenset(
        {
            "createindex",
            "createvectorbucket",
            "deleteindex",
            "deletevectorbucket",
            "deletevectorbucketpolicy",
            "getindex",
            "getvectorbucket",
            "getvectorbucketpolicy",
            "listindexes",
            "listtagsforresource",
            "listvectorbuckets",
            "putvectorbucketpolicy",
            "tagresource",
            "untagresource",
        }
    ),
    "dynamodb": frozenset(
        {
            "associatetablereplica",
            "createbackup",
            "createglobaltable",
            "createglobaltablewitness",
            "createtable",
            "createtablereplica",
            "deletebackup",
            "deleteglobaltablewitness",
            "deleteresourcepolicy",
            "deletetable",
            "deletetablereplica",
            "describebackup",
            "describecontinuousbackups",
            "describecontributorinsights",
            "describeendpoints",
            "describeexport",
            "describeglobaltable",
            "describeglobaltablesettings",
            "describeimport",
            "describekinesisstreamingdestination",
            "describelimits",
            "describereservedcapacity",
            "describereservedcapacityofferings",
            "describescalabletargets",
            "describestream",
            "describetable",
            "describetablereplicaautoscaling",
            "describetimetolive",
            "disablekinesisstreamingdestination",
            "enablekinesisstreamingdestination",
            "exporttabletopointintime",
            "getabacstatus",
            "getresourcepolicy",
            "importtable",
            "injecterror",
            "listbackups",
            "listcontributorinsights",
            "listexports",
            "listglobaltables",
            "listimports",
            "liststreams",
            "listtables",
            "listtagsofresource",
            "putresourcepolicy",
            "purchasereservedcapacityofferings",
            "registerscalabletarget",
            "replicatesettings",
            "restoretablefromawsbackup",
            "restoretablefrombackup",
            "restoretabletopointintime",
            "startawsbackupjob",
            "tagresource",
            "untagresource",
            "updateabacstatus",
            "updatecontinuousbackups",
            "updatecontributorinsights",
            "updateglobaltable",
            "updateglobaltablesettings",
            "updateglobaltableversion",
            "updatekinesisstreamingdestination",
            "updatetable",
            "updatetablereplicaautoscaling",
            "updatetimetolive",
        }
    ),
    "sns": frozenset(
        {
            "addpermission",
            "checkifphonenumberisoptedout",
            "confirmsubscription",
            "createplatformapplication",
            "createplatformendpoint",
            "createsmssandboxphonenumber",
            "createtopic",
            "deleteendpoint",
            "deleteplatformapplication",
            "deletesmssandboxphonenumber",
            "deletetopic",
            "getdataprotectionpolicy",
            "getendpointattributes",
            "getplatformapplicationattributes",
            "getsmsattributes",
            "getsmssandboxaccountstatus",
            "getsubscriptionattributes",
            "gettopicattributes",
            "listendpointsbyplatformapplication",
            "listoriginationnumbers",
            "listphonenumberoptedout",
            "listphonenumbersoptedout",  # registry spelling of the same API
            "listplatformapplications",
            "listsmssandboxphonenumbers",
            "listsubscriptions",
            "listsubscriptionsbytopic",
            "listtagsforresource",
            "listtopics",
            "optinphonenumber",
            "putdataprotectionpolicy",
            "removepermission",
            "setendpointattributes",
            "setplatformapplicationattributes",
            "setsmsattributes",
            "setsubscriptionattributes",
            "settopicattributes",
            "subscribe",
            "tagresource",
            "unsubscribe",
            "untagresource",
            "verifysmssandboxphonenumber",
        }
    ),
    "sqs": frozenset(
        {
            "addpermission",
            "cancelmessagemovetask",
            "createqueue",
            "deletequeue",
            "listmessagemovetasks",
            "purgequeue",
            "setqueueattributes",
            "startmessagemovetask",
            "tagqueue",
            "untagqueue",
        }
    ),
}


def classify_aws_data_plane(action: str) -> str:
    """Three-way classification of an AWS action (see the block above).

    Returns ``"data"`` (documented CloudTrail data event), ``"management"``
    (documented management event, visible to lookup_events) or
    ``"unclassified"`` (action of a mixed service missing from both tables;
    callers must default it to the safe side).
    """
    service, sep, name = action.strip().lower().partition(":")
    if not sep or not name:
        return _UNCLASSIFIED
    if service not in _AWS_DATA_EVENT_SERVICES:
        return _MANAGEMENT  # service contributes no data events at all
    if name in _AWS_DATA_EVENT_ACTIONS.get(service, _EMPTY):
        return _DATA
    if service in _AWS_MANAGEMENT_BY_DEFAULT_SERVICES:
        return _MANAGEMENT  # closed data-event set; everything else is mgmt
    if name in _AWS_MANAGEMENT_EVENT_ACTIONS.get(service, _EMPTY):
        return _MANAGEMENT
    return _UNCLASSIFIED


def is_unclassified_aws_action(action: str) -> bool:
    """Could not be classified as management vs data event?"""
    return classify_aws_data_plane(action) == _UNCLASSIFIED


def is_data_plane_action(action: str, *, provider: str = "aws") -> bool:
    """Is ``action`` possibly invisible to the activity source?

    AWS: True for documented data events AND for unclassified actions (the
    conservative default — an unclassifiable grant must never be droppable
    as "unused"). Azure: the matcher already carries the distinction via
    ``Statement.data_plane`` from ``dataActions``, so this helper is only
    consulted on AWS.
    """
    if provider == "azure":
        return False  # Azure: handled via ``Statement.data_plane``
    return classify_aws_data_plane(action) != _MANAGEMENT


# Access-level risk weights for the risk score.
_ACCESS_LEVEL_RISK = {
    "permissions management": 3.0,
    "write": 2.0,
    "tagging": 1.0,
    "read": 0.5,
    "list": 0.25,
}

# Actions whose control over IAM itself earns the top risk weight, per
# provider. AWS: the dataset's "Permissions management" access level. Azure:
# operations on Microsoft.Authorization (role assignments / definitions).
_AZURE_PERM_MGMT_PREFIX = "microsoft.authorization/"


class AnalyzerConfig:
    """Tunables for the analysis engine."""

    def __init__(
        self,
        registry: ActionRegistry | None = None,
        max_wildcard_expansion: int = 100_000,
    ) -> None:
        self.registry = registry or load_default_registry()
        self.max_wildcard_expansion = max_wildcard_expansion


class _PrincipalScan:
    """Per-principal accumulation: granted actions, wildcard patterns, usage."""

    def __init__(self) -> None:
        self.granted: dict[str, GrantedAction] = {}
        self.wildcard_patterns: dict[str, set[str]] = {}  # pattern -> granting sources
        # resource scopes per granted action, unioned across statements
        self.resources: dict[str, set[str]] = {}
        # actions granted by statements carrying a Condition element
        self.conditional: set[str] = set()
        # AWS actions the classifier could not place (see the classification
        # block) — defaulted to data-plane and surfaced on the finding
        self.unclassified: set[str] = set()
        # unused-looking grants on the data plane (lookup_events cannot see
        # data events; the usage may exist but be invisible to us)
        self.unknown_usage: set[str] = set()


class Analyzer:
    """Compute per-principal least-privilege findings from a unified snapshot."""

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self._config = config or AnalyzerConfig()
        self._provider = "aws"

    # ------------------------------------------------------------------ API

    def analyze(
        self,
        iam: IaMSnapshot,
        activity: ActivityLog,
        *,
        lookback_days: int | None = None,
    ) -> AnalysisReport:
        """Analyze a full snapshot.

        Args:
            iam: Static side from the collector.
            activity: Dynamic side from the collector.
            lookback_days: Overrides ``activity.window.lookback_days`` in the
                report header when provided.

        Returns:
            An :class:`AnalysisReport` with one finding per user/role,
                sorted by descending risk score.
        """
        registry = self._config.registry
        groups_by_name = {group.name: group for group in iam.groups}

        findings: list[PrincipalFinding] = []
        for user in iam.users:
            findings.append(self._analyze_user(user, groups_by_name, iam, activity))
        for role in iam.roles:
            findings.append(self._analyze_role(role, iam, activity))

        for finding in findings:
            self._score_risk(finding)

        report = AnalysisReport(
            account_id=iam.account_id,
            lookback_days=lookback_days if lookback_days is not None else activity.window.lookback_days,
            window_truncated=activity.window.truncated,
            dataset=registry.dataset_summary(),
            findings=sorted(findings, key=lambda f: f.risk_score, reverse=True),
        )
        LOGGER.info(
            "Analysis: %d principals, %d idle, %d total unused actions",
            len(report.findings),
            len(report.idle_principals),
            sum(f.unused_count for f in report.findings),
        )
        return report

    def analyze_document(self, document: dict[str, Any]) -> AnalysisReport:
        """Analyze a unified snapshot document produced by ``collect``.

        The provider recorded in ``meta.provider`` decides the action
        registry: AWS uses the bundled 20,455-action dataset; Azure builds
        the action universe from the snapshot itself (there is no offline
        Azure action dataset — see
        :mod:`permtrim.analyzer.azure_registry`).
        """
        provider = document.get("meta", {}).get("provider", "aws")
        self._provider = provider
        if provider == "azure":
            self._config = AnalyzerConfig(registry=build_azure_registry(document))  # type: ignore[arg-type]
        iam = self._iam_from_document(document)
        activity = self._activity_from_document(document)
        return self.analyze(iam, activity, lookback_days=document.get("meta", {}).get("lookback_days"))

    # ------------------------------------------------------------ principals

    def _analyze_user(
        self,
        user: IAMUser,
        groups_by_name: dict[str, IAMGroup],
        iam: IaMSnapshot,
        activity: ActivityLog,
    ) -> PrincipalFinding:
        """Effective permissions of a user = own policies + group policies."""
        policy_set = PolicySet()
        for name, document in user.inline_policies.items():
            policy_set.add_policy_document(document, f"inline:{name}@user/{user.name}")
        self._attach_managed(policy_set, user.attached_policies, iam, f"user/{user.name}")
        for group_name in user.groups:
            group = groups_by_name.get(group_name)
            if group is None:
                continue
            for name, document in group.inline_policies.items():
                policy_set.add_policy_document(document, f"inline:{name}@group/{group_name}")
            self._attach_managed(policy_set, group.attached_policies, iam, f"group/{group_name}")

        finding = PrincipalFinding(kind="user", name=user.name, arn=user.arn, provider=self._provider)
        finding.permission_boundary_arn = user.permission_boundary_arn
        scan = self._scan_grants(policy_set, activity, ("user", user.name))
        self._fill_finding(finding, scan)
        return finding

    def _analyze_role(self, role: IAMRole, iam: IaMSnapshot, activity: ActivityLog) -> PrincipalFinding:
        """Role permissions: identity policies (trust policy is out of scope)."""
        policy_set = PolicySet()
        for name, document in role.inline_policies.items():
            policy_set.add_policy_document(document, f"inline:{name}@role/{role.name}")
        self._attach_managed(policy_set, role.attached_policies, iam, f"role/{role.name}")

        finding = PrincipalFinding(kind="role", name=role.name, arn=role.arn, provider=self._provider)
        finding.permission_boundary_arn = role.permission_boundary_arn
        scan = self._scan_grants(policy_set, activity, ("role", role.name))
        self._fill_finding(finding, scan)
        return finding

    @staticmethod
    def _attach_managed(
        policy_set: PolicySet, refs: list[ManagedPolicyRef], iam: IaMSnapshot, label: str
    ) -> None:
        """Add managed-policy documents from the snapshot catalog to the policy set."""
        for ref in refs:
            policy = iam.policies.get(ref.arn)
            if policy is not None and policy.document is not None:
                policy_set.add_policy_document(policy.document, f"managed:{ref.name}@{label}")

    # ------------------------------------------------------------- scanning

    def _scan_grants(
        self, policy_set: PolicySet, activity: ActivityLog, usage_key: tuple[str, str]
    ) -> _PrincipalScan:
        """Expand every Allow into concrete granted actions; separate usage."""
        scan = _PrincipalScan()

        used, error_only = self._working_usage(activity, usage_key)

        for statement in policy_set.allow_statements:
            if statement.actions:
                for pattern in statement.actions:
                    self._grant_pattern(pattern, statement, scan)
            elif statement.not_actions:
                # NotAction Allow: grants everything except the listed patterns.
                # Unbounded to expand; attribute the *used* actions it covers.
                for action in sorted(used):
                    if statement.matches(action):
                        self._grant_action(action, statement, scan, wildcard=False)

        # explicit denies remove grants regardless of source
        for deny in policy_set.deny_statements:
            for action in list(scan.granted):
                if deny.matches(action):
                    scan.granted.pop(action, None)

        for granted in scan.granted.values():
            granted.used = granted.action in used
            granted.error_only = granted.action in error_only and granted.action not in used
        return scan

    def _working_usage(self, activity: ActivityLog, usage_key: tuple[str, str]) -> tuple[set[str], set[str]]:
        """Split observed actions into working usage vs error-only attempts."""
        registry = self._config.registry
        usage = activity.usage.get(usage_key)
        if usage is None:
            return set(), set()
        working: set[str] = set()
        error_only: set[str] = set()
        for action, total in usage.action_counts.items():
            normalized = registry.normalize(action)
            if normalized is None:
                continue
            errors = usage.error_action_counts.get(action, 0)
            if errors >= total:
                error_only.add(normalized)
            else:
                working.add(normalized)
        return working, error_only

    def _grant_pattern(self, pattern: str, statement: Statement, scan: _PrincipalScan) -> None:
        """Record every concrete action an IAM pattern grants."""
        registry = self._config.registry
        wildcard = "*" in pattern or "?" in pattern
        expanded = registry.expand(pattern, limit=self._config.max_wildcard_expansion)
        if expanded:
            for action in expanded:
                self._grant_action(action, statement, scan, wildcard=wildcard)
        else:
            # Pattern matches no known action: keep it verbatim so the report
            # surfaces unknown actions (typos, brand-new services) instead of
            # silently dropping them.
            self._grant_action(pattern, statement, scan, wildcard=False)

    def _grant_action(
        self, action: str, statement: Statement, scan: _PrincipalScan, *, wildcard: bool = False
    ) -> None:
        registry = self._config.registry
        # NotAction exclusions apply even when the same statement carries
        # actions (Azure: actions + notActions together; AWS: either/or —
        # for AWS statements this guard is a no-op).
        if not statement.matches(action):
            return
        if statement.condition:
            scan.conditional.add(action)
        # The data-plane flag is OR-ed across every granting statement: an
        # action granted by BOTH a control-plane and a data-plane statement
        # is treated as data-plane (the conservative choice — its usage may
        # be invisible to the activity source). On AWS the statement is
        # never tagged by the matcher, so the analyzer classifies the action
        # itself; an unclassifiable AWS action defaults to data-plane (the
        # safe side) and is recorded for the reviewer.
        if self._provider == "azure":
            is_data_plane = statement.data_plane
        else:
            classification = classify_aws_data_plane(action)
            is_data_plane = statement.data_plane or classification != _MANAGEMENT
            if classification == _UNCLASSIFIED:
                scan.unclassified.add(action)
        granted = scan.granted.get(action)
        if granted is None:
            granted = GrantedAction(
                action=action,
                sources=[],
                used=False,
                error_only=False,
                access_level=registry.access_level(action),
                data_plane=is_data_plane,
            )
            scan.granted[action] = granted
        elif is_data_plane:
            granted.data_plane = True
        if statement.source not in granted.sources:
            granted.sources.append(statement.source)
        if statement.resources:
            scan.resources.setdefault(action, set()).update(statement.resources)
        if wildcard:
            scan.wildcard_patterns.setdefault(pattern_of(statement, action), set()).add(statement.source)

    # ------------------------------------------------------------- findings

    def _fill_finding(self, finding: PrincipalFinding, scan: _PrincipalScan) -> None:
        granted_map = {g.action: g for g in scan.granted.values()}
        used = {g.action for g in scan.granted.values() if g.used}
        # used actions not granted by identity policies still count as usage
        # (resource-policy flows); merge them into used_actions for the report
        finding.used_actions = sorted(
            {g.action for g in scan.granted.values() if g.used} | set()
        )  # granted view only
        finding.granted_actions = sorted(scan.granted.values(), key=lambda g: g.action)
        # keep the resource scopes of the original grants for the used actions
        # (""-free; empty means no resource provenance was available)
        finding.used_action_resources = {
            action: sorted(scopes)
            for action, scopes in scan.resources.items()
            if granted_map.get(action) is not None and granted_map[action].used
        }
        # used actions whose grants carried Condition elements: surfaced in
        # the report and payload; the tightener refuses to auto-replace them
        finding.conditional_grants = sorted(scan.conditional & used)
        # unused-looking DATA-plane grants: usage on the data plane is
        # INVISIBLE to lookup_events / Activity Log (management/control-plane
        # events only), so these are "unknown usage", not confirmed excess —
        # never classified unused. The data-plane flag is set on the grant
        # itself (AWS: classified per action by ``classify_aws_data_plane``
        # with unclassifiable actions defaulted to data-plane; Azure: carried
        # from ``dataActions`` by the matcher), so this one path covers both
        # providers.
        finding.unknown_usage_actions = sorted(
            action
            for action, granted in scan.granted.items()
            if not granted.used and not granted.error_only and granted.data_plane
        )
        # the subset of the above the classification table could not place:
        # explicitly surfaced (CLI note / JSON report) so reviewers can see
        # which grants were protected by the conservative default rather
        # than by a documented data-event classification
        finding.unclassified_actions = sorted(
            action
            for action, granted in scan.granted.items()
            if action in scan.unclassified and not granted.used and not granted.error_only
        )
        self._collect_wildcards(finding, scan.wildcard_patterns, used)

    def _collect_wildcards(
        self, finding: PrincipalFinding, patterns: dict[str, set[str]], used: set[str]
    ) -> None:
        """Attach wildcard pattern stats (expansion size + unused examples)."""
        registry = self._config.registry
        for pattern in sorted(patterns):
            examples = [action for action in registry.expand(pattern)[:50] if action not in used][
                :_WILDCARD_EXAMPLES_LIMIT
            ]
            finding.wildcard_sources.append(
                {
                    "pattern": pattern,
                    "concrete_action_count": registry.count_matching(pattern),
                    "unused_examples": examples,
                }
            )

    # ------------------------------------------------------------ risk

    def _score_risk(self, finding: PrincipalFinding) -> None:
        """Risk score 0..100: prioritize which principal to tighten first."""
        # unknown-usage data-plane grants are NOT confirmed excess (their
        # usage may simply be invisible to lookup_events); exclude them from
        # the unused set so reports and risk stay honest.
        unknown = set(finding.unknown_usage_actions)
        unused = [g for g in finding.granted_actions if not g.used and g.action not in unknown]
        finding.unused_actions = sorted(unused, key=lambda g: g.action)

        if finding.granted_count == 0:
            finding.risk_score = 0.0
            finding.risk_reasons = ["no_identity_policies"]
            return

        reasons: list[str] = []
        score = 0.0

        if finding.is_idle:
            score += 40.0
            reasons.append("idle principal: no observed activity in the window")

        unused_risk = sum(
            _ACCESS_LEVEL_RISK.get((g.access_level or "").lower(), 0.5) for g in finding.unused_actions
        )
        score += min(30.0, unused_risk * 0.3)
        if unused_risk > 0:
            reasons.append(f"{finding.unused_count} unused granted actions (weighted risk {unused_risk:.1f})")

        wildcard_pattern_count = len(finding.wildcard_sources)
        if wildcard_pattern_count:
            score += min(20.0, 5.0 * wildcard_pattern_count)
            reasons.append(f"{wildcard_pattern_count} wildcard-granting patterns")

        perm_mgmt = sum(
            1
            for g in finding.granted_actions
            if (g.access_level or "").lower() == "permissions management"
            or g.action.startswith(_AZURE_PERM_MGMT_PREFIX)
        )
        if perm_mgmt:
            score += min(10.0, perm_mgmt * 0.5)
            reasons.append(f"{perm_mgmt} permissions-management actions granted")

        finding.risk_score = max(0.0, min(100.0, score))
        finding.risk_reasons = reasons

    # ------------------------------------------------------ document loading

    @staticmethod
    def _iam_from_document(document: dict[str, Any]) -> IaMSnapshot:
        """Rebuild a minimal IaMSnapshot view from a unified document.

        The ``principals[]`` blocks already carry the merged per-principal
        permission sources (inline policies, resolved managed-policy
        documents, group memberships), so they are the single input here —
        no need to re-join ``identities`` with attachments.
        """
        from datetime import datetime, timezone

        from ..models.iam import IAMGroup, IAMRole, IAMUser, ManagedPolicy, ManagedPolicyRef, PolicyKind

        def _refs(entry: dict[str, Any]) -> list[ManagedPolicyRef]:
            return [
                ManagedPolicyRef(name=ref["name"], arn=ref["arn"], kind=PolicyKind(ref["kind"]))
                for ref in entry.get("permission_sources", {}).get("attached_managed_policies", [])
                if ref.get("arn")
            ]

        def _inline(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
            return dict(entry.get("permission_sources", {}).get("inline_policies", {}))

        users: list[IAMUser] = []
        roles: list[IAMRole] = []
        groups: list[IAMGroup] = []
        policies: dict[str, ManagedPolicy] = {}

        for entry in document.get("principals", []):
            kind, name = entry.get("kind"), entry.get("name", "")
            if kind == "user":
                users.append(
                    IAMUser(
                        name=name,
                        arn=entry.get("arn", ""),
                        groups=list(entry.get("permission_sources", {}).get("via_groups", [])),
                        inline_policies=_inline(entry),
                        attached_policies=_refs(entry),
                        permission_boundary_arn=entry.get("permission_sources", {}).get(
                            "permission_boundary_arn"
                        ),
                    )
                )
                # capture managed-policy documents for the catalog
                for ref in entry.get("permission_sources", {}).get("attached_managed_policies", []):
                    if ref.get("arn") and ref.get("document") is not None:
                        policies[ref["arn"]] = ManagedPolicy(
                            name=ref["name"],
                            arn=ref["arn"],
                            kind=PolicyKind(ref["kind"]),
                            default_version_id=None,
                            document=ref["document"],
                        )
            elif kind == "role":
                roles.append(
                    IAMRole(
                        name=name,
                        arn=entry.get("arn", ""),
                        inline_policies=_inline(entry),
                        attached_policies=_refs(entry),
                        permission_boundary_arn=entry.get("permission_sources", {}).get(
                            "permission_boundary_arn"
                        ),
                    )
                )
                for ref in entry.get("permission_sources", {}).get("attached_managed_policies", []):
                    if ref.get("arn") and ref.get("document") is not None:
                        policies[ref["arn"]] = ManagedPolicy(
                            name=ref["name"],
                            arn=ref["arn"],
                            kind=PolicyKind(ref["kind"]),
                            default_version_id=None,
                            document=ref["document"],
                        )
            elif kind == "group":
                groups.append(
                    IAMGroup(
                        name=name,
                        arn=entry.get("arn", ""),
                        inline_policies=_inline(entry),
                        attached_policies=_refs(entry),
                    )
                )
                for ref in entry.get("permission_sources", {}).get("attached_managed_policies", []):
                    if ref.get("arn") and ref.get("document") is not None:
                        policies[ref["arn"]] = ManagedPolicy(
                            name=ref["name"],
                            arn=ref["arn"],
                            kind=PolicyKind(ref["kind"]),
                            default_version_id=None,
                            document=ref["document"],
                        )

        meta = document.get("meta", {})
        return IaMSnapshot(
            account_id=meta.get("account_id", "unknown"),
            collector_identity_arn=meta.get("collector_identity_arn", ""),
            collected_at=datetime.now(timezone.utc),
            users=users,
            roles=roles,
            groups=groups,
            policies=policies,
        )

    @staticmethod
    def _activity_from_document(document: dict[str, Any]) -> ActivityLog:
        """Rebuild an ActivityLog view from a unified document (usage summaries)."""
        from datetime import datetime, timedelta, timezone

        from ..models.activity import ActivityWindow, UsageSummary

        meta = document.get("meta", {})
        window_info = meta.get("window", {})
        now = datetime.now(timezone.utc)
        end = datetime.fromisoformat(window_info["end"]) if window_info.get("end") else now
        start = (
            datetime.fromisoformat(window_info["start"])
            if window_info.get("start")
            else now - timedelta(days=30)
        )
        window = ActivityWindow(
            start=start,
            end=end,
            lookback_days=window_info.get("lookback_days", 30),
            truncated=window_info.get("truncated", False),
        )

        usage: dict[tuple[str, str], UsageSummary] = {}
        for key, summary in document.get("activity", {}).get("usage", {}).items():
            kind, _, name = key.partition(":")
            summary_obj = UsageSummary(
                event_count=summary.get("event_count", 0),
                error_event_count=summary.get("error_event_count", 0),
                action_counts=dict(summary.get("action_counts", {})),
                error_action_counts=dict(summary.get("error_action_counts", {})),
                first_seen=datetime.fromisoformat(summary["first_seen"])
                if summary.get("first_seen")
                else None,
                last_seen=datetime.fromisoformat(summary["last_seen"]) if summary.get("last_seen") else None,
            )
            usage[(kind, name)] = summary_obj
        return ActivityLog(window=window, events=[], usage=usage)


def pattern_of(statement: Statement, action: str) -> str:
    """The wildcard pattern from ``statement`` that grants ``action`` (for
    provenance reporting). Falls back to the action itself."""
    for pattern in statement.actions:
        if "*" in pattern or "?" in pattern:
            return pattern
    return action
