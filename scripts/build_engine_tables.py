"""Build the CloudTrail-doc-derived verification tables for engine.py.

Sources:
  data/cloudtrail_data_events_2026-11.tsv — every row of the CloudTrail "Logging data events"
      resource-type table (service | resources.type | console name | desc),
      transcribed 2026-11-20 from
      https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
  data/iam_dataset_prefixes.txt — the 445 IAM service prefixes in the bundled dataset

Mapping policy (row -> IAM prefix):
  - explicit dict below, hand-reviewed row by row;
  - rows whose data events are not authorized by any IAM prefix in the
    dataset map to None (they cannot appear in an expandable policy grant);
  - the script FAILS if the TSV contains a row missing from the dict, and
    warns if a mapped prefix is absent from the dataset;
  - a None row whose prefix DOES exist in the dataset is a silent bug: the
    prefix drops into management-only (the dangerous direction), so the
    residual scan below FAILS the build on any suspect prefix that is not
    in the reviewed-exceptions list (REVIEWED_EXCEPTIONS, each with its
    reason), and warns when an exception is no longer a suspect.

Run modes:
  python scripts/build_engine_tables.py          regenerate + write the artifact
  python scripts/build_engine_tables.py --check  CI mode: verify the committed
      scripts/engine_tables.generated.py is exactly what the current inputs
      produce — nothing is written, exit 1 on drift.

Safety direction: a data-event service WRONGLY ABSENT from the generated
_AWS_DATA_EVENT_SERVICES would land in _AWS_MANAGEMENT_ONLY_SERVICES (the
dangerous direction — its invisible data-plane usage becomes removable), so
after mapping we re-scan every resources.type of the doc table for each
management-only prefix.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TSV = Path("data/cloudtrail_data_events_2026-11.tsv")
PREFIXES = Path("data/iam_dataset_prefixes.txt")

for _p in (TSV, PREFIXES):
    if not _p.exists():
        raise SystemExit(
            f"Girdi dosyası eksik: {_p}\n"
            "Bu dosyalar repo kökündeki data/ dizininde commit edilmelidir\n"
            "( CloudTrail 'Logging data events' resource-type tablosunun\n"
            "  2026-11 transkripsiyonu ve dataset'in IAM prefix listesi ).\n"
            "Repo kökünden çalıştırın: python scripts/build_engine_tables.py"
        )

# resources.type (without AWS::) -> IAM prefix in the bundled dataset, or None
ROW_MAP: dict[str, str | None] = {
    "Abuse::Report": None,
    "Account::ControlledDomain": None,  # internal OMW service, not account mgmt APIs
    "AgentAccessMCP::Tools": None,
    "AgentRegistry::Registry": None,  # no 'agent-registry' prefix in dataset
    "AIDevOps::AgentSpace": "aidevops",
    "AIDevOps::Association": "aidevops",
    "AIDevOps::OperatorAppTeam": "aidevops",
    "AIDevOps::PipelineMetadata": "aidevops",
    "AIDevOps::Service": "aidevops",
    "AIOps::InvestigationGroup": "aiops",
    "AmplifyGen3::Branch": "amplify",  # amplifybackend handled below if present
    "AOSS::Collection": "aoss",
    "AppConfig::Configuration": "appconfig",
    "AppSync::GraphQLApi": "appsync",
    "ApplicationSignals::InstrumentationConfig": "application-signals",
    "AppMonetization::App": None,
    "Assurance::Environment": None,
    "AWSExternalAnthropic::Workspace": None,
    "Backup::BackupAccessPoint": "backup",
    "Backup::SearchJob": "backup",
    "BedrockAgentCore::Payments": "bedrock-agentcore",
    "DataExchange::Asset": "dataexchange",
    "Deadline::Fleet": "deadline",
    "Deadline::Job": "deadline",
    "Deadline::Queue": "deadline",
    "Deadline::Worker": "deadline",
    "NeptuneGraph::Graph": "neptune-graph",
    "BedrockAgentCore::ABTest": "bedrock-agentcore",
    "BedrockAgentCore::AgentInsightStore": "bedrock-agentcore",
    "BedrockAgentCore::APIKeyCredentialProvider": "bedrock-agentcore",
    "BedrockAgentCore::BatchEvaluate": "bedrock-agentcore",
    "BedrockAgentCore::Browser": "bedrock-agentcore",
    "BedrockAgentCore::BrowserCustom": "bedrock-agentcore",
    "BedrockAgentCore::BrowserProfile": "bedrock-agentcore",
    "BedrockAgentCore::CapacityProvider": "bedrock-agentcore",
    "BedrockAgentCore::CodeInterpreter": "bedrock-agentcore",
    "BedrockAgentCore::CodeInterpreterCustom": "bedrock-agentcore",
    "BedrockAgentCore::Dataset": "bedrock-agentcore",
    "BedrockAgentCore::Evaluator": "bedrock-agentcore",
    "BedrockAgentCore::Gateway": "bedrock-agentcore",
    "BedrockAgentCore::Memory": "bedrock-agentcore",
    "BedrockAgentCore::OAuth2CredentialProvider": "bedrock-agentcore",
    "BedrockAgentCore::Policy": "bedrock-agentcore",
    "BedrockAgentCore::PolicyEngine": "bedrock-agentcore",
    "BedrockAgentCore::Recommendation": "bedrock-agentcore",
    "BedrockAgentCore::Registry": "bedrock-agentcore",
    "BedrockAgentCore::Runtime": "bedrock-agentcore",
    "BedrockAgentCore::RuntimeEndpoint": "bedrock-agentcore",
    "BedrockAgentCore::TokenVault": "bedrock-agentcore",
    "BedrockAgentCore::WebSearch": "bedrock-agentcore",
    "BedrockAgentCore::WorkloadIdentity": "bedrock-agentcore",
    "BedrockAgentCore::WorkloadIdentityDirectory": "bedrock-agentcore",
    "BedrockMantle::Project": "bedrock-mantle",  # CreateInference data events; prefix is in the dataset
    "BedrockWebSearch::Tool": None,
    "B2BI::Transformer": "b2bi",
    "Cassandra::Stream": "cassandra",
    "Cassandra::Table": "cassandra",
    "CertificateManager::AcmeEndpoint": "acm",
    "ClinicalTrialsTech::Codelist": None,
    "ClinicalTrialsTech::Dataset": None,
    "ClinicalTrialsTech::Execution": None,
    "ClinicalTrialsTech::Instance": None,
    "ClinicalTrialsTech::Mapping": None,
    "ClinicalTrialsTech::Schedule": None,
    "ClinicalTrialsTech::Study": None,
    "CloudExtensions::Profile": None,
    "CloudFront::KeyValueStore": "cloudfront-keyvaluestore",  # KVS has its own IAM prefix
    "CloudOptimization::Profile": None,
    "CloudOptimization::Recommendation": None,
    "CloudTrail::Channel": "cloudtrail-data",  # ingestion = cloudtrail-data:PutAuditEvents
    "CloudWatch::Dataset": "cloudwatch",
    "CloudWatch::IngestionEndpoint": "cloudwatch",
    "CloudWatch::Metric": "cloudwatch",
    "CodeWhisperer::Customization": "codewhisperer",
    "CodeWhisperer::Profile": "codewhisperer",
    "CodeGuruProfiler::ProfilingGroup": "codeguru-profiler",
    "Cognito::IdentityPool": "cognito-identity",
    "Context::AgentContext": None,
    "Context::Task": None,
    "ContextMCP::Tools": None,
    "Continuum::SupplyChainPackageDecision": None,
    "Continuum::SupplyChainPackageVulnerability": None,
    "CredentialBroker::CredentialProvider": None,
    "DiodeAlerting::LinkedAlert": None,
    "DynamoDB::Stream": "dynamodb",
    "DynamoDB::Table": "dynamodb",
    "DSQL::Cluster": "dsql",
    "EC2::InstanceConnectEndpoint": "ec2-instance-connect",
    "EC2::Snapshot": "ebs",  # EBS direct APIs are the 'ebs' prefix
    "ECS::ContainerInstance": "ecs",
    "EKS::Dashboard": "eks",
    "EMRWAL::Workspace": None,  # no emrwal prefix in dataset
    "EndUserMessaging::NotifyCodeVerification": None,
    "Events::Endpoint": "events",
    "Events::EventBus": "events",
    "Events::EventSource": "events",
    "Events::Rule": "events",
    "EventsV2::EventBus": "events",
    "EventsV2::EventSource": "events",
    "FinSpace::Environment": "finspace",
    "FSx::Volume": "fsx",
    "GameLiftStreams::Application": "gameliftstreams",
    "GameLiftStreams::StreamGroup": "gameliftstreams",
    "GeoMaps::Provider": "geo-maps",
    "GeoPlaces::Provider": "geo-places",
    "GeoRoutes::Provider": "geo-routes",
    "Glue::Table": "glue",
    "GreengrassV2::ComponentVersion": "greengrass",  # IoT Greengrass V2 IAM prefix
    "GreengrassV2::Deployment": "greengrass",
    "GuardDuty::Detector": "guardduty",
    "GuardDuty::MalwareScan": "guardduty",
    "HealthAgent::Domain": "health-agent",  # Amazon Connect Health data plane
    "HealthAgent::Integration": "health-agent",  # Amazon Connect Health data plane
    "HealthAgent::PatientInsightsJob": "health-agent",  # Amazon Connect Health data plane
    "HealthAgent::Session": "health-agent",  # Amazon Connect Health data plane
    "HealthAgent::Subscription": "health-agent",  # Amazon Connect Health data plane
    "HealthLake::DataTransformationProfile": "healthlake",
    "IoT::Certificate": "iot",
    "IoT::Thing": "iot",
    "IoT::Tunnel": "iot",
    "IoTSiteWise::Asset": "iotsitewise",
    "IoTSiteWise::Dataset": "iotsitewise",
    "IoTSiteWise::Pipeline": "iotsitewise",
    "IoTSiteWise::TimeSeries": "iotsitewise",
    "IoTSiteWise::Workspace": "iotsitewise",
    "IoTTwinMaker::Entity": "iottwinmaker",
    "IoTTwinMaker::Workspace": "iottwinmaker",
    "KendraRanking::ExecutionPlan": "kendra-ranking",
    "Kinesis::Queue": "kinesis",
    "Kinesis::Stream": "kinesis",
    "Kinesis::StreamConsumer": "kinesis",
    "KinesisFirehose::DeliveryStream": "firehose",
    "KinesisVideo::SignalingChannel": "kinesisvideo",
    "KinesisVideo::Stream": "kinesisvideo",
    "Lambda::Function": "lambda",
    "Lambda::MicrovmImage": "lambda",
    "Lambda::WebFunction": "lambda",
    "Lex::Bot": "lex",
    "Lex::BotAlias": "lex",
    "Logs::LogGroupAuthorization": "logs",
    "Logs::ScheduledQuery": "logs",
    "MachineLearning::MlModel": "machinelearning",
    "ManagedBlockchain::Network": "managedblockchain",
    "ManagedBlockchain::Node": "managedblockchain",
    "ManagedBlockchainQuery::QueryAPI": "managedblockchain-query",
    "MedicalImaging::Datastore": "medical-imaging",
    "MedicalImaging::Imageset": "medical-imaging",
    "MWAA::Environment": "airflow",  # MWAA IAM prefix is 'airflow'
    "NetworkFlowMonitor::Monitor": "networkflowmonitor",
    "NetworkFlowMonitor::PerformanceMonitor": "networkflowmonitor",
    "NetworkFlowMonitor::Scope": "networkflowmonitor",
    "NovaAct::WorkflowDefinition": "nova-act",  # CreateAct / InvokeActStep data events
    "NovaAct::WorkflowRun": "nova-act",  # CreateAct / InvokeActStep data events
    "One::UKey": "one",
    "One::User": "one",
    "Osm::Space": None,
    "PaymentCryptography::Alias": "payment-cryptography",
    "PaymentCryptography::Key": "payment-cryptography",
    "PCAConnectorAD::Connector": "pca-connector-ad",
    "PCAConnectorSCEP::Connector": "pca-connector-scep",
    "Pinpoint::App": "mobiletargeting",  # Pinpoint IAM prefix
    "QApps::QApp": "qapps",
    "QApps::QAppSession": "qapps",
    "QBusiness::Application": "qbusiness",
    "QBusiness::DataSource": "qbusiness",
    "QBusiness::Index": "qbusiness",
    "QBusiness::Integration": "qbusiness",
    "QBusiness::WebExperience": "qbusiness",
    "QDeveloper::Integration": "qdeveloper",
    "Quicksight::ActionConnector": "quicksight",  # row spells it 'Quicksight'
    "QuickSight::ActionConnector": "quicksight",
    "QuickSight::App": "quicksight",
    "QuickSight::Automation": "quicksight",
    "QuickSight::AutomationJob": "quicksight",
    "QuickSight::Extension": "quicksight",
    "QuickSight::ExtensionAccess": "quicksight",
    "QuickSight::Flow": "quicksight",
    "QuickSight::FlowSession": "quicksight",
    "QuickSight::Page": "quicksight",
    "QuickSight::Task": "quicksight",
    "RDS::DBCluster": "rds-data",  # the row is the RDS Data API itself
    "Redshift::Cluster": "redshift-data",  # Redshift Data API on clusters
    "ResourceExplorer2::ManagedView": "resource-explorer-2",
    "ResourceExplorer2::View": "resource-explorer-2",
    "RUM::AppMonitor": "rum",
    "S3::AccessPoint": "s3",
    "S3::Object": "s3",
    "S3Express::AccessPoint": "s3express",
    "S3Express::Object": "s3express",
    "S3ObjectLambda::AccessPoint": "s3-object-lambda",
    "S3Outposts::Object": "s3-outposts",
    "S3Tables::Table": "s3tables",
    "S3Tables::TableBucket": "s3tables",
    "S3Vectors::Index": "s3vectors",
    "S3Vectors::VectorBucket": "s3vectors",
    "SageMaker::Endpoint": "sagemaker",
    "SageMaker::ExperimentTrialComponent": "sagemaker",
    "SageMaker::FeatureGroup": "sagemaker",
    "SageMaker::Hub": "sagemaker",
    "SageMaker::InferenceRouter": "sagemaker",
    "SageMaker::Job": "sagemaker",
    "SageMaker::MlflowApp": "sagemaker",
    "SageMaker::MlflowTrackingServer": "sagemaker",
    "SageMaker::TrainingSession": "sagemaker",
    "SCN::BusinessRule": "scn",
    "SCN::DataLakeException": "scn",
    "SCN::ExceptionInvestigation": "scn",
    "SCN::ExceptionRule": "scn",
    "SCN::Instance": "scn",
    "SCN::Metric": "scn",
    "SCN::MetricEvaluation": "scn",
    "SCN::Outcome": "scn",
    "SCN::OutcomeTemplate": "scn",
    "SDB::Domain": "sdb",
    "ServiceDiscovery::Namespace": "servicediscovery",
    "ServiceDiscovery::Service": "servicediscovery",
    "SES::ConfigurationSet": "ses",
    "SES::EmailIdentity": "ses",
    "SES::Template": "ses",
    "Signer::SigningJob": "signer",
    "Signer::SigningProfile": "signer",
    "SitewiseAssistant::Conversation": None,
    "SMSVoice::CarrierLookup": "sms-voice",
    "SMSVoice::ConfigurationSet": "sms-voice",
    "SMSVoice::Message": "sms-voice",
    "SMSVoice::NotifyConfiguration": "sms-voice",
    "SMSVoice::OriginationIdentity": "sms-voice",
    "SocialMessaging::PhoneNumberId": "social-messaging",
    "SocialMessaging::WabaId": "social-messaging",
    "SNS::PlatformEndpoint": "sns",
    "SNS::Topic": "sns",
    "SQS::Queue": "sqs",
    "SSM::ExecutionPreview": "ssm",
    "SSM::ManagedNode": "ssm",
    "SSMMessages::ControlChannel": "ssmmessages",
    "StepFunctions::Activity": "states",
    "StepFunctions::StateMachine": "states",
    "SupportAccess::Tenant": "support",
    "SupportAccess::TrustingAccount": "support",
    "SupportAccess::TrustingRole": "support",
    "SWF::Domain": "swf",
    "Textract::Job": "textract",
    "ThinClient::Device": "thinclient",
    "ThinClient::Environment": "thinclient",
    "Timestream::Database": "timestream",
    "Timestream::RegionalEndpoint": "timestream",
    "Timestream::Table": "timestream",
    "Timestamp::TimestampToken": None,
    "Transform::AgentInstance": "transform",
    "Transform::Profile": "transform",
    "TransformCustom::Campaign": "transform",
    "TransformCustom::Conversation": "transform",
    "TransformCustom::KnowledgeItem": "transform",
    "TransformCustom::Package": "transform",
    "UXC::AccountCustomization": "uxc",
    "VerifiedPermissions::PolicyStore": "verifiedpermissions",
    "WellArchitected::AgentRecommendation": "wellarchitected",
    "WorkloadTelemetry::CertificateTelemetry": None,
    "XRay::Trace": "xray",
}

# Bedrock main rows (from the EKSİK audit output)
for _rt in (
    "AdvancedOptimizePromptJob",
    "AgentAlias",
    "AsyncInvoke",
    "AutomatedReasoningPolicy",
    "AutomatedReasoningPolicyVersion",
    "Blueprint",
    "DataAutomationInvocation",
    "DataAutomationProfile",
    "DataAutomationProject",
    "FlowAlias",
    "FlowExecution",
    "Guardrail",
    "InlineAgent",
    "KnowledgeBase",
    "Model",
    "PromptVersion",
    "Session",
    "Tool",
):
    ROW_MAP[f"Bedrock::{_rt}"] = "bedrock"

dataset = set(PREFIXES.read_text(encoding="utf-8").split())

# --- parse TSV rows (service name | resources.type | console name | desc)
rt_rows: list[tuple[str, str]] = []  # (resources.type without AWS::, raw row text)
for line in TSV.read_text(encoding="utf-8").splitlines():
    parts = [p.strip() for p in line.split("\t| ")]
    if len(parts) >= 2 and parts[1].startswith("AWS::"):
        rt_rows.append((parts[1][len("AWS::") :], line))
rts = [rt for rt, _ in rt_rows]

missing = [rt for rt in rts if rt not in ROW_MAP]
if missing:
    raise SystemExit(f"MAPPING EKSİK {len(missing)} satır: {missing}")

# --- validate mapped prefixes against dataset
bad_prefix: list[str] = []
data_services: set[str] = set()
for rt, prefix in sorted(ROW_MAP.items()):
    if rt not in rts:
        continue  # dict rows not in the current doc snapshot (defensive)
    if prefix is None:
        continue
    if prefix not in dataset:
        bad_prefix.append(f"{rt} -> {prefix}")
    else:
        data_services.add(prefix)

if bad_prefix:
    print("UYARI — dataset'te olmayan prefix'ler (satır ihmal edilecek):")
    for b in bad_prefix:
        print("  ", b)

# existing engine table must be fully preserved
existing = {
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
lost = existing - data_services
if lost:
    raise SystemExit(f"Eski kapsam kaybedildi: {lost}")

management_only = dataset - data_services


# --- residual safety scan: a management-only prefix whose camel-cased form
# appears as a word inside any resources.type of the doc table means a
# missed mapping (the dangerous direction: a data-event service silently
# classified as removable management). Versioned service names strip their
# trailing version token (GreengrassV2 -> greengrass, EventsV2 -> events,
# KafkaConnectV2 -> kafkaconnect), because the IAM prefix never carries it.
def camel(prefix: str) -> str:
    return "".join(w.capitalize() for w in prefix.split("-"))


def versionless(rt_word: str) -> str:
    return re.sub(r"V\d+$", "", rt_word)


suspects = []
for p in sorted(management_only):
    c = camel(p)
    for rt, _raw in rt_rows:
        for word in rt.split("::"):
            if versionless(word) == c:
                suspects.append(p)
                break
        else:
            continue
        break

# Prefixes the scan legitimately flags, each manually reviewed against the
# doc table and the IAM dataset (2026-11): the camel-cased match comes from
# a row that maps to a DIFFERENT prefix, or the service truly has no data
# events. Any suspect NOT in this list means a missed mapping — the build
# fails, so a wrong management-only classification cannot ship silently
# (the direction that makes invisible data-plane usage look removable).
REVIEWED_EXCEPTIONS: dict[str, str] = {
    "account": ("Account::ControlledDomain is an internal OMW service, not the account management APIs"),
    "payments": ("BedrockAgentCore::Payments maps to bedrock-agentcore, not the payments service"),
    "profile": (
        "…Profile rows map to codewhisperer / transform or to None-internal services, not the profile prefix"
    ),
    "redshift": (
        "Redshift::Cluster is the Redshift Data API row (redshift-data); redshift itself is control plane"
    ),
    "transform-custom": "TransformCustom:: rows map to the transform prefix",
}

unexpected = [s for s in suspects if s not in REVIEWED_EXCEPTIONS]
stale = sorted(e for e in REVIEWED_EXCEPTIONS if e not in suspects)

print(f"doc satırları: {len(rts)}, map edilen: {len(data_services)} servis")
print(f"management-only (dataset - data-event): {len(management_only)} servis")
if suspects:
    print("  şüpheler:", ", ".join(suspects))
print(
    f"residual şüpheler: incelenmiş istisna {len(suspects) - len(unexpected)}, incelenmemiş {len(unexpected)}"
)
if unexpected:
    print("HATA — incelenmemiş residual şüpheler: management-only ama doc tablosunda geçiyor (tehlike yönü):")
    for s in unexpected:
        print("  ", s)
    print(
        "Eksik bir ROW_MAP eşleştirmesi mi var, yoksa gerçekten zararsız mı? "
        "Zararsızsa gerekçesiyle REVIEWED_EXCEPTIONS'a ekleyin."
    )
    raise SystemExit(1)
if stale:
    print("UYARI — artık şüphe üretmeyen incelenmiş istisnalar (REVIEWED_EXCEPTIONS'tan çıkarın):", stale)


# --- emit engine.py code
def fmt_frozenset(name: str, items: set[str], comment: str) -> str:
    # one item per line: matches `ruff format` output for frozenset literals
    # longer than the magic-split threshold, so regenerating the tables keeps
    # `ruff format --check` green in CI.
    lines = [comment, f"{name}: frozenset[str] = frozenset(", "    {"]
    for it in sorted(items):
        lines.append(f'        "{it}",')
    lines.append("    }")
    lines.append(")")
    return "\n".join(lines)


out = []
out.append(
    fmt_frozenset(
        "_AWS_DATA_EVENT_SERVICES",
        data_services,
        "# Services that contribute CloudTrail data events — every IAM prefix\n"
        "# mapped from at least one row of the CloudTrail 'Logging data events'\n"
        "# resource-type table (transcribed 2026-11; see _DOC_TABLE_URL below).",
    )
)
out.append("")
out.append(
    fmt_frozenset(
        "_AWS_MANAGEMENT_ONLY_SERVICES",
        management_only,
        "# Services the same CloudTrail table positively identifies as\n"
        "# contributing NO data events (absent from the complete resource-type\n"
        "# list). Every action of these is a management event: visible to\n"
        "# lookup_events, so absence of usage is real evidence of non-use.",
    )
)
content = "\n".join(out) + "\n"
GEN = Path("scripts/engine_tables.generated.py")

if "--check" in sys.argv[1:]:
    # CI mode: verify the committed artifact is exactly what the current
    # inputs produce — nothing is written, exit 1 on drift. Catches a TSV
    # or ROW_MAP change landing without regenerating the tables.
    if not GEN.exists():
        raise SystemExit(
            "HATA — scripts/engine_tables.generated.py yok.\n"
            "Bir kez --check'sız çalıştırıp üretilen dosyayı commit edin."
        )
    committed = GEN.read_text(encoding="utf-8")
    if committed != content:
        raise SystemExit(
            "HATA — scripts/engine_tables.generated.py güncel değil.\n"
            "'python scripts/build_engine_tables.py' çalıştırıp üretilen "
            "dosyayı commit edin."
        )
    print("\nOK — engine_tables.generated.py mevcut girdilerle birebir güncel.")
else:
    GEN.write_text(content, encoding="utf-8")
    print("\nTablo kodu scripts/engine_tables.generated.py dosyasına yazıldı.")
print("data-event servisleri:", sorted(data_services))
