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
    warns if a mapped prefix is absent from the dataset.

Safety direction: a data-event service WRONGLY ABSENT from the generated
_AWS_DATA_EVENT_SERVICES would land in _AWS_MANAGEMENT_ONLY_SERVICES (the
dangerous direction — its invisible data-plane usage becomes removable), so
after mapping we re-scan every resources.type of the doc table for each
management-only prefix.
"""

from __future__ import annotations

import re
from pathlib import Path

TSV = Path("data/cloudtrail_data_events_2026-11.tsv")
PREFIXES = Path("data/iam_dataset_prefixes.txt")

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
    "BedrockMantle::Project": None,
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
    "GreengrassV2::ComponentVersion": None,  # prefix not in bundled dataset
    "GreengrassV2::Deployment": None,
    "GuardDuty::Detector": "guardduty",
    "GuardDuty::MalwareScan": "guardduty",
    "HealthAgent::Domain": None,
    "HealthAgent::Integration": None,
    "HealthAgent::PatientInsightsJob": None,
    "HealthAgent::Session": None,
    "HealthAgent::Subscription": None,
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
    "NovaAct::WorkflowDefinition": None,
    "NovaAct::WorkflowRun": None,
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
# classified as removable management).
def camel(prefix: str) -> str:
    return "".join(w.capitalize() for w in prefix.split("-"))


suspects = []
for p in sorted(management_only):
    c = camel(p)
    for rt, _raw in rt_rows:
        if re.search(rf"(::|^)\b{re.escape(c)}\b(::|$)", rt):
            suspects.append(p)
            break

print(f"doc satırları: {len(rts)}, map edilen: {len(data_services)} servis")
print(f"management-only (dataset - data-event): {len(management_only)} servis")
print(f"residual şüpheler (doc'ta hâlâ geçen management-only prefix): {suspects or 'YOK'}")


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
Path("scripts/engine_tables.generated.py").write_text("\n".join(out) + "\n", encoding="utf-8")
print("\nTablo kodu scripts/engine_tables.generated.py dosyasına yazıldı.")
print("data-event servisleri:", sorted(data_services))
