from __future__ import annotations

import typer
from rich.console import Console

from core.config import ConfigLoader
from core.models import InventoryItem
from core.session import AwsSession
from exporters.csv_exporter import CSVExporter
from exporters.excel_exporter import ExcelExporter
from exporters.html_exporter import HTMLExporter
from exporters.json_exporter import JSONExporter
from exporters.report_exporter import ReportExporter
from scanners.ec2 import ACMScanner, AMIScanner, AthenaScanner, CloudFrontScanner, CloudTrailScanner, CloudWatchScanner, CodeBuildScanner, CodeCommitScanner, CodePipelineScanner, CodeDeployScanner, CodeArtifactScanner, ConfigScanner, DynamoDBScanner, DocumentDBScanner, EC2Scanner, ECSScanner, ECRScanner, EFSScanner, EKSScanner, ELBScanner, EventBridgeScanner, GlueScanner, GuardDutyScanner, InspectorScanner, IAMScanner, KMSScanner, LambdaScanner, MacieScanner, NeptuneScanner, OpenSearchScanner, OrganizationsScanner, RDSScanner, ReservedInstanceScanner, Route53Scanner, S3Scanner, SecurityHubScanner, ShieldScanner, SnapshotScanner, SNSScanner, SQSScanner, VPCScanner, VolumeScanner, WAFScanner, AccessAnalyzerScanner, ControlTowerScanner, SecretsManagerScanner, SSMParameterStoreScanner, XRayScanner, KinesisScanner, RedshiftScanner, EMRScanner, QuickSightScanner, CostExplorerScanner, BudgetsScanner, TrustedAdvisorScanner
from reports.security import SecurityAnalyzer
from reports.cost import CostAnalyzer

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


def build_sample_items() -> list[InventoryItem]:
    return [
        InventoryItem(
            account_id="123456789012",
            region="us-east-1",
            service="EC2",
            resource_name="demo-web-01",
            resource_id="i-demo001",
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-demo001",
            status="running",
            resource_type="instance",
            tags={"env": "prod"},
        ),
        InventoryItem(
            account_id="123456789012",
            region="us-west-2",
            service="S3",
            resource_name="example-bucket",
            resource_id="example-bucket",
            arn="arn:aws:s3:::example-bucket",
            status="active",
            resource_type="bucket",
            public=False,
        ),
    ]


@app.command()
def scan(
    profile: str | None = typer.Option(None, "--profile", help="Named AWS profile"),
    regions: list[str] | None = typer.Option(None, "--regions", help="AWS regions to scan"),
    role: str | None = typer.Option(None, "--role", help="AssumeRole ARN"),
    sample: bool = typer.Option(False, "--sample", help="Generate sample inventory without calling AWS"),
) -> None:
    """Scan selected AWS regions and export inventory artifacts using the current EC2-first implementation."""
    config = ConfigLoader().load()
    output_dir = config.get("output_dir", "reports")
    region_names = regions or config.get("regions", ["us-east-1"])
    items: list[InventoryItem] = build_sample_items() if sample else []

    if not sample:
        try:
            session = AwsSession(profile=profile, role_arn=role).create()
            for region in region_names:
                ec2_client = session.client("ec2", region_name=region)
                rds_client = session.client("rds", region_name=region)
                elb_client = session.client("elbv2", region_name=region)
                lambda_client = session.client("lambda", region_name=region)
                vpc_client = session.client("ec2", region_name=region)
                cloudwatch_client = session.client("cloudwatch", region_name=region)
                efs_client = session.client("efs", region_name=region)
                ecs_client = session.client("ecs", region_name=region)
                eks_client = session.client("eks", region_name=region)
                sns_client = session.client("sns", region_name=region)
                sqs_client = session.client("sqs", region_name=region)
                dynamodb_client = session.client("dynamodb", region_name=region)
                docdb_client = session.client("docdb", region_name=region)
                neptune_client = session.client("neptune", region_name=region)
                opensearch_client = session.client("es", region_name=region)
                acm_client = session.client("acm", region_name=region)
                kms_client = session.client("kms", region_name=region)
                cloudtrail_client = session.client("cloudtrail", region_name=region)
                eventbridge_client = session.client("events", region_name=region)
                athena_client = session.client("athena", region_name=region)
                glue_client = session.client("glue", region_name=region)
                ecr_client = session.client("ecr", region_name=region)
                codebuild_client = session.client("codebuild", region_name=region)
                codepipeline_client = session.client("codepipeline", region_name=region)
                guardduty_client = session.client("guardduty", region_name=region)
                # inspector has two service names in boto3 depending on version
                try:
                    inspector_client = session.client("inspector2", region_name=region)
                except Exception:
                    inspector_client = session.client("inspector", region_name=region)
                macie_client = session.client("macie2", region_name=region)
                securityhub_client = session.client("securityhub", region_name=region)
                config_client = session.client("config", region_name=region)
                org_client = session.client("organizations", region_name=region)
                access_analyzer_client = session.client("accessanalyzer", region_name=region)
                # Control Tower is region-global in many accounts; client may be unavailable
                try:
                    controltower_client = session.client("controltower", region_name=region)
                except Exception:
                    controltower_client = None
                secrets_client = session.client("secretsmanager", region_name=region)
                ssm_client = session.client("ssm", region_name=region)
                codecommit_client = session.client("codecommit", region_name=region)
                codedeploy_client = session.client("codedeploy", region_name=region)
                codeartifact_client = session.client("codeartifact", region_name=region)
                xray_client = session.client("xray", region_name=region)
                kinesis_client = session.client("kinesis", region_name=region)
                redshift_client = session.client("redshift", region_name=region)
                emr_client = session.client("emr", region_name=region)
                try:
                    quicksight_client = session.client("quicksight", region_name=region)
                except Exception:
                    quicksight_client = None
                # billing clients
                try:
                    ce_client = session.client("ce", region_name=region)
                except Exception:
                    ce_client = None
                try:
                    budgets_client = session.client("budgets", region_name=region)
                except Exception:
                    budgets_client = None
                try:
                    support_client = session.client("support", region_name=region)
                except Exception:
                    support_client = None

                items.extend(EC2Scanner(ec2_client).scan(region, account_id="local"))
                items.extend(ReservedInstanceScanner(ec2_client).scan(region, account_id="local"))
                items.extend(AMIScanner(ec2_client).scan(region, account_id="local"))
                items.extend(VolumeScanner(ec2_client).scan(region, account_id="local"))
                items.extend(SnapshotScanner(ec2_client).scan(region, account_id="local"))
                items.extend(RDSScanner(rds_client).scan(region, account_id="local"))
                items.extend(VPCScanner(vpc_client).scan(region, account_id="local"))
                items.extend(ELBScanner(elb_client).scan(region, account_id="local"))
                items.extend(LambdaScanner(lambda_client).scan(region, account_id="local"))
                items.extend(CloudWatchScanner(cloudwatch_client).scan(region, account_id="local"))
                items.extend(EFSScanner(efs_client).scan(region, account_id="local"))
                items.extend(ECSScanner(ecs_client).scan(region, account_id="local"))
                items.extend(EKSScanner(eks_client).scan(region, account_id="local"))
                items.extend(SNSScanner(sns_client).scan(region, account_id="local"))
                items.extend(SQSScanner(sqs_client).scan(region, account_id="local"))
                items.extend(DynamoDBScanner(dynamodb_client).scan(region, account_id="local"))
                items.extend(DocumentDBScanner(docdb_client).scan(region, account_id="local"))
                items.extend(NeptuneScanner(neptune_client).scan(region, account_id="local"))
                items.extend(OpenSearchScanner(opensearch_client).scan(region, account_id="local"))
                items.extend(ACMScanner(acm_client).scan(region, account_id="local"))
                items.extend(KMSScanner(kms_client).scan(region, account_id="local"))
                items.extend(CloudTrailScanner(cloudtrail_client).scan(region, account_id="local"))
                items.extend(EventBridgeScanner(eventbridge_client).scan(region, account_id="local"))
                items.extend(AthenaScanner(athena_client).scan(region, account_id="local"))
                items.extend(GlueScanner(glue_client).scan(region, account_id="local"))
                items.extend(ECRScanner(ecr_client).scan(region, account_id="local"))
                items.extend(CodeBuildScanner(codebuild_client).scan(region, account_id="local"))
                items.extend(CodePipelineScanner(codepipeline_client).scan(region, account_id="local"))
                items.extend(GuardDutyScanner(guardduty_client).scan(region, account_id="local"))
                items.extend(InspectorScanner(inspector_client).scan(region, account_id="local"))
                items.extend(MacieScanner(macie_client).scan(region, account_id="local"))
                items.extend(SecurityHubScanner(securityhub_client).scan(region, account_id="local"))
                items.extend(ConfigScanner(config_client).scan(region, account_id="local"))
                items.extend(OrganizationsScanner(org_client).scan(region, account_id="local"))
                items.extend(AccessAnalyzerScanner(access_analyzer_client).scan(region, account_id="local"))
                if controltower_client is not None:
                    items.extend(ControlTowerScanner(controltower_client).scan(region, account_id="local"))
                items.extend(SecretsManagerScanner(secrets_client).scan(region, account_id="local"))
                items.extend(SSMParameterStoreScanner(ssm_client).scan(region, account_id="local"))
                items.extend(CodeCommitScanner(codecommit_client).scan(region, account_id="local"))
                items.extend(CodeDeployScanner(codedeploy_client).scan(region, account_id="local"))
                items.extend(CodeArtifactScanner(codeartifact_client).scan(region, account_id="local"))
                items.extend(XRayScanner(xray_client).scan(region, account_id="local"))
                items.extend(KinesisScanner(kinesis_client).scan(region, account_id="local"))
                items.extend(RedshiftScanner(redshift_client).scan(region, account_id="local"))
                items.extend(EMRScanner(emr_client).scan(region, account_id="local"))
                if quicksight_client is not None:
                    items.extend(QuickSightScanner(quicksight_client).scan(region, account_id="local"))
                if ce_client is not None:
                    items.extend(CostExplorerScanner(ce_client).scan(region, account_id="local"))
                if budgets_client is not None:
                    items.extend(BudgetsScanner(budgets_client).scan(region, account_id="local"))
                if support_client is not None:
                    items.extend(TrustedAdvisorScanner(support_client).scan(region, account_id="local"))

            iam_client = session.client("iam")
            s3_client = session.client("s3")
            cloudfront_client = session.client("cloudfront")
            route53_client = session.client("route53")
            waf_client = session.client("wafv2")
            shield_client = session.client("shield")
            items.extend(CloudFrontScanner(cloudfront_client).scan(account_id="local"))
            items.extend(Route53Scanner(route53_client).scan(account_id="local"))
            items.extend(WAFScanner(waf_client).scan(account_id="local"))
            items.extend(ShieldScanner(shield_client).scan(account_id="local"))
            items.extend(IAMScanner(iam_client).scan(account_id="local"))
            items.extend(S3Scanner(s3_client).scan(account_id="local"))
        except Exception as exc:  # pragma: no cover - defensive path
            console.print(f"[yellow]AWS scan failed: {exc}[/yellow]")
            items = build_sample_items()

    CSVExporter(output_dir).export(items, "inventory.csv")
    JSONExporter(output_dir).export(items, "inventory.json")
    ExcelExporter(output_dir).export(items, "inventory.xlsx")
    HTMLExporter(output_dir).export(items, "inventory.html")
    # run analyzers and export findings summary
    sec_analyzer = SecurityAnalyzer()
    cost_analyzer = CostAnalyzer()
    security_findings = sec_analyzer.analyze_all(items)
    cost_findings = cost_analyzer.analyze_costs(items)
    ReportExporter(output_dir).export_findings(security_findings, cost_findings)
    console.print(f"Inventory artifacts written to {output_dir}")


@app.command("export")
def export_command(
    output_dir: str = typer.Option("reports", "--output-dir"),
    formats: list[str] = typer.Option(["all"], "--format", help="Export formats: csv, json, excel, html, all"),
) -> None:
    """Export sample inventory files for local demos and documentation."""
    items = build_sample_items()
    selected = set(formats)
    if "all" in selected:
        selected = {"csv", "json", "excel", "html"}

    if "csv" in selected:
        CSVExporter(output_dir).export(items, "inventory.csv")
    if "json" in selected:
        JSONExporter(output_dir).export(items, "inventory.json")
    if "excel" in selected:
        ExcelExporter(output_dir).export(items, "inventory.xlsx")
    if "html" in selected:
        HTMLExporter(output_dir).export(items, "inventory.html")

    console.print(f"Exported inventory artifacts to {output_dir}")


if __name__ == "__main__":
    app()