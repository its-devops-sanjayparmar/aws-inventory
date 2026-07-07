from __future__ import annotations

from typing import Any

from core.models import InventoryItem


class EC2Scanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        paginator = self.client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = {tag["Key"]: tag.get("Value", "") for tag in instance.get("Tags", [])}
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="EC2",
                            resource_name=instance.get("InstanceId"),
                            resource_id=instance.get("InstanceId"),
                            arn=instance.get("IamInstanceProfile", {}).get("Arn"),
                            status=instance.get("State", {}).get("Name"),
                            resource_type="instance",
                            platform=instance.get("Platform"),
                            availability_zone=instance.get("Placement", {}).get("AvailabilityZone"),
                            tags=tags,
                            details={"instance_type": instance.get("InstanceType")},
                        )
                    )
        return items


class ReservedInstanceScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_reserved_instances()
        for reserved in response.get("ReservedInstances", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="EC2",
                    resource_name=reserved.get("ReservedInstanceId"),
                    resource_id=reserved.get("ReservedInstanceId"),
                    resource_type="reserved_instance",
                    status=reserved.get("State"),
                    details={"instance_type": reserved.get("InstanceType")},
                )
            )
        return items


class AMIScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_images(Owners=["self"])
        for image in response.get("Images", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="EC2",
                    resource_name=image.get("Name") or image.get("ImageId"),
                    resource_id=image.get("ImageId"),
                    resource_type="ami",
                    status="available",
                    details={"architecture": image.get("Architecture")},
                )
            )
        return items


class VolumeScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_volumes()
        for volume in response.get("Volumes", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="EBS",
                    resource_name=volume.get("VolumeId"),
                    resource_id=volume.get("VolumeId"),
                    resource_type="volume",
                    status=volume.get("State"),
                    availability_zone=volume.get("AvailabilityZone"),
                    details={"size_gb": volume.get("Size")},
                )
            )
        return items


class SnapshotScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_snapshots(OwnerIds=["self"])
        for snapshot in response.get("Snapshots", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="EBS",
                    resource_name=snapshot.get("SnapshotId"),
                    resource_id=snapshot.get("SnapshotId"),
                    resource_type="snapshot",
                    status=snapshot.get("Status"),
                    creation_date=snapshot.get("StartTime"),
                )
            )
        return items


class S3Scanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_buckets()
        for bucket in response.get("Buckets", []):
            location = {}
            try:
                location = self.client.get_bucket_location(Bucket=bucket["Name"]) or {}
            except Exception:
                location = {}

            region_for_bucket = region or location.get("LocationConstraint") or "us-east-1"

            # build base item
            item = InventoryItem(
                account_id=account_id,
                region=region_for_bucket,
                service="S3",
                resource_name=bucket.get("Name"),
                resource_id=bucket.get("Name"),
                resource_type="bucket",
                status="active",
                details={"location_constraint": location.get("LocationConstraint")},
            )

            # try to collect ACL and policy to detect public exposure
            try:
                acl = self.client.get_bucket_acl(Bucket=bucket["Name"]) or {}
                item.details["acl"] = acl
                grants = acl.get("Grants", [])
                for g in grants:
                    grantee = g.get("Grantee", {})
                    uri = grantee.get("URI") or grantee.get("Type")
                    if uri and ("AllUsers" in str(uri) or "AuthenticatedUsers" in str(uri)):
                        item.public = True
                        break
            except Exception:
                pass

                try:
                    policy = self.client.get_bucket_policy(Bucket=bucket["Name"]) or {}
                    item.details["policy"] = policy
                    policy_text = None
                    if isinstance(policy, dict):
                        policy_text = policy.get("Policy") or policy.get("policy")
                    elif isinstance(policy, str):
                        policy_text = policy

                    if policy_text:
                        try:
                            policy_doc = json.loads(policy_text)
                            statements = policy_doc.get("Statement", [])
                            if isinstance(statements, dict):
                                statements = [statements]
                            for stmt in statements:
                                if str(stmt.get("Effect", "Allow")).lower() != "allow":
                                    continue
                                principal = stmt.get("Principal")
                                if principal == "*":
                                    item.public = True
                                    break
                                if isinstance(principal, dict):
                                    aws_principal = principal.get("AWS")
                                    if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                                        item.public = True
                                        break
                        except Exception:
                            # if policy isn't JSON or parsing fails, fall back to string heuristics
                            try:
                                pt = str(policy_text)
                                if '"Principal": "*"' in pt or '"AWS": "*"' in pt:
                                    item.public = True
                            except Exception:
                                pass
                except Exception:
                    pass

            items.append(item)
        return items


class IAMScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_users()
        for user in response.get("Users", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region or "global",
                    service="IAM",
                    resource_name=user.get("UserName"),
                    resource_id=user.get("UserId"),
                    resource_type="user",
                    status="active",
                )
            )
        return items


class RDSScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_db_instances()
        for instance in response.get("DBInstances", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="RDS",
                    resource_name=instance.get("DBInstanceIdentifier"),
                    resource_id=instance.get("DbiResourceId") or instance.get("DBInstanceIdentifier"),
                    resource_type="db_instance",
                    status=instance.get("DBInstanceStatus"),
                    details={"engine": instance.get("Engine")},
                )
            )
        return items


class VPCScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_vpcs()
        for vpc in response.get("Vpcs", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="VPC",
                    resource_name=vpc.get("VpcId"),
                    resource_id=vpc.get("VpcId"),
                    resource_type="vpc",
                    status="available",
                    details={"cidr": vpc.get("CidrBlock")},
                )
            )
        return items


class ELBScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_load_balancers()
        for lb in response.get("LoadBalancers", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="ELB",
                    resource_name=lb.get("LoadBalancerName"),
                    resource_id=lb.get("LoadBalancerArn") or lb.get("LoadBalancerName"),
                    resource_type="load_balancer",
                    status=lb.get("State", {}).get("Code"),
                )
            )
        return items


class LambdaScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_functions()
        for function in response.get("Functions", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="Lambda",
                    resource_name=function.get("FunctionName"),
                    resource_id=function.get("FunctionArn"),
                    resource_type="function",
                    status=function.get("State") or "active",
                    details={"runtime": function.get("Runtime")},
                )
            )
        return items


class CloudFrontScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_distributions()
        for dist in response.get("DistributionList", {}).get("Items", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region or "global",
                    service="CloudFront",
                    resource_name=dist.get("DomainName"),
                    resource_id=dist.get("Id"),
                    resource_type="distribution",
                    status=dist.get("Status"),
                )
            )
        return items


class Route53Scanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_hosted_zones()
        for zone in response.get("HostedZones", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region or "global",
                    service="Route53",
                    resource_name=zone.get("Name"),
                    resource_id=zone.get("Id"),
                    resource_type="hosted_zone",
                    status="active",
                )
            )
        return items


class CloudWatchScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_alarms()
        for alarm in response.get("MetricAlarms", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="CloudWatch",
                    resource_name=alarm.get("AlarmName"),
                    resource_id=alarm.get("AlarmArn"),
                    resource_type="alarm",
                    status=alarm.get("StateValue"),
                )
            )
        return items


class EFSScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_file_systems()
        for fs in response.get("FileSystems", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="EFS",
                    resource_name=fs.get("Name") or fs.get("FileSystemId"),
                    resource_id=fs.get("FileSystemId"),
                    resource_type="file_system",
                    status=fs.get("LifeCycleState"),
                    details={"performance_mode": fs.get("PerformanceMode")},
                )
            )
        return items


class SNSScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_topics()
        for topic in response.get("Topics", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="SNS",
                    resource_name=topic.get("TopicArn"),
                    resource_id=topic.get("TopicArn"),
                    resource_type="topic",
                    status="active",
                )
            )
        return items


class SQSScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_queues()
        for queue in response.get("QueueUrls", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="SQS",
                    resource_name=queue,
                    resource_id=queue,
                    resource_type="queue",
                    status="active",
                )
            )
        return items


class ECSScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_clusters()
        for cluster in response.get("clusterArns", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="ECS",
                    resource_name=cluster,
                    resource_id=cluster,
                    resource_type="cluster",
                    status="active",
                )
            )
        return items


class EKSScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_clusters()
        for cluster in response.get("clusters", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="EKS",
                    resource_name=cluster,
                    resource_id=cluster,
                    resource_type="cluster",
                    status="active",
                )
            )
        return items


class DynamoDBScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_tables()
        for table_name in response.get("TableNames", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="DynamoDB",
                    resource_name=table_name,
                    resource_id=table_name,
                    resource_type="table",
                    status="active",
                )
            )
        return items


class DocumentDBScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_db_clusters()
        for cluster in response.get("DBClusters", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="DocumentDB",
                    resource_name=cluster.get("DBClusterIdentifier"),
                    resource_id=cluster.get("DBClusterIdentifier"),
                    resource_type="cluster",
                    status=cluster.get("Status"),
                )
            )
        return items


class NeptuneScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_db_clusters()
        for cluster in response.get("DBClusters", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="Neptune",
                    resource_name=cluster.get("DBClusterIdentifier"),
                    resource_id=cluster.get("DBClusterIdentifier"),
                    resource_type="cluster",
                    status=cluster.get("Status"),
                )
            )
        return items


class OpenSearchScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_domain_names()
        for domain in response.get("DomainNames", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="OpenSearch",
                    resource_name=domain.get("DomainName"),
                    resource_id=domain.get("DomainName"),
                    resource_type="domain",
                    status="active",
                )
            )
        return items


class GuardDutyScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "list_detectors"):
                resp = self.client.list_detectors()
                detector_ids = resp.get("DetectorIds", [])
            else:
                detector_ids = []
        except Exception:
            detector_ids = []

        for det in detector_ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="GuardDuty",
                    resource_name=det,
                    resource_id=det,
                    resource_type="detector",
                    status="active",
                )
            )
        return items


class InspectorScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            # try Inspector2 first, fall back to inspector
            if hasattr(self.client, "list_findings"):
                resp = self.client.list_findings(maxResults=50)
                findings = resp.get("findings", []) if isinstance(resp, dict) else []
                ids = [f.get("id") or f for f in findings]
            elif hasattr(self.client, "list_assessment_runs"):
                resp = self.client.list_assessment_runs()
                ids = resp.get("assessmentRunArns", [])
            else:
                ids = []
        except Exception:
            ids = []

        for idv in ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="Inspector",
                    resource_name=str(idv),
                    resource_id=str(idv),
                    resource_type="assessment",
                    status="active",
                )
            )
        return items


class MacieScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "list_classification_jobs"):
                resp = self.client.list_classification_jobs()
                jobs = resp.get("items", [])
                ids = [j.get("jobId") or j.get("id") or j for j in jobs]
            else:
                ids = []
        except Exception:
            ids = []

        for j in ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="Macie",
                    resource_name=str(j),
                    resource_id=str(j),
                    resource_type="classification_job",
                    status="active",
                )
            )
        return items


class SecurityHubScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "get_findings"):
                resp = self.client.get_findings(MaxResults=50)
                findings = resp.get("Findings", [])
                ids = [f.get("Id") or f.get("Id") for f in findings]
            elif hasattr(self.client, "list_enabled_products_for_import"):
                resp = self.client.list_enabled_products_for_import()
                products = resp.get("Products", [])
                ids = [p.get("ProductArn") for p in products]
            else:
                ids = []
        except Exception:
            ids = []

        for idv in ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="SecurityHub",
                    resource_name=str(idv),
                    resource_id=str(idv),
                    resource_type="finding_or_product",
                    status="active",
                )
            )
        return items


class ConfigScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "describe_config_rules"):
                resp = self.client.describe_config_rules()
                rules = resp.get("ConfigRules", [])
                ids = [r.get("ConfigRuleName") for r in rules]
            else:
                ids = []
        except Exception:
            ids = []

        for r in ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="Config",
                    resource_name=str(r),
                    resource_id=str(r),
                    resource_type="config_rule",
                    status="active",
                )
            )
        return items


class OrganizationsScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "list_accounts"):
                resp = self.client.list_accounts()
                accounts = resp.get("Accounts", [])
                ids = [a.get("Id") for a in accounts]
            else:
                ids = []
        except Exception:
            ids = []

        for a in ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region or "global",
                    service="Organizations",
                    resource_name=str(a),
                    resource_id=str(a),
                    resource_type="account",
                    status="active",
                )
            )
        return items


class AccessAnalyzerScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "list_analyzers"):
                resp = self.client.list_analyzers()
                analyzers = resp.get("analyzers", [])
                ids = [a.get("arn") or a.get("name") for a in analyzers]
            else:
                ids = []
        except Exception:
            ids = []

        for an in ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="AccessAnalyzer",
                    resource_name=str(an),
                    resource_id=str(an),
                    resource_type="analyzer",
                    status="active",
                )
            )
        return items


class ControlTowerScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            # Control Tower APIs vary; attempt a few common calls
            ids = []
            if hasattr(self.client, "list_control_towers"):
                resp = self.client.list_control_towers()
                cts = resp.get("controlTowers", [])
                ids = [c.get("controlTowerArn") or c.get("id") for c in cts]
            elif hasattr(self.client, "list_accounts"):
                resp = self.client.list_accounts()
                ids = [a.get("Id") for a in resp.get("accounts", [])]
        except Exception:
            ids = []

        for ct in ids:
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region or "global",
                    service="ControlTower",
                    resource_name=str(ct),
                    resource_id=str(ct),
                    resource_type="controltower",
                    status="active",
                )
            )
        return items


class SecretsManagerScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            paginator = getattr(self.client, "get_paginator", None)
            if paginator:
                for page in self.client.get_paginator("list_secrets").paginate():
                    for s in page.get("SecretList", []):
                        arn = s.get("ARN") or s.get("Name")
                        item = InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="SecretsManager",
                            resource_name=s.get("Name"),
                            resource_id=arn,
                            resource_type="secret",
                            status=s.get("DeletedDate") and "deleted" or "active",
                            details={"tags": s.get("Tags", [])},
                        )

                        # attempt to fetch resource policy metadata
                        try:
                            policy = self.client.get_resource_policy(SecretId=arn)
                            item.details["resource_policy"] = policy
                            policy_text = policy.get("ResourcePolicy") or policy.get("Policy")
                            if policy_text:
                                try:
                                    policy_doc = json.loads(policy_text)
                                    statements = policy_doc.get("Statement", [])
                                    if isinstance(statements, dict):
                                        statements = [statements]
                                    for stmt in statements:
                                        if str(stmt.get("Effect", "Allow")).lower() != "allow":
                                            continue
                                        principal = stmt.get("Principal")
                                        if principal == "*":
                                            item.public = True
                                            break
                                        if isinstance(principal, dict):
                                            aws_principal = principal.get("AWS")
                                            if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                                                item.public = True
                                                break
                                except Exception:
                                    pt = str(policy_text)
                                    if '"Principal": "*"' in pt or '"AWS": "*"' in pt:
                                        item.public = True
                        except Exception:
                            # some accounts or secrets may not have a resource policy or permission
                            pass

                        try:
                            desc = self.client.describe_secret(SecretId=arn)
                            # include rotation and other metadata
                            item.details.setdefault("meta", {}).update({
                                "rotation_enabled": desc.get("RotationEnabled"),
                                "rotation_lambda": desc.get("RotationLambdaARN"),
                            })
                        except Exception:
                            pass

                        items.append(item)
            else:
                resp = self.client.list_secrets()
                for s in resp.get("SecretList", []):
                    arn = s.get("ARN") or s.get("Name")
                    item = InventoryItem(
                        account_id=account_id,
                        region=region,
                        service="SecretsManager",
                        resource_name=s.get("Name"),
                        resource_id=arn,
                        resource_type="secret",
                        status=s.get("DeletedDate") and "deleted" or "active",
                        details={"tags": s.get("Tags", [])},
                    )
                    try:
                        policy = self.client.get_resource_policy(SecretId=arn)
                        item.details["resource_policy"] = policy
                        policy_text = policy.get("ResourcePolicy") or policy.get("Policy")
                        if isinstance(policy_text, str) and ('"Principal": "*"' in policy_text or '"AWS": "*"' in policy_text):
                            item.public = True
                    except Exception:
                        pass
                    try:
                        desc = self.client.describe_secret(SecretId=arn)
                        item.details.setdefault("meta", {}).update({
                            "rotation_enabled": desc.get("RotationEnabled"),
                            "rotation_lambda": desc.get("RotationLambdaARN"),
                        })
                    except Exception:
                        pass
                    items.append(item)
        except Exception:
            pass
        return items


class SSMParameterStoreScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            paginator = getattr(self.client, "get_paginator", None)
            if paginator:
                for page in self.client.get_paginator("describe_parameters").paginate():
                    for p in page.get("Parameters", []):
                                details = {}
                                # include type metadata if present
                                if isinstance(p, dict):
                                    if "Type" in p:
                                        details["type"] = p.get("Type")
                                items.append(
                                    InventoryItem(
                                        account_id=account_id,
                                        region=region,
                                        service="SSM",
                                        resource_name=p.get("Name"),
                                        resource_id=p.get("Name"),
                                        resource_type="parameter",
                                        status="active",
                                        details=details,
                                    )
                                )
            else:
                resp = self.client.describe_parameters()
                for p in resp.get("Parameters", []):
                    details = {}
                    if isinstance(p, dict) and "Type" in p:
                        details["type"] = p.get("Type")
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="SSM",
                            resource_name=p.get("Name"),
                            resource_id=p.get("Name"),
                            resource_type="parameter",
                            status="active",
                            details=details,
                        )
                    )
        except Exception:
            pass
        return items


class CodeCommitScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            resp = self.client.list_repositories()
            for r in resp.get("repositories", []):
                name = r.get("repositoryName") or r.get("name") or r
                arn = r.get("repositoryArn") or name
                items.append(
                    InventoryItem(
                        account_id=account_id,
                        region=region,
                        service="CodeCommit",
                        resource_name=name,
                        resource_id=arn,
                        resource_type="repository",
                        status="active",
                    )
                )
        except Exception:
            pass
        return items


class CodeDeployScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            resp = self.client.list_applications()
            for app in resp.get("applications", []):
                name = app
                items.append(
                    InventoryItem(
                        account_id=account_id,
                        region=region,
                        service="CodeDeploy",
                        resource_name=name,
                        resource_id=name,
                        resource_type="application",
                        status="active",
                    )
                )
        except Exception:
            pass
        return items


class CodeArtifactScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            resp = self.client.list_repositories()
            for repo in resp.get("repositories", []):
                name = repo.get("name") or repo.get("repositoryName") or repo
                arn = repo.get("arn") or name
                items.append(
                    InventoryItem(
                        account_id=account_id,
                        region=region,
                        service="CodeArtifact",
                        resource_name=name,
                        resource_id=arn,
                        resource_type="repository",
                        status="active",
                    )
                )
        except Exception:
            pass
        return items


class XRayScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "get_groups"):
                resp = self.client.get_groups()
                groups = resp.get("Groups", [])
                for g in groups:
                    name = g.get("GroupName") or g.get("Name") or g
                    arn = g.get("GroupARN") or name
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="XRay",
                            resource_name=name,
                            resource_id=arn,
                            resource_type="group",
                            status="active",
                        )
                    )
            else:
                # fallback: list sampling rules as X-Ray artifacts
                resp = self.client.get_sampling_rules()
                for r in resp.get("SamplingRuleRecords", []):
                    rule = r.get("SamplingRule", {})
                    name = rule.get("RuleName")
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="XRay",
                            resource_name=name,
                            resource_id=name,
                            resource_type="sampling_rule",
                            status="active",
                        )
                    )
        except Exception:
            pass
        return items


class KinesisScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "list_streams"):
                resp = self.client.list_streams()
                for name in resp.get("StreamNames", []):
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="Kinesis",
                            resource_name=name,
                            resource_id=name,
                            resource_type="stream",
                            status="active",
                        )
                    )
        except Exception:
            pass
        return items


class RedshiftScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "describe_clusters"):
                resp = self.client.describe_clusters()
                for c in resp.get("Clusters", []):
                    cid = c.get("ClusterIdentifier") or c.get("DBName")
                    arn = c.get("ClusterNamespaceArn") or c.get("ClusterIdentifier") or cid
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="Redshift",
                            resource_name=cid,
                            resource_id=arn,
                            resource_type="cluster",
                            status=c.get("ClusterStatus") or "unknown",
                        )
                    )
        except Exception:
            pass
        return items


class EMRScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            if hasattr(self.client, "list_clusters"):
                resp = self.client.list_clusters()
                for cl in resp.get("Clusters", []):
                    cid = cl.get("Id") or cl.get("ClusterId")
                    name = cl.get("Name") or cid
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region,
                            service="EMR",
                            resource_name=name,
                            resource_id=cid,
                            resource_type="cluster",
                            status=cl.get("Status", {}).get("State") or "unknown",
                        )
                    )
        except Exception:
            pass
        return items


class QuickSightScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            # Many QuickSight calls require AwsAccountId; try to use provided account_id or skip
            aws_account = account_id or None
            if aws_account is None:
                # attempt without account id (may fail) and rely on exception handling
                resp = self.client.list_dashboards()
            else:
                resp = self.client.list_dashboards(AwsAccountId=aws_account)

            for d in resp.get("DashboardSummaryList", []) if isinstance(resp, dict) else []:
                did = d.get("DashboardId") or d.get("Id")
                name = d.get("Name") or did
                items.append(
                    InventoryItem(
                        account_id=account_id,
                        region=region,
                        service="QuickSight",
                        resource_name=name,
                        resource_id=did,
                        resource_type="dashboard",
                        status="active",
                    )
                )
        except Exception:
            pass
        return items


class CostExplorerScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            # Request last full month cost summary as an inventory artifact
            from datetime import datetime, timedelta, timezone

            end = datetime.now(timezone.utc).replace(day=1)
            start = (end - timedelta(days=1)).replace(day=1)
            time_period = {"Start": start.strftime("%Y-%m-%d"), "End": end.strftime("%Y-%m-%d")}
            resp = self.client.get_cost_and_usage(TimePeriod=time_period, Granularity="MONTHLY", Metrics=["UnblendedCost"])
            # create a single summary item if response present
            if isinstance(resp, dict):
                items.append(
                    InventoryItem(
                        account_id=account_id,
                        region=region,
                        service="CostExplorer",
                        resource_name=f"cost-summary-{time_period['Start']}",
                        resource_id=f"cost-summary-{time_period['Start']}",
                        resource_type="cost_report",
                        status="available",
                        details=resp,
                    )
                )
        except Exception:
            pass
        return items


class BudgetsScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            params = {}
            if account_id:
                params["AccountId"] = account_id
            resp = self.client.describe_budgets(**params)
            for b in resp.get("Budgets", []):
                name = b.get("BudgetName")
                items.append(
                    InventoryItem(
                        account_id=account_id,
                        region=region,
                        service="Budgets",
                        resource_name=name,
                        resource_id=name,
                        resource_type="budget",
                        status=b.get("BudgetLimit") and "configured" or "unknown",
                        details=b,
                    )
                )
        except Exception:
            pass
        return items


class TrustedAdvisorScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        try:
            # list available checks and include them as advisory items
            if hasattr(self.client, "describe_trusted_advisor_checks"):
                resp = self.client.describe_trusted_advisor_checks(language="en")
                for chk in resp.get("checks", []):
                    cid = chk.get("id") or chk.get("name")
                    items.append(
                        InventoryItem(
                            account_id=account_id,
                            region=region or "global",
                            service="TrustedAdvisor",
                            resource_name=chk.get("name"),
                            resource_id=cid,
                            resource_type="check",
                            status="available",
                            details=chk,
                        )
                    )
        except Exception:
            pass
        return items


class ACMScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_certificates()
        for cert in response.get("CertificateSummaryList", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="ACM",
                    resource_name=cert.get("DomainName"),
                    resource_id=cert.get("CertificateArn"),
                    resource_type="certificate",
                    status="active",
                )
            )
        return items


class KMSScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_keys()
        for key in response.get("Keys", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="KMS",
                    resource_name=key.get("KeyId"),
                    resource_id=key.get("KeyArn"),
                    resource_type="key",
                    status="enabled",
                )
            )
        return items


class WAFScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_web_acls()
        for acl in response.get("WebACLs", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region or "global",
                    service="WAF",
                    resource_name=acl.get("Name"),
                    resource_id=acl.get("Id"),
                    resource_type="web_acl",
                    status="active",
                )
            )
        return items


class ShieldScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str | None = None, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_protections()
        for protection in response.get("Protections", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region or "global",
                    service="Shield",
                    resource_name=protection.get("Name"),
                    resource_id=protection.get("Id"),
                    resource_type="protection",
                    status="active",
                )
            )
        return items


class CloudTrailScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_trails()
        for trail in response.get("trailList", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="CloudTrail",
                    resource_name=trail.get("Name"),
                    resource_id=trail.get("TrailARN"),
                    resource_type="trail",
                    status="active",
                )
            )
        return items


class EventBridgeScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_rules()
        for rule in response.get("Rules", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="EventBridge",
                    resource_name=rule.get("Name"),
                    resource_id=rule.get("Arn"),
                    resource_type="rule",
                    status=rule.get("State"),
                )
            )
        return items


class AthenaScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_work_groups()
        for group in response.get("WorkGroups", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="Athena",
                    resource_name=group.get("Name"),
                    resource_id=group.get("Name"),
                    resource_type="workgroup",
                    status="active",
                )
            )
        return items


class GlueScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.get_databases()
        for database in response.get("DatabaseList", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="Glue",
                    resource_name=database.get("Name"),
                    resource_id=database.get("Name"),
                    resource_type="database",
                    status="active",
                )
            )
        return items


class ECRScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.describe_repositories()
        for repo in response.get("repositories", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="ECR",
                    resource_name=repo.get("repositoryName"),
                    resource_id=repo.get("repositoryArn"),
                    resource_type="repository",
                    status="active",
                )
            )
        return items


class CodeBuildScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_projects()
        for project in response.get("projects", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="CodeBuild",
                    resource_name=project,
                    resource_id=project,
                    resource_type="project",
                    status="active",
                )
            )
        return items


class CodePipelineScanner:
    def __init__(self, client: Any):
        self.client = client

    def scan(self, region: str, account_id: str | None = None) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        response = self.client.list_pipelines()
        for pipeline in response.get("pipelines", []):
            items.append(
                InventoryItem(
                    account_id=account_id,
                    region=region,
                    service="CodePipeline",
                    resource_name=pipeline.get("name"),
                    resource_id=pipeline.get("name"),
                    resource_type="pipeline",
                    status="active",
                )
            )
        return items