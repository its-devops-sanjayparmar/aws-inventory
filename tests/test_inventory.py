import pandas as pd

from core.models import InventoryItem
from exporters.csv_exporter import CSVExporter
from reports.cost import CostAnalyzer
from reports.security import SecurityAnalyzer
from scanners.ec2 import AMIScanner, CloudFrontScanner, CloudWatchScanner, DynamoDBScanner, DocumentDBScanner, EC2Scanner, ECSScanner, EFSScanner, EKSScanner, ELBScanner, IAMScanner, LambdaScanner, NeptuneScanner, OpenSearchScanner, RDSScanner, ReservedInstanceScanner, Route53Scanner, S3Scanner, SnapshotScanner, SNSScanner, SQSScanner, VPCScanner, VolumeScanner


def test_inventory_item_to_row_contains_core_fields():
    item = InventoryItem(
        account_id="123456789012",
        region="us-east-1",
        service="EC2",
        resource_name="demo-instance",
        resource_id="i-abc123",
        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
        status="running",
        resource_type="instance",
        owner="platform",
        tags={"env": "prod"},
    )

    row = item.to_row()

    assert row["account_id"] == "123456789012"
    assert row["region"] == "us-east-1"
    assert row["service"] == "EC2"
    assert row["resource_name"] == "demo-instance"
    assert row["resource_id"] == "i-abc123"
    assert row["status"] == "running"


def test_security_analyzer_flags_public_s3_buckets():
    analyzer = SecurityAnalyzer()
    findings = analyzer.find_public_s3_buckets(
        [
            InventoryItem(service="S3", resource_name="public-bucket", resource_type="bucket", public=True),
            InventoryItem(service="S3", resource_name="private-bucket", resource_type="bucket", public=False),
        ]
    )

    assert len(findings) == 1
    assert findings[0].resource_name == "public-bucket"


def test_cost_analyzer_flags_unattached_volumes():
    analyzer = CostAnalyzer()
    findings = analyzer.find_unattached_volumes(
        [
            InventoryItem(service="EBS", resource_name="in-use-volume", resource_type="volume", status="in-use"),
            InventoryItem(service="EBS", resource_name="unused-volume", resource_type="volume", status="available"),
        ]
    )

    assert len(findings) == 1
    assert findings[0].resource_name == "unused-volume"


def test_csv_exporter_writes_dataframe(tmp_path):
    exporter = CSVExporter(output_dir=str(tmp_path))
    items = [
        InventoryItem(service="EC2", resource_name="demo", resource_id="i-1", region="us-east-1"),
    ]

    path = exporter.export(items, "inventory.csv")

    df = pd.read_csv(path)
    assert df.iloc[0]["service"] == "EC2"
    assert df.iloc[0]["resource_name"] == "demo"


def test_ec2_scanner_collects_instances():
    class FakeEC2Client:
        def get_paginator(self, operation_name):
            class Pager:
                def paginate(self):
                    return [{"Reservations": [{"Instances": [{"InstanceId": "i-123", "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "web"}], "Placement": {"AvailabilityZone": "us-east-1a"}, "InstanceType": "t3.micro"}]}]}]
            return Pager()

    scanner = EC2Scanner(FakeEC2Client())
    results = scanner.scan("us-east-1", account_id="123456789012")

    assert len(results) == 1
    assert results[0].service == "EC2"
    assert results[0].resource_id == "i-123"


def test_other_scanners_collect_expected_resources():
    class FakeClient:
        def describe_reserved_instances(self):
            return {"ReservedInstances": [{"ReservedInstanceId": "ri-1", "State": "active"}]}

        def describe_images(self, Owners=None):
            return {"Images": [{"ImageId": "ami-1", "Name": "base"}]}

        def describe_volumes(self):
            return {"Volumes": [{"VolumeId": "vol-1", "State": "in-use"}]}

        def describe_snapshots(self, OwnerIds=None):
            return {"Snapshots": [{"SnapshotId": "snap-1", "Status": "completed"}]}

        def list_buckets(self):
            return {"Buckets": [{"Name": "demo-bucket"}]}

        def get_bucket_location(self, Bucket=None):
            return {"LocationConstraint": "us-east-1"}

        def list_users(self):
            return {"Users": [{"UserId": "u-1", "UserName": "demo-user"}]}

        def describe_db_instances(self):
            return {"DBInstances": [{"DBInstanceIdentifier": "db-1", "DBInstanceStatus": "available", "Engine": "mysql"}]}

        def describe_vpcs(self):
            return {"Vpcs": [{"VpcId": "vpc-123", "CidrBlock": "10.0.0.0/16"}]}

        def describe_load_balancers(self):
            return {"LoadBalancers": [{"LoadBalancerName": "app-lb", "State": {"Code": "active"}}]}

        def list_functions(self):
            return {"Functions": [{"FunctionName": "hello", "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:hello", "Runtime": "python3.12"}]}

        def list_distributions(self):
            return {"DistributionList": {"Items": [{"Id": "E123", "DomainName": "d123.cloudfront.net", "Status": "Deployed"}]}}

        def list_hosted_zones(self):
            return {"HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com."}]}

        def describe_alarms(self):
            return {"MetricAlarms": [{"AlarmName": "cpu-high", "AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:cpu-high", "StateValue": "OK"}]}

        def describe_file_systems(self):
            return {"FileSystems": [{"FileSystemId": "fs-123", "Name": "shared", "LifeCycleState": "available", "PerformanceMode": "generalPurpose"}]}

        def list_tables(self):
            return {"TableNames": ["demo-table"]}

        def describe_db_clusters(self):
            return {"DBClusters": [{"DBClusterIdentifier": "docdb-1", "Status": "available"}]}

        def list_domain_names(self):
            return {"DomainNames": [{"DomainName": "search-domain"}]}

        def list_topics(self):
            return {"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:123456789012:alerts"}]}

        def list_queues(self):
            return {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/123456789012/demo"]}

        def list_clusters(self):
            return {
                "clusterArns": ["arn:aws:ecs:us-east-1:123456789012:cluster/default"],
                "clusters": ["demo-cluster"],
            }

    reserved = ReservedInstanceScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    amis = AMIScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    volumes = VolumeScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    snapshots = SnapshotScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    buckets = S3Scanner(FakeClient()).scan(account_id="123456789012")
    iam_users = IAMScanner(FakeClient()).scan(account_id="123456789012")
    rds_instances = RDSScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    vpcs = VPCScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    lbs = ELBScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    lambdas = LambdaScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    cloudfront = CloudFrontScanner(FakeClient()).scan(account_id="123456789012")
    route53 = Route53Scanner(FakeClient()).scan(account_id="123456789012")
    alarms = CloudWatchScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    efs = EFSScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    sns_topics = SNSScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    sqs_queues = SQSScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    ecs_clusters = ECSScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    eks_clusters = EKSScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    dynamodb_tables = DynamoDBScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    docdb_clusters = DocumentDBScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    neptune_clusters = NeptuneScanner(FakeClient()).scan("us-east-1", account_id="123456789012")
    opensearch_domains = OpenSearchScanner(FakeClient()).scan("us-east-1", account_id="123456789012")

    assert reserved[0].resource_id == "ri-1"
    assert amis[0].resource_id == "ami-1"
    assert volumes[0].resource_id == "vol-1"
    assert snapshots[0].resource_id == "snap-1"
    assert buckets[0].resource_name == "demo-bucket"
    assert iam_users[0].resource_name == "demo-user"
    assert rds_instances[0].resource_id == "db-1"
    assert vpcs[0].resource_id == "vpc-123"
    assert lbs[0].resource_name == "app-lb"
    assert lambdas[0].resource_name == "hello"
    assert cloudfront[0].resource_id == "E123"
    assert route53[0].resource_id == "/hostedzone/Z1"
    assert alarms[0].resource_name == "cpu-high"
    assert efs[0].resource_id == "fs-123"
    assert sns_topics[0].resource_id == "arn:aws:sns:us-east-1:123456789012:alerts"
    assert sqs_queues[0].resource_id.startswith("https://sqs")
    assert ecs_clusters[0].resource_id.startswith("arn:aws:ecs")
    assert eks_clusters[0].resource_id == "demo-cluster"
    assert dynamodb_tables[0].resource_name == "demo-table"
    assert docdb_clusters[0].resource_id == "docdb-1"
    assert neptune_clusters[0].resource_id == "docdb-1"
    assert opensearch_domains[0].resource_name == "search-domain"
