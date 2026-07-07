from core.models import InventoryItem
from scanners.ec2 import (
    GuardDutyScanner,
    InspectorScanner,
    SecretsManagerScanner,
    CodeCommitScanner,
    KinesisScanner,
    CostExplorerScanner,
    BudgetsScanner,
)


def test_guardduty_scanner_lists_detectors():
    class FakeGDClient:
        def list_detectors(self):
            return {"DetectorIds": ["det-1"]}

    scanner = GuardDutyScanner(FakeGDClient())
    results = scanner.scan("us-east-1", account_id="123")
    assert len(results) == 1
    assert results[0].service == "GuardDuty"
    assert results[0].resource_id == "det-1"


def test_inspector_scanner_lists_assessments():
    class FakeInspectorClient:
        def list_assessment_runs(self):
            return {"assessmentRunArns": ["arn:inspector:run/1"]}

    scanner = InspectorScanner(FakeInspectorClient())
    results = scanner.scan("us-east-1", account_id="123")
    assert len(results) == 1
    assert results[0].service == "Inspector"


def test_secretsmanager_scanner_iterates_secrets():
    class FakeSecretsClient:
        def get_paginator(self, name):
            class Pager:
                def paginate(self):
                    return [{"SecretList": [{"Name": "s1", "ARN": "arn:secret:s1"}]}]

            return Pager()

    scanner = SecretsManagerScanner(FakeSecretsClient())
    results = scanner.scan("us-east-1", account_id="123")
    assert len(results) == 1
    assert results[0].service == "SecretsManager"
    assert results[0].resource_name == "s1"


def test_codecommit_scanner_lists_repos():
    class FakeCC:
        def list_repositories(self):
            return {"repositories": [{"repositoryName": "repo1", "repositoryArn": "arn:repo:repo1"}]}

    scanner = CodeCommitScanner(FakeCC())
    results = scanner.scan("us-east-1", account_id="123")
    assert results[0].service == "CodeCommit"
    assert results[0].resource_name == "repo1"


def test_kinesis_scanner_lists_streams():
    class FakeKinesis:
        def list_streams(self):
            return {"StreamNames": ["stream1"]}

    scanner = KinesisScanner(FakeKinesis())
    results = scanner.scan("us-east-1", account_id="123")
    assert results[0].service == "Kinesis"
    assert results[0].resource_name == "stream1"


def test_costexplorer_and_budgets_scanners_return_items():
    class FakeCE:
        def get_cost_and_usage(self, TimePeriod=None, Granularity=None, Metrics=None):
            return {"ResultsByTime": [{"TimePeriod": TimePeriod}]}

    class FakeBudgets:
        def describe_budgets(self, **kwargs):
            return {"Budgets": [{"BudgetName": "b1", "BudgetLimit": {"Amount": "10"}}]}

    ce = CostExplorerScanner(FakeCE())
    budgets = BudgetsScanner(FakeBudgets())

    ce_results = ce.scan("us-east-1", account_id="123")
    b_results = budgets.scan("us-east-1", account_id="123")

    assert any(r.service == "CostExplorer" for r in ce_results)
    assert any(r.service == "Budgets" for r in b_results)
