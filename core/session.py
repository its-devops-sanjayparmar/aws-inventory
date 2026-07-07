from __future__ import annotations

import boto3
from botocore.config import Config


class AwsSession:
    def __init__(self, profile: str | None = None, region: str | None = None, role_arn: str | None = None):
        self.profile = profile
        self.region = region
        self.role_arn = role_arn

    def create(self):
        session_kwargs: dict[str, object] = {"config": Config(retries={"max_attempts": 5, "mode": "adaptive"})}
        if self.profile:
            session_kwargs["profile_name"] = self.profile
        base_session = boto3.Session(**session_kwargs)
        if self.role_arn:
            sts_client = base_session.client("sts")
            assumed = sts_client.assume_role(RoleArn=self.role_arn, RoleSessionName="aws-inventory-pro")
            creds = assumed["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region or base_session.region_name or "us-east-1",
            )
        return base_session