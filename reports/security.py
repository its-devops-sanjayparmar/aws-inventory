from __future__ import annotations

from dataclasses import dataclass

from core.models import InventoryItem


@dataclass
class SecurityFinding:
    resource_name: str | None
    service: str
    finding: str


class SecurityAnalyzer:
    def find_public_s3_buckets(self, items: list[InventoryItem]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for item in items:
            if item.service == "S3" and item.resource_type == "bucket" and item.public:
                findings.append(SecurityFinding(item.resource_name, item.service, "public bucket"))
        return findings

    def find_secrets_with_sensitive_names(self, items: list[InventoryItem]) -> list[SecurityFinding]:
        """Flag secrets or parameters that contain common sensitive keywords in their names.

        This heuristic helps find likely secrets left in Parameter Store or Secrets Manager
        with names that indicate sensitive content.
        """
        findings: list[SecurityFinding] = []
        keywords = ("password", "passwd", "secret", "token", "apikey", "api_key", "key", "credential")
        for item in items:
            if item.service in ("SecretsManager", "SSM") and item.resource_name:
                name = item.resource_name.lower()
                if any(k in name for k in keywords):
                    findings.append(SecurityFinding(item.resource_name, item.service, "sensitive-name"))
        return findings

    def find_secrets_exposed_public(self, items: list[InventoryItem]) -> list[SecurityFinding]:
        """Flag secrets that are marked public or whose metadata suggests exposure.

        Scanners may set `public=True` for S3-like resources; for secrets this is a best-effort
        check that inspects the `public` flag and `details` for potential ACL/policy exposure.
        """
        findings: list[SecurityFinding] = []
        for item in items:
            if item.service in ("SecretsManager", "SSM"):
                if getattr(item, "public", False):
                    findings.append(SecurityFinding(item.resource_name, item.service, "publicly-exposed"))
                    continue
                # look for obvious policy strings in details
                try:
                    details = item.details or {}
                    policy = details.get("Policy") or details.get("ResourcePolicy") or ""
                    if isinstance(policy, str) and ("*" in policy or "Principal" in policy and "Allow" in policy):
                        findings.append(SecurityFinding(item.resource_name, item.service, "possible-policy-exposure"))
                except Exception:
                    continue
        return findings

    def analyze_all(self, items: list[InventoryItem]) -> list[SecurityFinding]:
        """Run all security heuristics and return combined findings."""
        findings: list[SecurityFinding] = []
        findings.extend(self.find_public_s3_buckets(items))
        findings.extend(self.find_secrets_with_sensitive_names(items))
        findings.extend(self.find_secrets_exposed_public(items))
        return findings
