from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class InventoryItem:
    account_id: str | None = None
    account_alias: str | None = None
    region: str | None = None
    service: str = "Unknown"
    resource_name: str | None = None
    resource_id: str | None = None
    arn: str | None = None
    status: str | None = None
    creation_date: str | None = None
    owner: str | None = None
    tags: dict[str, Any] = field(default_factory=dict)
    encryption: str | None = None
    public: bool | None = None
    resource_type: str | None = None
    platform: str | None = None
    availability_zone: str | None = None
    relationships: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "account_alias": self.account_alias,
            "region": self.region,
            "service": self.service,
            "resource_name": self.resource_name,
            "resource_id": self.resource_id,
            "arn": self.arn,
            "status": self.status,
            "creation_date": self.creation_date,
            "owner": self.owner,
            "tags": self.tags,
            "encryption": self.encryption,
            "public": self.public,
            "resource_type": self.resource_type,
            "platform": self.platform,
            "availability_zone": self.availability_zone,
            "relationships": ";".join(self.relationships),
            "details": self.details,
        }