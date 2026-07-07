from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ConfigLoader:
    def __init__(self, config_path: str | None = None):
        self.config_path = Path(config_path or "config.yaml")

    def load(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {"default": {"output_dir": "reports", "regions": ["us-east-1"], "profile": "default"}}
        with self.config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return data.get("default", data)
