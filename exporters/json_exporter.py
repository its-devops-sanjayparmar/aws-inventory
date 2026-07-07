from __future__ import annotations

import json
from pathlib import Path

from core.models import InventoryItem


class JSONExporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, items: list[InventoryItem], filename: str) -> str:
        path = self.output_dir / filename
        with path.open("w", encoding="utf-8") as handle:
            json.dump([item.to_row() for item in items], handle, indent=2)
        return str(path)
