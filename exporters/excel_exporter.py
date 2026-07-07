from __future__ import annotations

from pathlib import Path

import pandas as pd

from core.models import InventoryItem


class ExcelExporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, items: list[InventoryItem], filename: str) -> str:
        rows = [item.to_row() for item in items]
        df = pd.DataFrame(rows)
        path = self.output_dir / filename
        with pd.ExcelWriter(path) as writer:
            df.to_excel(writer, sheet_name="Inventory", index=False)
        return str(path)
