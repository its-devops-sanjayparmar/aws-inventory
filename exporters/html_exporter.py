from __future__ import annotations

from pathlib import Path

from core.models import InventoryItem


class HTMLExporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, items: list[InventoryItem], filename: str) -> str:
        path = self.output_dir / filename
        rows = "\n".join(
            f"<tr><td>{item.service}</td><td>{item.resource_name or ''}</td><td>{item.region or ''}</td></tr>"
            for item in items
        )
        html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head><meta charset=\"utf-8\" /><title>AWS Inventory Dashboard</title></head>
<body>
  <h1>AWS Inventory Dashboard</h1>
  <p>Total resources: {len(items)}</p>
  <table>
    <thead><tr><th>Service</th><th>Resource</th><th>Region</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
        path.write_text(html, encoding="utf-8")
        return str(path)
