import csv
import html
import os
from datetime import datetime
from typing import Iterable

from reports.security import SecurityFinding
from reports.cost import CostFinding


class ReportExporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir

    def export_findings(self, security_findings: Iterable[SecurityFinding], cost_findings: Iterable[CostFinding]) -> dict[str, str]:
        """Write findings to CSV and a small HTML summary. Returns dict of paths."""
        sec_path = f"{self.output_dir}/security_findings.csv"
        cost_path = f"{self.output_dir}/cost_findings.csv"
        html_path = f"{self.output_dir}/findings_summary.html"

        # write security CSV
        with open(sec_path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["service", "resource_name", "finding"])
            for f in security_findings:
                w.writerow([f.service, f.resource_name, f.finding])

        # write cost CSV
        with open(cost_path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["service", "resource_name", "finding"])
            for f in cost_findings:
                w.writerow([f.service, f.resource_name, f.finding])

        # write enhanced HTML summary with counts and links
        sec_list = list(security_findings)
        cost_list = list(cost_findings)
        timestamp = datetime.utcnow().isoformat()
        with open(html_path, "w") as fh:
            fh.write("<html><head><meta charset=\"utf-8\"><title>Inventory Findings Summary</title>")
            fh.write("<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px}h1{color:#2b6ea3}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f4f4f4}</style>")
            fh.write("</head><body>")
            fh.write(f"<h1>Inventory Findings Summary</h1><p>Generated: {html.escape(timestamp)}</p>")
            # Links to inventory artifacts if present
            fh.write("<p>Artifacts: ")
            for name in ("inventory.csv", "inventory.json", "inventory.xlsx", "inventory.html"):
                path = os.path.join(self.output_dir, name)
                if os.path.exists(path):
                    fh.write(f"<a href=\"{html.escape(path)}\">{html.escape(name)}</a> ")
                else:
                    fh.write(f"{html.escape(name)} ")
            fh.write("</p>")

            fh.write(f"<h2>Security Findings ({len(sec_list)})</h2>")
            if sec_list:
                fh.write("<table><tr><th>Service</th><th>Resource</th><th>Finding</th></tr>")
                for f in sec_list:
                    fh.write(f"<tr><td>{html.escape(f.service)}</td><td>{html.escape(str(f.resource_name))}</td><td>{html.escape(f.finding)}</td></tr>")
                fh.write("</table>")
            else:
                fh.write("<p>No security findings.</p>")

            fh.write(f"<h2>Cost Findings ({len(cost_list)})</h2>")
            if cost_list:
                fh.write("<table><tr><th>Service</th><th>Resource</th><th>Finding</th></tr>")
                for f in cost_list:
                    fh.write(f"<tr><td>{html.escape(f.service)}</td><td>{html.escape(str(f.resource_name))}</td><td>{html.escape(f.finding)}</td></tr>")
                fh.write("</table>")
            else:
                fh.write("<p>No cost findings.</p>")

            fh.write("</body></html>")

        return {"security_csv": sec_path, "cost_csv": cost_path, "html": html_path}
