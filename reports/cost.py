from __future__ import annotations

from dataclasses import dataclass

from core.models import InventoryItem


@dataclass
class CostFinding:
    resource_name: str | None
    service: str
    finding: str


class CostAnalyzer:
    def find_unattached_volumes(self, items: list[InventoryItem]) -> list[CostFinding]:
        findings: list[CostFinding] = []
        for item in items:
            if item.service == "EBS" and item.resource_type == "volume" and item.status == "available":
                findings.append(CostFinding(item.resource_name, item.service, "unattached volume"))
        return findings

    def find_budget_gaps(self, items: list[InventoryItem]) -> list[CostFinding]:
        """Identify budgets that are close to or exceeding current spend.

        Heuristic: for each `Budgets` item, compare its `BudgetLimit` (if present) to the
        corresponding `CostExplorer` summary in the items list. If spend >= 90% of budget,
        flag as `approaching budget`; if spend > budget, flag as `budget exceeded`.
        """
        findings: list[CostFinding] = []
        budgets: dict[str, float] = {}
        costs: list[dict] = []

        for item in items:
            if item.service == "Budgets":
                try:
                    details = item.details or {}
                    # BudgetLimit may be a dict like {'Amount': '10', 'Unit': 'USD'}
                    limit = details.get("BudgetLimit") or (details.get("Budget", {}).get("BudgetLimit") if isinstance(details, dict) else None)
                    if isinstance(limit, dict):
                        amt = float(limit.get("Amount", 0))
                        budgets[item.resource_name or "unknown"] = amt
                except Exception:
                    continue
            if item.service == "CostExplorer":
                try:
                    details = item.details or {}
                    costs.append(details)
                except Exception:
                    continue

        # Simple aggregation: take the most recent cost amount from CostExplorer details
        recent_cost = None
        for d in costs:
            try:
                rbt = d.get("ResultsByTime", [])
                if rbt:
                    total = rbt[0].get("Total", {})
                    ub = total.get("UnblendedCost") or total.get("BlendedCost") or {}
                    amt = ub.get("Amount") if isinstance(ub, dict) else None
                    if amt is not None:
                        recent_cost = float(amt)
                        break
            except Exception:
                continue

        for name, limit in budgets.items():
            if recent_cost is None:
                continue
            if recent_cost > limit:
                findings.append(CostFinding(name, "Budgets", "budget exceeded"))
            elif recent_cost >= 0.9 * limit:
                findings.append(CostFinding(name, "Budgets", "approaching budget"))

        return findings

    def analyze_costs(self, items: list[InventoryItem]) -> list[CostFinding]:
        """Run all cost heuristics and return combined findings."""
        findings: list[CostFinding] = []
        findings.extend(self.find_unattached_volumes(items))
        findings.extend(self.find_budget_gaps(items))
        return findings
