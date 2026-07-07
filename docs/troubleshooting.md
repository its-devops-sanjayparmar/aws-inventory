# Troubleshooting

## Common issues
- Missing credentials: configure AWS CLI profiles or set environment credentials
- No permissions: ensure the IAM policy grants read-only Describe and List actions
- Export failures: confirm pandas/openpyxl are installed
- Import errors like `ModuleNotFoundError: No module named 'core'`: ensure package directories such as `core/`, `scanners/`, `exporters/`, and `reports/` contain `__init__.py`.
