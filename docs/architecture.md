# Architecture Notes

The inventory platform is designed around a clean separation of responsibilities:

1. CLI entrypoint handles user interaction.
2. Configuration and session objects provide AWS connection context.
3. Scanner modules discover resources from AWS APIs.
4. InventoryItem models normalize resource metadata into a common schema.
5. Exporters write the normalized data into human-readable reports.
6. Report analyzers identify security and cost optimization opportunities.

This structure makes it easier to add more services and keep the codebase maintainable as the project grows.
