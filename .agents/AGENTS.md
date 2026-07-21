# Agent Customizations

## 1. Implementation Documents
Every implementation plan and walkthrough must be saved in the `Implementation docs` folder (`.agents/Implementation docs/`).
- Implementation plans should be named following the pattern: `implementation plan_PhaseX_V.x.md` (if there are multiple plans of the same phase).
- Walkthroughs should be named similarly to the implementation plan.
- Any changes made to the implementation plan or walkthrough must be documented and saved in the `Implementation docs` folder.
- the walkthrough should include everything mentioned in the implementation plan.
- Read previous implementation plan and walkthrough to understand the context and what has already been implemented.

## 2. Action Logging (Audit Trail)
Every action the agent takes must be recorded in the `logs` folder (`.agents/logs/`). This serves as an audit trail for what the agent does. 
When making code changes, always append a log entry for the session.
It should also include all the commands the agent runs. No file should be left un-logged.

Example log format:
```text
=== Session_[timestamp] ===
add: supabase/migrations/007_purchase_orders.sql
add: src/services/supplierService.js
edit: src/pages/purchase/index.jsx
command: npm run dist 
fix: useDebounce hook import
     problem: SupplierAutocomplete and ItemAutocomplete crashed because useDebounce was imported as a named export instead of a default export.
     solution: Changed import to default export in both files.
git: git commit [commit id] [commit name]

=== Session_[timestamp] ===

add: ...
command: ...
edit:
fix:
git:
```
