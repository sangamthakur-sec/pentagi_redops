---
name: web-sqli
description: SQL injection — detected, exploited to impact, proven with a control case.
metadata:
  sources_read: "2026-10-15"
---

# SQL injection

## Read first

1. This list is not the workflow.

## Workflow

Execute these steps within whatever phase the coordinator has placed you in.

1. **Identify injection points** — every input that reaches an interpreter: query/body/JSON params,
   headers, cookies, path segments.
2. **Detect the class** with minimal, read-only probes:
```
1. this numbered line is inside a code block
```
   - a nested bullet stays with step 2
3. **Load the matching reference — mandatory gate before any exploit payload.** You MUST have read
   `reference/INDEX.md`; destructive-to-others operations (DROP, mass-delete, DoS) stay out of bounds.

Every applicable class is driven to a verdict.

4. Report to standard. This numbered line follows a closing paragraph and still belongs to the list.

### Notes inside workflow

Text under a deeper heading is skipped.

## Anti-Patterns

1. Not a step.
