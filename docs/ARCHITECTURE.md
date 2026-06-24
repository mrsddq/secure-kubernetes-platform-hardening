# Architecture

This repo models security as platform guardrails instead of one-off application changes.

## Layers

1. Namespace security labels set Pod Security Standards.
2. RBAC constrains what workloads and humans can do.
3. NetworkPolicies isolate traffic by default.
4. Admission policies enforce runtime and image rules.
5. Secret templates define safe delivery without committing secret values.
6. CI scans policy and manifest structure before merge.

## Production Rollout

Start in audit mode for admission policies, review denied events, then move stable controls into enforce mode. Keep exceptions narrow, time-bound, and documented.
