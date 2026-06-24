# Portfolio Evidence

This repo demonstrates Kubernetes security guardrails that a platform team can standardize across namespaces and workloads.

## Verified Locally

```bash
python -m unittest discover -s tests
python scripts/validate_layout.py
```

## Reviewer Evidence

| Evidence | Location | What it proves |
|---|---|---|
| CI badge | `README.md` | Static control validation and Trivy config scan run in CI. |
| PSS labels | `kubernetes/base/namespace.yaml` | Restricted Pod Security Standards baseline. |
| Network isolation | `kubernetes/networkpolicies/` | Default-deny and scoped allow policies. |
| Least privilege | `kubernetes/rbac/` | Narrow service account permissions. |
| Hardened workload | `kubernetes/workloads/secure-api.yaml` | Non-root, read-only filesystem, probes and resources. |
| Admission policies | `policies/kyverno/` and `policies/opa/` | Enforced and explainable guardrails. |
| Threat model | `docs/THREAT_MODEL.md` | Security risks mapped to controls. |
