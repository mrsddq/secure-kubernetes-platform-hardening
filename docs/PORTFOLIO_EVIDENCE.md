# Portfolio Evidence

This repo demonstrates Kubernetes security guardrails that a platform team can standardize across namespaces and workloads.

## Verified Locally

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests
python scripts/validate_layout.py
make policy-test # OPA 1.8.0 and Kyverno CLI 1.15.2
```

## Reviewer Evidence

| Evidence | Location | What it proves |
|---|---|---|
| CI badge | `README.md` | Static checks, blocking OPA/Kyverno behavioral tests, and an advisory Trivy config scan. |
| PSS labels | `kubernetes/base/namespace.yaml` | Restricted Pod Security Standards baseline. |
| Network isolation | `kubernetes/networkpolicies/` | Default-deny and scoped allow policies. |
| Least privilege | `kubernetes/rbac/` | Narrow service account permissions. |
| Hardened workload | `kubernetes/workloads/secure-api.yaml` | Non-root, read-only filesystem, probes and resources. |
| Admission policies | `policies/kyverno/` and `policies/opa/` | Tested policy decisions; live admission requires installed controllers. |
| Threat model | `docs/THREAT_MODEL.md` | Security risks mapped to controls. |
