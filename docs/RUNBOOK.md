# Runbook

## New Namespace Onboarding

1. Apply restricted Pod Security labels.
2. Add default-deny ingress and egress policies.
3. Create a service account with minimal Role permissions.
4. Add required Kyverno policy exceptions only when justified.
5. Confirm workloads have probes, resource limits, and non-root containers.

## When A Deployment Is Blocked

1. Check Kyverno or admission controller events.
2. Identify the denied rule.
3. Fix the workload manifest if possible.
4. If an exception is required, document owner, expiry, and reason.
5. Re-run CI before applying.

## Security Review Checklist

- No privileged pods.
- No hostPath mounts without exception.
- No `latest` image tags.
- No broad wildcard RBAC.
- No default service account usage.
- No committed secret values.
