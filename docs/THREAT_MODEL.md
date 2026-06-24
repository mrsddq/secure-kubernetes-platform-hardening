# Threat Model

## Assets

- Kubernetes API access
- Workload identities and service accounts
- Secrets and external secret references
- Application network paths
- Container images and runtime configuration

## Primary Risks

- Privilege escalation through pod security context
- Lateral movement through open network paths
- Secret exposure through committed manifests or broad RBAC
- Unreviewed image changes through mutable tags
- Excessive service account permissions

## Controls In This Repo

- Restricted Pod Security Standards labels
- Default-deny network policies
- Least-privilege RBAC
- Immutable image tag policy
- Non-root and read-only filesystem policy
- Secret delivery templates without secret material
