from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "README.md",
    ".github/workflows/ci.yml",
    "kubernetes/base/namespace.yaml",
    "kubernetes/networkpolicies/default-deny.yaml",
    "kubernetes/rbac/service-account.yaml",
    "kubernetes/workloads/secure-api.yaml",
    "kubernetes/secrets/external-secret.yaml",
    "policies/kyverno/require-non-root.yaml",
    "policies/kyverno/disallow-latest-images.yaml",
    "policies/opa/kubernetes-security.rego",
    "docs/THREAT_MODEL.md",
]


def main() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        raise SystemExit(f"missing required files: {', '.join(missing)}")
    print("secure platform layout validation passed")


if __name__ == "__main__":
    main()
