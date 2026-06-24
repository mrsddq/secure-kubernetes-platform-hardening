import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SecurityControlsTest(unittest.TestCase):
    def test_namespace_uses_restricted_pod_security(self):
        text = (ROOT / "kubernetes" / "base" / "namespace.yaml").read_text(encoding="utf-8")
        self.assertIn("pod-security.kubernetes.io/enforce: restricted", text)

    def test_network_default_deny_exists(self):
        text = (ROOT / "kubernetes" / "networkpolicies" / "default-deny.yaml").read_text(encoding="utf-8")
        self.assertIn("policyTypes:", text)
        self.assertIn("Ingress", text)
        self.assertIn("Egress", text)

    def test_workload_has_security_context_and_probes(self):
        text = (ROOT / "kubernetes" / "workloads" / "secure-api.yaml").read_text(encoding="utf-8")
        self.assertIn("runAsNonRoot: true", text)
        self.assertIn("allowPrivilegeEscalation: false", text)
        self.assertIn("readinessProbe:", text)
        self.assertIn("livenessProbe:", text)

    def test_kyverno_policies_cover_core_controls(self):
        policy_text = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "policies" / "kyverno").glob("*.yaml"))
        for phrase in ("require-non-root", "disallow-latest-images", "require-resources-probes", "disallow-privileged"):
            self.assertIn(phrase, policy_text)


if __name__ == "__main__":
    unittest.main()
