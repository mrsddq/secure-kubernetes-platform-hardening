"""Run positive/negative fixtures against the real Kyverno engine, without a cluster."""
from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    deployment = yaml.safe_load((ROOT / "kubernetes/workloads/secure-api.yaml").read_text())
    baseline = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "valid", "namespace": "secure-app"},
                "spec": deployment["spec"]["template"]["spec"]}
    cases = [("valid", baseline, {})]
    for name, image in [("latest", "nginx:latest"), ("untagged", "nginx"),
                        ("mutable-tag", "nginx:1.27"), ("short-digest", "nginx@sha256:abc")]:
        pod = deepcopy(baseline)
        pod["spec"]["containers"][0]["image"] = image
        cases.append((name, pod, {"require-image-digest": "fail"}))
    for field in ("initContainers", "ephemeralContainers"):
        pod = deepcopy(baseline)
        extra = deepcopy(pod["spec"]["containers"][0])
        extra["name"] = "extra"
        for key in ("livenessProbe", "readinessProbe"):
            extra.pop(key, None)
        if field == "ephemeralContainers":
            for key in ("resources", "ports"):
                extra.pop(key, None)
        extra["image"] = "nginx:latest"
        pod["spec"][field] = [extra]
        cases.append((field.lower() + "-image", pod, {"require-image-digest": "fail"}))
        pod = deepcopy(baseline)
        extra = deepcopy(pod["spec"]["containers"][0])
        extra["name"] = "extra"
        for key in ("livenessProbe", "readinessProbe"):
            extra.pop(key, None)
        if field == "ephemeralContainers":
            for key in ("resources", "ports"):
                extra.pop(key, None)
        extra["securityContext"]["allowPrivilegeEscalation"] = True
        pod["spec"][field] = [extra]
        cases.append((field.lower() + "-privilege", pod, {"disallow-privileged-containers": "fail"}))
    pod = deepcopy(baseline)
    del pod["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"]
    cases.append(("missing-escalation", pod, {"disallow-privileged-containers": "fail"}))
    for setting, value in (("runAsNonRoot", False), ("runAsUser", 0)):
        pod = deepcopy(baseline)
        pod["spec"]["containers"][0]["securityContext"][setting] = value
        cases.append((setting.lower(), pod, {"disallow-container-root-override": "fail"}))
    pod = deepcopy(baseline)
    del pod["spec"]["containers"][0]["resources"]["limits"]["cpu"]
    cases.append(("missing-cpu", pod, {"require-resources": "fail"}))
    pod = deepcopy(baseline)
    del pod["spec"]["containers"][0]["readinessProbe"]
    cases.append(("missing-readiness", pod, {"require-resources": "fail"}))
    rules = {"disallow-latest-images": ["require-image-digest"],
             "disallow-privileged": ["disallow-privileged-containers"],
             "require-non-root": ["require-pod-run-as-non-root", "disallow-container-root-override"],
             "require-resources-probes": ["require-resources"]}
    results = []
    for name, pod, failures in cases:
        pod["metadata"]["name"] = name
        for policy, names in rules.items():
            for rule in names:
                results.append({"policy": policy, "rule": rule, "resources": [name], "kind": "Pod",
                                "result": failures.get(rule, "pass")})
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        (directory / "resources.yaml").write_text(yaml.safe_dump_all([pod for _, pod, _ in cases]))
        (directory / "kyverno-test.yaml").write_text(yaml.safe_dump({
            "apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Test", "metadata": {"name": "admission-regressions"},
            "policies": [str(path) for path in sorted((ROOT / "policies/kyverno").glob("*.yaml"))],
            "resources": ["resources.yaml"], "results": results}))
        subprocess.run(["kyverno", "test", str(directory)], check=True)


if __name__ == "__main__":
    main()
