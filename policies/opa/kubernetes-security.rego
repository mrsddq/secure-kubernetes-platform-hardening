package kubernetes.security

import rego.v1

# Accept a raw Kubernetes object (CLI) or a standard AdmissionReview (webhook).
# This is a standalone OPA policy, not a Gatekeeper ConstraintTemplate.
resource := object.get(object.get(input, "request", {}), "object", input)

containers contains container if {
    resource.kind == "Pod"
    some field in ["containers", "initContainers", "ephemeralContainers"]
    container := object.get(resource.spec, field, [])[_]
}

deny contains msg if {
    some container in containers
    not regex.match(`^[^@]+@sha256:[a-f0-9]{64}$`, object.get(container, "image", ""))
    msg := sprintf("container %s must use an image digest", [container.name])
}

deny contains msg if {
    some container in containers
    security := object.get(container, "securityContext", {})
    object.get(security, "allowPrivilegeEscalation", true) != false
    msg := sprintf("container %s allows privilege escalation", [container.name])
}

deny contains msg if {
    some container in containers
    security := object.get(container, "securityContext", {})
    object.get(security, "privileged", false) == true
    msg := sprintf("container %s is privileged", [container.name])
}

# Ephemeral containers cannot specify resources; only regular/init containers are checked.
deny contains msg if {
    resource.kind == "Pod"
    some field in ["containers", "initContainers"]
    container := object.get(resource.spec, field, [])[_]
    limits := object.get(object.get(container, "resources", {}), "limits", {})
    object.get(limits, "cpu", "") == ""
    msg := sprintf("container %s has no CPU limit", [container.name])
}
