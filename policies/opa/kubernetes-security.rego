package kubernetes.security

deny[msg] {
  input.kind.kind == "Pod"
  container := input.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("container %s uses latest image tag", [container.name])
}

deny[msg] {
  input.kind.kind == "Pod"
  container := input.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("container %s has no CPU limit", [container.name])
}

deny[msg] {
  input.kind.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation != false
  msg := sprintf("container %s allows privilege escalation", [container.name])
}
