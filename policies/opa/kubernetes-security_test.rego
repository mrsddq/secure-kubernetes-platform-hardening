package kubernetes.security_test

import rego.v1
import data.kubernetes.security.deny

image := "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
container := {"name": "app", "image": image, "securityContext": {"allowPrivilegeEscalation": false}, "resources": {"limits": {"cpu": "100m"}}}
pod := {"kind": "Pod", "spec": {"containers": [container]}}

test_raw_pod_allows_valid_container if { count(deny) == 0 with input as pod }
test_admission_review_allows_valid_pod if { count(deny) == 0 with input as {"request": {"object": pod}} }
test_untagged_image_denied if {
    bad := object.union(container, {"image": "nginx"})
    count(deny) == 1 with input as {"kind": "Pod", "spec": {"containers": [bad]}}
}
test_version_tag_is_mutable if {
    bad := object.union(container, {"image": "nginx:1.27"})
    count(deny) == 1 with input as {"request": {"object": {"kind": "Pod", "spec": {"containers": [bad]}}}}
}
test_init_container_image_denied if {
    bad := object.union(container, {"image": "nginx:latest"})
    count(deny) == 1 with input as {"kind": "Pod", "spec": {"containers": [container], "initContainers": [bad]}}
}
test_ephemeral_container_image_denied if {
    bad := object.union(container, {"image": "nginx"})
    count(deny) == 1 with input as {"kind": "Pod", "spec": {"containers": [container], "ephemeralContainers": [bad]}}
}
test_missing_escalation_control_denied if {
    bad := object.remove(container, ["securityContext"])
    count(deny) == 1 with input as {"kind": "Pod", "spec": {"containers": [bad]}}
}
test_privileged_container_denied if {
    bad := object.union(container, {"securityContext": {"allowPrivilegeEscalation": false, "privileged": true}})
    count(deny) == 1 with input as {"kind": "Pod", "spec": {"containers": [bad]}}
}
test_missing_cpu_limit_denied if {
    bad := object.remove(container, ["resources"])
    count(deny) == 1 with input as {"kind": "Pod", "spec": {"containers": [bad]}}
}
test_ephemeral_container_does_not_require_resource_limits if {
    debug := object.remove(container, ["resources"])
    count(deny) == 0 with input as {"kind": "Pod", "spec": {"containers": [container], "ephemeralContainers": [debug]}}
}
test_other_kind_ignored if { count(deny) == 0 with input as {"kind": "ConfigMap"} }
