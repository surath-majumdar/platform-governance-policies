package main

import rego.v1

governed_types := {
    "kubernetes_namespace",
    "kubernetes_namespace_v1",
    "kubernetes_deployment",
    "kubernetes_deployment_v1",
}

is_create_or_update(actions) if {
    some action in actions
    action in {"create", "update"}
}

# Rule 1: Require cost-center label
deny contains msg if {
    some rc in input.resource_changes
    rc.type in governed_types
    is_create_or_update(rc.change.actions)

    labels := object.get(rc.change.after.metadata[0], "labels", {})
    not labels["cost-center"]

    msg := sprintf("FinOps Violation: Resource '%s' (%s) is missing the required 'cost-center' label.", [rc.address, rc.type])
}

# Rule 2: Enforce standard cost-center format (CC-1001)
deny contains msg if {
    some rc in input.resource_changes
    rc.type in governed_types
    is_create_or_update(rc.change.actions)

    labels := object.get(rc.change.after.metadata[0], "labels", {})
    cc := labels["cost-center"]
    not regex.match(`^CC-[0-9]{4}$`, cc)

    msg := sprintf("FinOps Violation: Resource '%s' has invalid cost-center '%s'. Must match 'CC-XXXX' (e.g., CC-1001).", [rc.address, cc])
}