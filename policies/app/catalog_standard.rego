package main

import rego.v1

is_catalog if {
    is_object(input)
}

# Rule 1: Require owner
deny contains msg if {
    is_catalog
    not input.spec.owner

    msg := "Repo Standard Violation (catalog-info.yaml): Missing required 'spec.owner'."
}

# Rule 2: Require valid lifecycle
valid_lifecycles := {"experimental", "production", "deprecated"}

deny contains msg if {
    is_catalog
    not input.spec.lifecycle in valid_lifecycles

    msg := "Repo Standard Violation (catalog-info.yaml): 'spec.lifecycle' must be one of: experimental, production, deprecated."
}

# Rule 3: Require FinOps cost-center annotation
deny contains msg if {
    is_catalog
    annotations := object.get(input.metadata, "annotations", {})
    cc := annotations["finops/cost-center"]
    not regex.match(`^CC-[0-9]{4}$`, cc)

    msg := "Repo Standard Violation (catalog-info.yaml): 'metadata.annotations[\"finops/cost-center\"]' must match 'CC-XXXX'."
}

deny contains msg if {
    is_catalog
    annotations := object.get(input.metadata, "annotations", {})
    not annotations["finops/cost-center"]

    msg := "Repo Standard Violation (catalog-info.yaml): Missing required 'metadata.annotations[\"finops/cost-center\"]'."
}