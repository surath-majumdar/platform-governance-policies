package main

import rego.v1

is_dockerfile if {
    is_array(input)
}

# Rule 1: Disallow :latest base image tags
deny contains msg if {
    is_dockerfile
    some i
    input[i].Cmd == "from"
    val := input[i].Value[0]
    endswith(val, ":latest")

    msg := sprintf("Security Violation (Dockerfile): Base image '%s' uses mutable ':latest' tag. Pin to an explicit version.", [val])
}

# Rule 2: Disallow untagged base images
deny contains msg if {
    is_dockerfile
    some i
    input[i].Cmd == "from"
    val := input[i].Value[0]
    val != "scratch"
    not contains(val, ":")

    msg := sprintf("Security Violation (Dockerfile): Base image '%s' is missing an explicit version tag.", [val])
}

# Rule 3: Require a non-root USER
has_non_root_user if {
    some i
    input[i].Cmd == "user"
    user := lower(input[i].Value[0])
    user != "root"
    user != "0"
}

deny contains msg if {
    is_dockerfile
    not has_non_root_user

    msg := "Security Violation (Dockerfile): Container must define a non-root USER instruction."
}
