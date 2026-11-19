# Platform Governance Policies

Centralized, read-only **Policy-as-Code (OPA/Rego)** repository owned by the Platform & Governance Team.

## Architecture & Separation of Duties
Application and infrastructure repositories do **not** store Rego policies locally. Instead, they act as **thin pointers** that pull these policies remotely at build and deploy time via `conftest --update`. This prevents developer tampering, eliminates template drift, and ensures policy updates propagate across the entire fleet immediately.

Changes to this repository are restricted via `.github/CODEOWNERS` and branch protection rules.

## Policy Domains

### 1. Infrastructure & FinOps (`policies/infra/`)
* **`cost_center.rego`**: Inspects Terraform JSON plans (`terraform show -json`) before `terraform apply`. Blocks Kubernetes Namespaces and Deployments missing a valid `cost-center` label matching `CC-XXXX` (e.g., `CC-1001`).

### 2. Application Security & Repo Standardization (`policies/app/`)
* **`dockerfile_security.rego`**: Blocks mutable `:latest` tags, untagged base images, and containers running as `root`.
* **`catalog_standard.rego`**: Validates Backstage `catalog-info.yaml` files to enforce `spec.owner`, valid `spec.lifecycle`, and the `finops/cost-center` annotation.

## Usage (Thin-Pointer Invocation)

**Infra Repos (Pre-Apply Front-Gate):**
```bash
conftest test tfplan.json \
  --update git::https://github.com/surath-majumdar/platform-governance-policies.git//policies/infra