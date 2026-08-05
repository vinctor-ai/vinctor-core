# Demo Policy Templates

These policy files are non-secret local demo inputs for:

```bash
vinctor --db .vinctor-local.sqlite \
  --workspace-id ws_local \
  operator policy apply --file docs/examples/policies/ci.yaml
```

## Templates

| File | Use |
| --- | --- |
| `ci.yaml` | Auto-approve CI test/build requests. |
| `repo-write-boundary.yaml` | Allow manual approval for writes inside `vinctor-core`. |
| `secret-read.yaml` | Show disabled high-risk secret-read policy input. |
| `deploy-manual-review.yaml` | Auto-approve staging deploys while keeping production deploys manual. |
| `sibling-repo-deny.yaml` | Demonstrate that `write:repo/vinctor-core/*` does not allow sibling repo writes. |

These templates configure service-layer issuance policy. They do not grant
authority until a request is approved and a scoped grant is issued.
