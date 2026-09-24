# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `kustomize.literal-secret` | Critical | Credential-shaped literals embedded by `secretGenerator` |
| `kustomize.mutable-remote` | High | Remote resources pinned to mutable `main`, `master`, or `HEAD` refs |
| `kustomize.configmap-secret-shaped` | High | Credential-shaped data placed in `configMapGenerator` literals |
| `kustomize.patch-privilege-escalation` | High | YAML patches that add privileged mode, host namespaces, `hostPath`, or dangerous capabilities |
| `kustomize.api-version-json-patch` | High | JSON patches that add or replace a resource's `/apiVersion` |
| `kustomize.latest-image` | Medium | Image overrides using mutable `latest`, `main`, or `edge` tags |
| `kustomize.name-suffix-hash-disabled` | Medium | `generatorOptions.disableNameSuffixHash: true` |
| `kustomize.deprecated-patches-strategic-merge` | Low | Use of the deprecated `patchesStrategicMerge` field |
