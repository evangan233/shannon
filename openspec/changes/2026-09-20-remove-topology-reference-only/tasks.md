## 1. Frontend

- [x] 1.1 Remove the reference-only checkbox from `NodePanel` and the `setTopologyReferenceOnly` import/usage in `TopologyEditor.tsx`.
- [x] 1.2 Render `isolated_node` as a non-blocking warning (amber) in the editor bottom validation list; keep other issues destructive.
- [x] 1.3 Remove `TopologyNodeDraft.referenceOnly`, `setTopologyReferenceOnly`, the fingerprint field, and the YAML→draft inheritance in `correlation-topology-draft.ts`.
- [x] 1.4 Make `confirmTopologyDraft` ignore `isolated_node` as a blocking issue; keep it in `validateTopologyDraft` output.
- [x] 1.5 Update the isolated-node test to assert the warning stays while confirmation succeeds; remove the reference-only exemption assertions.
- [x] 1.6 Remove the `topology.referenceOnly` i18n key and reword `issues.isolated_node` (zh/en).

## 2. Spec & verification

- [x] 2.1 Update the `cross-repo-topology-discovery` spec delta: isolated repository warning no longer blocks confirmation.
- [x] 2.2 Run `correlation-topology-draft` unit tests and frontend typecheck/build.
