# Resumable release state machine

`scripts/release_state.py` models the local release evidence boundary:

```text
DISCOVER -> QUALIFY -> FREEZE -> REVIEW -> MERGE -> VERIFY_MAIN -> BUILD
  -> VERIFY_DRAFT -> HUMAN_AUTHORIZE -> PUBLISH_ONCE -> VERIFY_PUBLIC
```

The state file binds a version, source commit, source tree, and artifact
manifest. A transition is idempotent only when the binding is identical. A
wrong head/tree, backwards transition, existing immutable tag, artifact drift,
failed upstream gate, missing attestation, or expired exception is rejected.
The script is read/write only on a caller-selected local state file; it never
pushes, merges, publishes, deletes, retags, or creates a public dummy release.

`HUMAN_AUTHORIZE` is an explicit boundary. Machine review is not substituted
for a human decision where a selected standard or owner policy requires one.
`PUBLISH_ONCE` can be recorded only after the caller has read the actual remote
state and supplied an approval receipt. Public verification remains a separate
state and is never inferred from a green local build.

Run the unit tests before using the helper. Keep the state file with the launch
evidence and preserve failed publication attempts as evidence.
