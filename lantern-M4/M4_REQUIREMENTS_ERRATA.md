# M4 prerequisite interface errata

This document records two prerequisite corrections discovered when binding the
approved M4 semantics to the accepted M0/M1 APIs. The normative requirements
document has been updated before code changes, as required by the module
discipline.

## E1: signed initial administrative key

The initial `ControlActionV1::Enable` must carry `initial_admin_key`. Because
the action is inside canonical `ControlEventV1`, the control-domain signature
binds the new authority. The initial event verifies under that same embedded
key. A rollover-preauthorized successor must present the identical embedded
key when it is later enabled.

Without this field, an application has no authenticated source for the key
that is supposed to verify the first Enable and all later control events.
Supplying it in an unsigned wrapper or local node configuration would make
replicas disagree or permit authority substitution.

Compatibility action: extend the M0 Enable array from two to three fields,
regenerate M0 vectors, and add wrong-key/substitution negative tests. Existing
Disable, Cancel, Rollover, and Terminal encodings remain unchanged.

## E2: epoch-zero presence

M1 commit metadata and snapshot manifests must represent
`last_closed_epoch: Option<u64>` together with `last_closed_head_id`.

- `None/None`: no epoch has closed;
- `Some(0)/Some(head)`: epoch zero has closed;
- `Some(e)/Some(head)`: later epoch `e` has closed.

The existing fixed-width metadata already has a closed-head presence byte, so
the on-disk length does not change. When the flag is absent, the epoch bytes
must be zero; when present, epoch zero is legal. Successor validation compares
the optional epochs and forbids a HeadID change without epoch advancement.

Snapshot JSON changes `last_closed_epoch` from a mandatory number to an
optional number. This is a snapshot-format schema change and therefore bumps
the external snapshot format version; old snapshot manifests fail closed
rather than being ambiguously interpreted.

## Traceability

| Security requirement | Corrected binding | Required tests |
| --- | --- | --- |
| Initial admin authority | signed `Enable.initial_admin_key` | canonical vector, substituted key/signature rejection |
| Head chain starts at epoch zero | optional epoch + HeadID pair | epoch-zero commit/reopen and snapshot restore |
| Monotonic closed-head state | optional successor comparison | regression and same-epoch/different-HeadID rejection |

These corrections do not implement M5 consensus/QC behavior and do not alter
the accepted M2 JMT or M3 MMR proof formats.
