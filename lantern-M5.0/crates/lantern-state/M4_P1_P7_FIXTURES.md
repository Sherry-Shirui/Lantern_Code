# M4 P1–P7 authenticated fixture matrix

The test `p1_through_p7_authenticated_fixture_matrix_is_constructible` builds
this matrix through the real M1/M2/M3/M4 path. It does not substitute a legacy
Merkle prototype and does not claim an M8 Routinator verdict.

| Predicate | M4 fixture and assertion | Deferred consumer |
| --- | --- | --- |
| P1 | `AppState.last_closed_epoch = 1`, heads 0/1 exist, current head 2 is absent | M6 packages absence/staleness; M8 applies policy |
| P2 | A strict M2 membership proof decodes to `status = Disabled` | M8 maps authenticated disabled state to legacy handling |
| P3 | A strict M2 membership proof decodes to Enabled and its effective manifest hash equals the observed exact hash; Cancel fixtures also retrieve and verify the archived admin authorization plus the restored EE intent digest | M8 accepts only after QC/proof-package checks |
| P4 | An older Publish record has a verified M3 inclusion proof and `current_epoch - admission_epoch <= G` | M8 grace policy |
| P5 | The same authenticated old record is evaluated at a later epoch where age exceeds `G`, while M2 latest differs | M8 stale policy |
| P6 | The CA/version proof-index lookup is absent and no record is fabricated | M6 authenticated response envelope; M8 absence policy |
| P7 | Mutating a head body changes `HeadID`; the separate four-replica test commits identical AppHash, roots, results, and heads for identical ordered blocks | M5 supplies QC; M8 checks conflict evidence |

The strict fixture publication authorizer parses a test-only manifest envelope,
extracts CA ID/number/algorithm, hashes the exact bytes, validates a one-key EE
chain fixture, and strictly verifies the detached intent signature. It is
deliberately not labeled an RPKI validator; M7 must replace it with the Krill/
RPKI implementation behind the unchanged `PublicationAuthorizer` trait.
