# Operator recovery runbook

Procedures for the epoch lifecycle failures an operator will actually meet.
Protocol reference: `nomad-protocol/docs/EPOCH_LIFECYCLE.md`. Every
procedure below is exercised by an automated drill; see **Drill** at the end.

Two rules apply throughout:

- **Never** copy another operator's private material, and never let one
  machine hold more than its own share. A procedure that would require that
  is the wrong procedure.
- Timing is public. Nothing here is scheduled in response to user activity,
  and no step is accelerated because a publication or query is pending.

## 1. Ceremony fails to complete

**Symptom** The successor DKG does not reach full QUAL by its phase
deadline; no certificate is produced.

**Cause** Any single operator that is offline, slow past the signed
deadline, or equivocating aborts the ceremony. This is by design: partial
membership cannot activate an epoch.

**Procedure**

1. Do nothing until the next public retry offset. The retry ladder is in the
   published rotation policy; `PlanAt` reports the attempt that is due.
2. At the retry instant, run the ceremony again with a **fresh session** and
   the same membership. Never resume an interrupted session: the ephemeral
   dealer polynomial is deliberately not persisted, and the journal refuses
   a resume.
3. If the ladder reaches its escalation offset with no certificate, the plan
   changes to `ESCALATE`. Proceed to procedure 3 (operator replacement).

**Do not** extend the outgoing epoch to buy time. If no successor exists at
`retire_at`, the epoch retires anyway and the network is down until a
successor activates. Availability is sacrificed rather than serving past a
signed boundary.

## 2. Operator credential compromise

**Symptom** An operator's identity key is believed to be in someone else's
hands.

**Procedure**

1. **Revoke.** If the operator still controls the key, it self-revokes
   (`Reason: self`, signed by itself). If it does not, the remaining
   operators assemble a compromise revocation: an approval quorum of peers
   signs the statement, and the target's own signature does not count
   toward that quorum.
2. **Distribute** the revocation to every operator and accept it into each
   revocation store. From that point no verifier will admit a new epoch
   containing that identity.
3. **Replace.** Run procedure 3 to bring in a replacement operator via an
   `emergency` transition, which activates before the outgoing epoch's
   scheduled retirement.
4. **Erase** the compromised operator's epoch material per procedure 5 if
   the machine is still under control.

The revocation is forward-scoped: it stops the identity being used in
future epochs. It does not retroactively invalidate the epochs that
identity already helped activate, and verifiers must keep their existing
chains loadable — a revocation that bricked the store would disable
recovery exactly when it is needed.

## 3. Operator replacement (membership transition)

**Symptom** An operator is compromised, permanently lost, or leaving.

**Procedure**

1. The replacement operator generates its own private material locally
   (`nomad-operator init`). Nobody else ever sees it.
2. It publishes a signed enrollment containing only public values.
3. The coordinator assembles a draft topology for epoch N+1 with the new
   membership. The coordinator holds no operator private key and cannot
   change membership by itself.
4. Every operator of N+1 inspects and attests the exact draft.
5. N+1 runs its DKG and produces a certificate.
6. **A quorum of the previous epoch's operators approves the transition.**
   This is the step that makes membership a protocol action rather than a
   configuration edit: without `max(previous_threshold, majority)` distinct
   previous-epoch approvals, no verifier accepts the successor.
7. Every operator of N+1 signs the activation. Signing goes through the
   local journal, which refuses a second distinct descriptor for the epoch.
8. Distribute the descriptor. Verifiers append it; it activates at its
   public boundary.

If more previous-epoch operators are lost than the quorum tolerates, no
valid transition exists and the network must re-bootstrap from a new
genesis. Clients treat that as a new trust decision, never as an automatic
continuation.

## 4. Conflicting descriptors observed (equivocation)

**Symptom** A verifier reports `ErrEquivocation` and halts.

**Meaning** Two distinct, individually valid descriptors exist for one
`(network, epoch)`. Someone with authority signed both. This is a
governance failure, not a transport error.

**Procedure**

1. Stop. A halted verifier serves no epoch and appends nothing. Do not
   delete the halt marker to "get running again"; that destroys the
   evidence and re-forks the store.
2. Collect the `HALTED` file from every affected verifier. It contains both
   descriptors in full, so any third party can re-verify the conflict
   independently.
3. Determine which operators signed both. Their signature journals show
   whether a signer refused or produced the second signature.
4. Revoke the equivocating identities (procedure 2) and re-bootstrap with a
   new genesis, distributed out of band.

## 5. Epoch retirement and key erasure

**When** At every `retire_at`, and immediately after any emergency
transition retires an epoch early.

**Procedure**

1. Confirm the epoch is no longer ACTIVE. The share service refuses
   threshold work outside the serving window; a refusal is expected, not a
   fault.
2. Run the erasure procedure over the epoch's private share file and its
   DKG journal. Each file is overwritten, synced and unlinked.
3. Keep the signed erasure statement. It records each file's pre-erasure
   digest and size, the method, the filesystem, and the standard
   limitations text.
4. File the statement with the epoch's evidence.

**Limitations, stated plainly.** Overwrite-then-unlink destroys the file as
the filesystem sees it. On journaling filesystems, flash with wear
levelling, or where snapshots or backups exist, it does not guarantee
physical destruction. The operative guarantee is destruction within an
encrypted volume, so operators must use full-disk encryption and must not
back up the share directory. Any claim beyond that is unsupported.

## 6. Interrupted ceremony or restarted process

**Symptom** An operator process died mid-ceremony.

**Procedure** Do not attempt to resume. The state directory refuses to
start a session in a non-empty directory, and the journal refuses to resume
an interrupted ephemeral session. Archive the directory as evidence, then
wait for the next public retry offset and start a fresh signed session
(procedure 1).

## Drill

`live/epoch` carries an automated drill covering procedures 1 through 5:
`TestRecoveryDrill` in `live/epoch/drill_test.go`. It runs a genesis epoch,
compromises an operator, revokes it by peer quorum, replaces it through an
emergency membership transition approved by the previous committee, erases
the retired material, and verifies that the retired epoch can no longer be
served. Run it with:

    go test -race ./live/epoch/ -run TestRecoveryDrill -v

The drill is protocol-level. It does not establish that independent
administrators performed these steps on separate hosts; that remains
external (see `nomad-protocol/production/EXTERNAL_BLOCKERS.md`, EB-2).
