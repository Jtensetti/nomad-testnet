# Governance transitions

The production goal asks for explicit protocol transitions for seven events,
and says not to rely on manual compose-file edits as the governance protocol.
All seven are implemented. None of them is a state machine named after the
event: they are expressed through two mechanisms, which is a defensible design
and an undocumented one -- nobody could check the seven were covered without
reading the code, and a requirement nobody can check is one nobody can hold you
to.

This maps each event to the mechanism that carries it, the tests that evidence
it, and what is not covered.

## The two mechanisms

**The signed topology** names the committee, the DKG threshold and the traffic
class. It is refused unless it is canonical, has between three and 64
operators, and declares a threshold of at least two and no more than the
operator count.

**The epoch descriptor chain** carries transitions between epochs. Each
descriptor names its transition kind -- `genesis`, `scheduled` or `emergency`
-- embeds the topology it activates, and must be approved by a quorum of the
*previous* committee. The chain refuses a second activation for one epoch,
burns epoch numbers so a retired one cannot be reused, and halts on
equivocation.

Membership change is therefore not a separate protocol. It is a new topology
inside a descriptor the outgoing committee approved, which is what stops an
operator adding or removing anyone alone.

## The seven

| Event | Mechanism | Evidence |
|---|---|---|
| Operator addition | new topology in a descriptor approved by the previous committee's quorum | `TestMembershipTransitionRequiresPreviousCommittee`, `TestApprovalQuorumCannotBeForgedByOneOperator` |
| Operator removal | voluntary self-revocation, signed by the operator being removed | `TestSelfRevocationRequiresTheRevokedOperator`, `TestRevocationStorePersistsAndFeedsChainAdmission` |
| Compromised operator | revocation asserted by a quorum of peers, not by one | `TestCompromiseRevocationNeedsPeerQuorum`, `TestVerifyRejectsRevokedApproverAndMember` |
| Unavailable operator | removal by scheduled transition, same route as any membership change; runtime absence is visible in the liveness gate | `TestAVanishedPeerChangesNothingTheSurvivorSees`, `TestTheLivenessTimestampFollowsWhatActuallyWentOut` |
| Equivocation | the chain halts, and stays halted across restarts | `TestChainHaltsOnValidEquivocation`, `TestPreexistingHaltMarkerStopsAnotherInstance`, `TestHaltSurvivesEvidencePersistenceFailure` |
| Threshold loss | a topology may not declare a threshold above its own membership, so a shrinking committee must lower the threshold deliberately or fail | `TestTheThresholdMustBeReachableAndMoreThanOne`, `TestAReachableThresholdIsAccepted` |
| Emergency epoch transition | `emergency` descriptors retire their predecessor, under the same approval quorum | `TestChainEmergencyRetiresPredecessor`, `TestLawfulRebootstrapIsNotEquivocation` |

Two of those tests were written because this document was: the threshold bounds
were implemented in one clause and exercised by nothing, so deleting the clause
left the suite green. Writing down what a requirement rests on is how that gets
noticed.

## What is not covered, and why

**An unavailable operator is not distinguishable from a withheld response.**
This is the honest limit and it is not an implementation gap. Availability
reports establish that work did not arrive at the observers, never that it was
withheld; asynchrony makes the two indistinguishable to any observer. So
"unavailable" is a judgement a human makes from availability evidence and then
executes as a scheduled membership change -- the protocol carries the change,
not the diagnosis. Recorded against PROD-07.

**Threshold loss at runtime is an availability failure, not a protocol state.**
The topology bound stops a committee being *declared* that cannot decrypt. It
does not stop enough operators being offline at once that a live epoch cannot
produce partials. That is degraded availability, it is not attributable for
the same reason as above, and no mechanism here converts it into a transition.

**Selective failure below the observer quorum is undetectable**, and lowering
the quorum does not fix it: the same threshold is what makes a minority
harmless. Recorded against PROD-07.

**None of this is evidence of independent governance.** Every transition above
is exercised on one machine, by one administrator, with identities this project
generated. The DoD for independent operators requires five separately
administered operators, local key generation, no central machine holding all
threshold shares or creating all identities, a real WAN DKG and at least three
failure domains. That is EB-2 and it is not something this repository can
supply. The transitions being implemented and tested says the mechanism is
there for operators who are independent; it says nothing about whether any are.
