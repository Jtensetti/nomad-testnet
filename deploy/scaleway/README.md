# Scaleway three-region WAN lab

This directory provisions the first real public-WAN measurement fixture for
Nomad. It is deliberately small and deliberately honest about what it proves.

## What it creates

Terraform creates exactly three `STARDUST1-S` Ubuntu instances:

| Nomad operator | Scaleway zone |
|---|---|
| `operator-a` | `fr-par-1` |
| `operator-b` | `nl-ams-1` |
| `operator-c` | `pl-waw-2` |

Each host receives one routed IPv4 and one routed IPv6 address. The first
campaign uses IPv4 only: Nomad UDP/4200 and DKG TLS/4400 are restricted to the
three lab IPv4 addresses, and SSH is restricted to the current GitHub Actions
runner. IPv6 is allocated for later dual-stack work but has no Nomad ingress
rule and is not part of the first evidence claim.

The instance type is intentionally hard-coded. This workflow is measurement
infrastructure, not a performance environment, and a workflow input must not be
able to accidentally select an expensive VM.

## Trust boundary

All three cloud resources are created from one Scaleway project and one GitHub
workflow. Therefore this lab is **one administrative trust domain** even though
the operator processes have distinct keys and run in three real regions.

It can produce WAN evidence. It cannot produce evidence of independently
administered operators. `CLAIM_BOUNDARY.txt` in every evidence artifact records
that limitation explicitly.

## Secrets

The workflow expects these GitHub Actions repository secrets:

- `SCW_ACCESS_KEY`
- `SCW_SECRET_KEY`
- `SCW_PROJECT_ID`
- `SCW_ORGANIZATION_ID`

Do not create `*.tfvars`, `.env`, or other repository files containing those
values. Terraform state is runtime material and is ignored by Git.

## Safe workflow

The workflow is `.github/workflows/scaleway-wan.yml`.

### 1. Plan

Run **Scaleway WAN → Run workflow** with `operation=plan` first. This downloads
the provider and shows the exact resources Terraform intends to create. It does
not create cloud resources.

### 2. Apply and measure

Run it again with `operation=apply`. The workflow:

1. generates a one-run SSH key and restricts SSH to the runner's public `/32`;
2. creates the three hosts and waits for cloud-init;
3. installs binaries built from the exact checked-out commit;
4. generates each operator identity on that operator host;
5. collects only public enrollments and signed attestations;
6. creates and activates one signed topology;
7. performs the real networked Pedersen DKG over TLS;
8. verifies that all hosts independently produce the same public DKG certificate
   while each threshold share remains local;
9. starts fixed-cadence Nomad nodes in the three regions;
10. captures both emitted cells and cells that actually arrive over the WAN at
    every host boundary;
11. requires exact 1200-byte payloads, fixed sender destinations, no sender-side
    catch-up burst, bounded sender cadence and a sane no-fault WAN arrival rate;
12. uploads hashes, pcaps, health data, DKG evidence and claim limits as a
    GitHub artifact.

The default capture is five minutes. The input accepts 30-3600 seconds. The TTL
must leave at least fifteen minutes beyond the selected capture interval. Longer
campaigns and the required 72-hour production evidence are separate work.

### 3. Destroy

A successful apply uploads a private state artifact named
`scaleway-wan-state-<RUN_ID>`.

Run the workflow with:

- `operation=destroy`
- `state_run_id=<the successful apply run ID>`

This restores that exact Terraform state and removes the servers, security
groups and routed IP resources.

**Poweroff is not destroy.** Cloud-init schedules an automatic poweroff after
the selected TTL as a cost backstop, but allocated IPv4 resources can remain
billable. Always run the destroy operation when the experiment is finished.

If an apply or measurement job fails, the workflow attempts an immediate
fail-closed Terraform destroy using its local state.

## First-phase claim

A successful run means only:

> The current Nomad binaries completed their distributed DKG and maintained the
> specified fixed-size/fixed-cadence reader-side fabric across three real
> Scaleway regions for the recorded capture interval under one administrator,
> with both sender-boundary and receiver-arrival packet evidence.

It does **not** by itself establish anonymous publication, independent operator
governance, IPv6 protocol behavior, long-horizon indistinguishability,
production availability, or an external security assessment.
