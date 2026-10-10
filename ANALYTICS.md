# Attest Analytics: method

Attest Analytics reports how Attest is used, computed on Attest's servers from records Attest already keeps, with no tracking scripts, cookies or third parties. Every finished UTC day is sealed: its figures, and the exact records behind each one, are committed to and anchored on Horizen. This document defines each figure and how a sealed day can be checked.

## Figures

Each figure counts records in one UTC day `[d, d + 1 day)`. For an organization's view, only accounts that are accepted members of that organization are in scope (`org_members.accepted_at` set); for the platform, every account.

| Figure | Counts | Record |
| --- | --- | --- |
| `newAccounts` | accounts in scope created that day | `users.id` with `created_at` in the day |
| `sent` | agreements sent for signature that day by an account in scope | `agreements.id` with `status <> 'draft'` and `created_at` in the day |
| `completed` | agreements completed that day | `agreements.id` with `completed_at` in the day |
| `signatures` | passkey signatures on those senders' agreements | `agreement_signers.id` with `signed_at` in the day |
| `proofsShared` | zero-knowledge proofs a party chose to share | `agreement_zk_claims.id` with `automatic = false` and `created_at` in the day |
| `anchors` | anchoring transactions mined that day | `batches.tx_hash` with `status = 'anchored'` and `anchored_at` in the day |

A figure is a count of its records: when a day is sealed, a figure that doesn't equal its number of records stops the seal.

## What a sealed day commits to

Three canonical JSON documents (keys sorted, no whitespace):

- **figures**: `{ activity, kpis, onchain }`, what the dashboard shows. Private to the dashboard's viewers.
- **commitments**: `{ <figure>: <Merkle root or null> }`, one root per figure. Contains no counts.
- **summary**: `{ format: "attest.analytics_snapshot.v2", day, scope, figuresSha256, commitmentsSha256, definitions, method }`. Its SHA-256 is recorded as an Attest receipt and anchored on Horizen.

Each figure's tree:

```
leaf     sha256("attest.analytics.leaf.v1|" + figure + "|" + recordId + "|" + salt)   salt: 16 random bytes, hex
anchors  the transaction hash itself (public): anyone can read each one from the chain
tree     leaves sorted by value; parent = sha256(min(a, b) || max(a, b)) over the 32-byte values; an odd node is
         promoted; one leaf is its own root; no records gives a null root
count    the number of leaves = the figure
```

The salts never leave Attest except to a record's own parties. A leaf reveals nothing about its record.

## Checking a sealed day

The open verifier reads `attest.analytics_evidence.v1` (FORMAT.md):

1. The summary's SHA-256 is anchored on Horizen (its receipt's Merkle path and transaction).
2. The figures and commitments are the ones the summary names (their SHA-256).
3. **Full evidence** (the dashboard's viewers) carries every figure's leaves: each figure is recounted from them, and each root recomputed. Each committed anchor transaction is read from the chain and must be an anchor on the registry, mined that day.
4. **Inclusion evidence** (a party to an agreement) carries the summary, the commitments, and for each of the party's records counted (the agreement as sent and completed, their own signature) its salt and Merkle path: its leaf must reach the sealed root.

## What this establishes

- The figures shown for a sealed day are the ones sealed and anchored that day: they can't be revised later.
- Each figure equals the number of records committed behind it.
- Anyone counted can check that they were. A record left out cannot produce a valid path, so its party can show the figure is incomplete; a record made up adds a leaf no real party can open.
- Anchors are fully recountable by anyone: their transactions are public.
- Days before October 10, 2026 were sealed in format v1: anchored as sealed, without record commitments.
