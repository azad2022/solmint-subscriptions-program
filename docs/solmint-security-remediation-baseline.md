# SolMint Subscriptions — Security Remediation Baseline

## Repository ownership and provenance

- Maintained fork: `azad2022/solmint-subscriptions-program`
- Upstream: `solana-foundation/subscriptions`
- Upstream immutable tag: `program-v0.5.0`
- Exact source commit: `364a41976c33347d092902443bbec2def9227e75`
- Source license: MIT (original copyright and license text retained in `LICENSE`)
- SolMint working branch: `feat/solmint-g1-authority-vnext`
- Pristine pinned baseline branch: `solmint/v0.5.0-baseline`
- Existing upstream Program ID in this baseline: `De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44`

This branch is a SolMint-maintained fork. No upstream maintainer merge or write access is required for local source changes. The upstream repository's `main` remains intact and is not the deployment authority for SolMint's VNext Program.

The pinned tag is eight commits after the Cantina remediation commit `debb4f75ff7571218b39de3b633074dd843e70db`. The upstream compare shows no `program/` source files changed in those eight commits; the Rust Program source at this pinned tag therefore matches that audited-fix source revision, while clients, release workflows, metadata and audit records have subsequent changes.

## Reproducible baseline build evidence

The exact source commit above was checked out and built by SolMint's existing pinned-source CI on the reconciled Subscription branch:

- GitHub Actions run: `42233967558`
- Exact tested SolMint branch SHA: `f908440cf75b28299b1322e39f1148176e3c7c8c`
- Job: `subscription-reproducible-build` — SUCCESS
- Source commit: `364a41976c33347d092902443bbec2def9227e75`
- `solana-verify`: `0.5.2`
- Solana CLI build version: `3.1.10`
- Repository `rust-toolchain.toml`: `1.92`
- Build-container Rust toolchain: `1.86.0-x86_64-unknown-linux-gnu`
- Docker image digest: `sha256:f71be5ca7620b7e40933b7f1294fa44e01d08c1fc5ba1f375a2478f5a01580d3`
- Baseline ELF SHA-256: `056ca97cf3ee6586650275ce819d026f7369de0172dc54010fa6dc58180e0318`
- Baseline IDL SHA-256: `1522580389fe155633e37682b91488df7cf6c7b3ba5a6cb3ba0e5ae00ffe89aa`

These hashes are the unmodified v0.5.0 baseline, not a VNext artifact and not deployment evidence. Every VNext source change must produce a new reproducible ELF/IDL pair and exact build provenance.

## Product capability baseline — must be preserved

The upstream repository includes the complete Program, IDL, generated TypeScript and Rust clients, integration tests, fuzzing, demo webapp and release workflows. The protocol's supported surface includes:

- Shared subscription authority and multiple independent permissions per customer/mint.
- Fixed delegations with total allowance and optional expiry.
- Recurring delegations with per-period limits, reset windows and optional overall expiry.
- Merchant Plans, subscriptions, billing periods, pullers, destination restrictions, finite/perpetual Plans, cancellation and resume.
- Plan updates, sunset, deletion and rent recovery.
- SPL Token and Token-2022.
- Token-2022 TransferHook forwarding.
- On-chain events and generated IDL/client support.
- Explicit rent payer/sponsor support and abandoned-account recovery.

No capability is to be removed merely to make the security patch easier. Each capability must retain an explicit VNext account model, authorization rule, migration path and regression test.

## Existing Cantina review — residuals that G1 must close

The attached Cantina Managed review is dated 2026-07-30. It reviewed baseline `d6b3a5dc7ab18c4168441af733c81ab0a599d414`; the report summary records 9 findings: 4 Fixed and 5 Acknowledged. Cantina's later verification through `debb4f75ff7571218b39de3b633074dd843e70db` verifies the implemented fixes, but the five acknowledged findings are not equivalent to five fixed findings.

### Findings that remain in G1 scope

1. **High — Old signed creates restore revoked permissions (report §3.1.1, p.4–5).** A retained, unexecuted Init + Create/Subscribe bundle can recreate a closed deterministic Authority and restore `Approve(u64::MAX)`; `UNKNOWN_INIT_ID` binds to the landing slot, not to the original consent. This finding was acknowledged, not fixed.
2. **Medium — Stale authority-control approvals (report §3.2.4, p.8).** Init can refresh the existing delegate; old Close/Revoke signatures are not bound to the Authority generation. This finding was acknowledged, not fixed.
3. **Medium — Stale immediate-cancel approvals (report §3.2.1, p.5).** The current implementation binds `CancelSubscriptionNow` to `expected_current_period_start_ts`; a timestamp is not a unique incarnation or monotonic revision. Same-second recreation remains a required adversarial case.
4. **Medium — Stale resume approvals (report §3.2.3, p.8).** The current implementation includes `expected_expires_at_ts`, but does not have a persistent monotonic cancellation revision. Repeated same-value cancellation states require explicit collision/replay tests.
5. **Medium — Full-period charge at Plan expiry (report §3.2.5, p.9).** The pinned Subscribe path accepts a finite Plan while `current_ts <= end_ts`; it does not require a complete first billing period to remain. This must be fixed without silently changing the merchant's intended billing semantics.
6. **Low — Automatic rent sponsorship (report §3.3.2, p.10).** Preserve sponsorship as a product feature, but make sponsorship explicit and bounded with enforceable payer recovery/quotas; do not infer an indefinite rent liability from transaction fee payer alone.

### Findings already verified fixed upstream

- Stale `UpdatePlan` approvals: Cantina verified lifecycle/state binding in `653dec58`; retain regression tests and add a monotonic revision in VNext.
- Optional `CreatePlan` payer missing from IDL: fixed and verified in `11173179`.
- IDL generation failures not failing release: fixed and verified in `1b6e98e`.

The new VNext audit must cover all inherited and newly introduced attack surfaces; the 2026-07-30 Cantina report is a baseline, not an audit certificate for VNext.

## VNext isolation hypothesis — NOT YET PROVEN

The old Program validates the canonical Associated Token Account during Authority initialization and derives/checks that canonical ATA in transfer helpers. VNext may use a dedicated customer-owned **non-ATA** source token account, with a new Program ID and Authority PDA bound to that exact source account.

This is a candidate isolation boundary only. Before relying on it, LiteSVM adversarial tests against the exact old Program binary/source must prove that stale legacy Init, Subscribe, Fixed/Recurring creation and all legacy transfer paths cannot:
- accept the VNext non-ATA source account;
- change its delegate or close authority;
- debit its balance;
- recreate or mutate VNext registry/authority state.

The user remains the token-account owner and must explicitly sign account creation, token movement and VNext consent. Legacy assets, Plans and Subscriptions are not auto-migrated. Each customer must explicitly migrate assets into the dedicated source account, each merchant must recreate/verify Plans, and each customer must provide fresh consent. Existing legacy ATA funds must never be treated as migrated merely because a VNext account exists.

A new Program ID does not disable the old Program or invalidate old signed transactions. The existing Program ID must not be reused unless the existing upgrade authority and Squads governance explicitly approve a verified upgrade. No attempt to bypass that governance is permitted.

## Mutation and release boundary

- No Program source, IDL, Program ID, signer, keypair, deployment, upgrade, Squads proposal, Devnet/Mainnet transaction, database, customer consent or funds were changed while establishing this baseline.
- VNext source patches are confined to `feat/solmint-g1-authority-vnext`; the pristine tag baseline remains `solmint/v0.5.0-baseline`.
- Devnet deployment requires a separately reviewed build and explicit key custody/deployment approval. Mainnet deployment requires an independent audit, exact ELF/IDL verification, migration rehearsal and explicit release authorization.
