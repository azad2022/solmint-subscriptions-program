# SolMint VNext — Protocol and ABI Design

**Status:** DRAFT — PARTIAL RUNTIME IMPLEMENTATION; ABI NOT FROZEN; NO DEPLOYMENT  
**Work branch:** feat/solmint-g1-authority-vnext  
**Baseline branch:** solmint/v0.5.0-baseline  
**Reviewed source HEAD:** c7882a51862f07eec781ba5aa3b82eee4eb24212  
**Immutable upstream source baseline:** solana-foundation/subscriptions@364a41976c33347d092902443bbec2def9227e75  
**Purpose:** G1-2 protocol and ABI design checkpoint

> This document records source-verified baseline facts and a protocol design direction. It is not an ABI freeze, implementation claim, audit result, or deployment authorization. The supplied execution prompt ended part-way through §7.1 after the word “حداقل”; the remaining required Registry fields and later requirements were not available. Those requirements are deliberately not inferred here.

## 1. Scope and security objectives

The VNext Program must close delayed-signature and lifecycle-replay weaknesses in the pinned v0.5.0 Program while preserving the complete product capability surface.

The protocol design must provide:

1. Durable, non-resettable Authority consent lineage that remains effective across Authority close/recreation.
2. A way for the subscriber to invalidate a previously signed but not-yet-landed authorization even when no current Authority account exists.
3. A unique, monotonic lifecycle incarnation for each logical Subscription, surviving close/recreate of the current Subscription PDA.
4. Monotonic Plan administration revisions; restoring previous field values must not revive an old signed update.
5. Action-specific replay protection and an on-chain bounded validity interval for signed instructions.
6. Atomic state transition and token-authority effects. A failed CPI must roll back the corresponding Program state change.
7. Explicit treatment of legacy instructions and accounts. No old unbound instruction may bypass VNext checks.
8. Complete compatibility and migration treatment for all existing supported capabilities, including delayed execution through durable nonces and program-controlled wallets, after their protocol freshness semantics are proven.
9. A verifiable source-token-account isolation boundary between VNext and the old Program.

These are protocol requirements. Backend locks, recent-blockhash UX, browser restrictions, a database generation column, or a server-side denylist are defense-in-depth and cannot invalidate a transaction already signed for direct submission to Solana.

## 2. Repository and source baseline

### 2.1 Live repository facts at design start

- Fork: azad2022/solmint-subscriptions-program.
- Work branch exists: feat/solmint-g1-authority-vnext.
- Pristine baseline branch exists: solmint/v0.5.0-baseline.
- Source HEAD reviewed for this checkpoint: 52afc0d2a4a360989b2c1775a47af62037562c41.
- The work branch now contains VNext Authority Consent Registry/Authority handlers, Plan and Subscription state, Plan create/update handlers, Subscription lifecycle handlers, VNext transfer handler, Codama instruction annotations and integration tests. The pristine baseline branch remains unchanged.
- The VNext work branch still declares the legacy Program ID; it is not an independently deployable Program identity yet.
- The source baseline is the exact MIT-licensed v0.5.0 source commit 364a41976c33347d092902443bbec2def9227e75. The original LICENSE and copyright notices are retained.
- The project is a Pinocchio Program with Codama IDL generation; it is not an Anchor workspace. The Rust workspace root is Cargo.toml, with members program, clients/rust, and tests/integration-tests.
- Workspace versions inspected at the work branch: Rust edition 2021, Pinocchio 0.11.1 and Codama 0.9.2. Reproducible baseline build evidence is recorded in docs/solmint-security-remediation-baseline.md.

The pristine baseline branch must remain unchanged. All subsequent source, test, generated IDL and client changes belong on the VNext work branch.

### 2.2 Verified baseline source structures

The following facts were read from the pinned baseline and the current VNext work-branch source:

| Source | Verified representation |
|---|---|
| program/src/lib.rs | Pinocchio Program; currently declares the legacy Program ID De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44. |
| program/src/instructions/mod.rs | SubscriptionsInstruction is repr(u8); the first instruction-data byte is the instruction discriminator; Codama annotations describe account metas. |
| program/src/state/subscription_authority.rs | repr(C, packed); fields are discriminator:u8, user:Address, token_mint:Address, payer:Address, bump:u8, init_id:i64. PDA seeds are currently ["SubscriptionAuthority", user, token_mint]. |
| program/src/state/header.rs | Shared packed delegation header contains discriminator, version, bump, delegator, delegatee, payer and init_id:i64; init_id starts at byte offset 99. |
| program/src/state/subscription_delegation.rs | Subscription PDA is derived from ["subscription", plan_pda, subscriber]; the account is closable/reusable and stores terms, period accounting and expires_at_ts. |
| program/src/state/plan.rs | Plan is packed; current Plan::LEN is pinned to PLAN_LEN_V1 = 491; PDA seeds are ["plan", owner, plan_id]. |
| tests/integration-tests/Cargo.toml | The integration suite uses LiteSVM 0.12. |
| program/src/state/authority_consent_registry.rs | Persistent 188-byte Registry keyed by subscriber, mint and exact source token account. |
| program/src/state/vnext_subscription_authority.rs | 204-byte VNext Authority bound to subscriber, mint, source, Registry, token program and authority generation. |
| program/src/state/vnext_plan.rs | 500-byte VNext Plan under the separate `planVNext` seed namespace. |
| program/src/state/vnext_subscription.rs | 260-byte VNext Subscription keyed by Plan, subscriber and exact source token account. |
| program/src/state/subscription_lifecycle_registry.rs | Persistent 148-byte Subscription lifecycle revision/nonce Registry. |
| program/src/state/plan_revision_registry.rs | Persistent 116-byte Plan administration revision/nonce Registry. |
| program/src/instructions/vnext_subscription.rs | VNext Subscribe, Cancel, CancelNow, Resume and Transfer runtime handlers. |
| program/src/instructions/vnext_plan.rs | VNext Plan create/update runtime handlers. |

The current account discriminators and instruction discriminators are separate namespaces. Do not conflate them when designing the VNext ABI.

### 2.3 Source-verified vulnerable behavior

- InitSubscriptionAuthority has legacy instruction discriminator 0 and no instruction payload. On first creation it stores Clock::slot as i64 as init_id. Whether the Authority account is newly created or already exists, the handler then executes SPL Token Approve(u64::MAX). Replaying Init against an existing Authority can therefore re-approve the delegate without a new durable consent generation.
- CloseSubscriptionAuthority has legacy instruction discriminator 6 and closes the Authority PDA.
- RevokeSubscriptionAuthority has legacy instruction discriminator 14. It revokes the Program's delegate when the current delegate matches, then closes the Authority PDA.
- Subscribe has legacy instruction discriminator 11. Its packed payload contains expected_subscription_authority_init_id:i64; the UNKNOWN_INIT_ID sentinel is resolved against the landing slot by SubscriptionAuthority::check_init_id.
- CreateFixedDelegation and CreateRecurringDelegation also carry expected_subscription_authority_init_id:i64 and create permissions through the shared Authority.
- The current SubscriptionDelegation PDA can be closed and recreated. A revision stored only inside this account cannot prove monotonicity across its own close/recreate lifecycle.
- CancelSubscriptionNow binds approval to expected_current_period_start_ts:i64; ResumeSubscription binds to expected_expires_at_ts:i64. These timestamps can collide or return to the same value.
- UpdatePlan compares expected mutable values but has no persistent monotonic Plan revision. A value-change-and-restore (ABA) sequence therefore requires stronger protection.
- The old Program validates the canonical ATA during Authority initialization. The transfer helper also derives and checks the canonical ATA for the delegator source before transfer. This matters to the proposed non-ATA isolation hypothesis; it is not, by itself, proof of complete isolation.

Source references:
- program/src/instructions/initialize_subscription_authority.rs
- program/src/instructions/close_subscription_authority.rs
- program/src/instructions/revoke_subscription_authority.rs
- program/src/instructions/subscribe.rs
- program/src/instructions/create_fixed_delegation.rs
- program/src/instructions/create_recurring_delegation.rs
- program/src/instructions/cancel_subscription_now.rs
- program/src/instructions/resume_subscription.rs
- program/src/instructions/update_plan.rs
- program/src/instructions/helpers/transfer_utils.rs
- program/src/state/subscription_authority.rs
- program/src/state/subscription_delegation.rs
- program/src/state/plan.rs

## 3. VNext authority namespace and source-account identity

### 3.1 Authority Consent Registry identity

The user-supplied protocol requirement identifies an Authority Consent Registry by the exact tuple:

**(subscriber, mint, source_token_account)**

All three public keys are part of the logical identity. A Registry for one source token account must not authorize, invalidate, or be treated as consent for a different source token account, even when subscriber and mint are equal.

The source token account is therefore a first-class authority boundary, not an optional lookup hint.

#### Authority Consent Registry v1 account ABI — selected

The first executable state slice fixes the account identity and byte layout as follows:

- Account discriminator: **5** (the existing v0.5.0 account discriminators 0–4 are unchanged).
- Schema version: **1**.
- PDA seeds, in order: UTF-8 bytes for `authorityConsent`, subscriber public key, mint public key, source token account public key.
- Integer encoding: little-endian.
- Total account length: **188 bytes**.
- The account is program-owned and is a persistent tombstone/consent lineage. No ordinary instruction may close or reset it.

| Offset | Length | Field | Encoding |
|---:|---:|---|---|
| 0 | 1 | discriminator | u8 = 5 |
| 1 | 1 | version | u8 = 1 |
| 2 | 1 | status | u8; 0 = revoked, 1 = active |
| 3 | 1 | bump | u8 |
| 4 | 32 | subscriber | public key |
| 36 | 32 | mint | public key |
| 68 | 32 | source_token_account | public key |
| 100 | 32 | token_program | public key |
| 132 | 32 | rent_payer | public key |
| 164 | 8 | authority_generation | u64 |
| 172 | 8 | authorize_nonce | u64 |
| 180 | 8 | revoke_nonce | u64 |

The rent payer is recorded. The Registry is not closeable because that would reset the generation lineage; the rent-exempt principal is therefore retained. Any future excess-lamport recovery must preserve the exact data, owner and rent-exempt floor and return only excess to the recorded payer. The Registry must not be sponsored by SolMint.

#### Authority transition rules — selected

- A newly allocated Registry initializes as `REVOKED`, generation 0, authorize nonce 0, revoke nonce 0.
- Authorize requires subscriber authorization, the exact current generation, the next authorize nonce, and a Program-checked deadline. It increments generation and authorize nonce with checked arithmetic, then sets status to `ACTIVE`. An already-active Registry rejects Init; retrying Init cannot re-approve a revoked token delegate.
- Revoke has a separate monotonic nonce. When active, it must target the current authority generation. When revoked, it may target exactly the next generation, pre-empting one signed-but-not-yet-landed authorization. It increments generation to target + 1 and advances revoke nonce. This makes a signed invalidation valid whether the one pending authorization lands before or after it; later generations and stale replays fail.
- The two action counters are independent so an invalidate signed against an absent Registry is not made stale solely because one pending authorize transaction lands first.
- Generation and nonce arithmetic is checked; overflow fails without changing state.

The transition implementation is in `program/src/state/authority_consent_registry.rs`; authorize/revoke handlers are wired to dispatch and perform source-account/token-program validation, persistent Registry allocation, tuple-bound Authority creation, delegate approval/revoke and Authority close. The account layout is implemented, but ABI freeze remains pending complete golden tests, generated IDL synchronization and independent review. The current exact-source CI run must pass before this runtime slice is considered validated.

### 3.2 Required identity checks

Every VNext instruction that reads or mutates this Registry must establish, using actual account data and canonical derivation:

- the Registry belongs to the VNext Program;
- the Registry account is the canonical derivation for the exact subscriber, mint and source token account tuple;
- stored identity, derivation inputs and supplied accounts agree;
- the source token account is owned by the expected token program and its token-account owner is the subscriber;
- the source token account mint is exactly the Registry mint;
- the selected token program and mint interface match the supported asset and extension policy;
- Registry generation and action-freshness values satisfy the instruction's expected values.

The current VNext Authority is derived from the same exact tuple and its stored identity includes Registry PDA and token program. Subscribe, Resume and Transfer revalidate the live Registry generation and Authority identity. This implementation must still pass exact-source adversarial CI and independent review.

No exact token-account extension policy is established by this document. SPL Token and Token-2022/TransferHook support remain required product capabilities, but each supported configuration must have an explicit validation and test policy.

### 3.3 Source-account isolation hypothesis

The leading isolation route is a new Program ID plus a customer-owned dedicated non-ATA source token account, with VNext Authority/consent bound to that exact account.

This is only a partial source-level boundary, not complete legacy isolation. A LiteSVM regression has been added to load the exact old v0.5.0 binary and prove its legacy InitSubscriptionAuthority path rejects a VNext non-ATA source without leaving a delegate or Authority. The test is run separately by SolMint CI against the immutable baseline binary. The remaining old instruction paths still require explicit adversarial coverage. The G1 suite must establish that every old path is unable to:

- initialize an old Authority against the VNext non-ATA source account;
- replace its delegate or change its close-authority configuration through an old Program instruction;
- debit the VNext source account through fixed, recurring, subscription or other transfer paths;
- close, recreate or otherwise mutate VNext Registry/Authority state;
- gain access through an associated account, supplied remaining account, malformed account list or token-program substitution.

Tests must also cover an ATA and a non-ATA account for the same subscriber/mint to ensure the two consent lineages cannot be confused.

A new Program ID does not deactivate the old Program and does not invalidate old signed transactions against legacy accounts. Existing legacy ATA balances, Plans, Subscriptions and customer approvals do not migrate automatically. Any migration must require explicit customer authorization and prove that old pending instructions cannot reach the new source-account balance.

## 4. Durable Authority consent lifecycle

The protocol must use a persistent Authority generation lineage that survives Authority close/recreation. Clock slot, Unix timestamp, transaction signature, blockhash, browser-generated identifiers and a closable account's creation time are not suitable substitutes for that persistent generation.

The Registry must support an invalidation operation even when the corresponding Authority account is absent. This absent-Authority case is necessary to invalidate a previously signed but not-yet-landed Init.

### 4.1 Required transition semantics

| Operation | Preconditions | Required atomic postcondition |
|---|---|---|
| First consent / Registry initialization | Subscriber signs; canonical Registry and exact source token account validate; expected initial state is accepted by Program logic | A single canonical consent lineage is initialized. Caller cannot choose an arbitrary generation. |
| Initialize Authority | Subscriber signs; expected Registry generation/action state matches; action is within its Program-enforced validity window | Authority is created/bound to the exact Registry lineage and exact source account. |
| Retry or duplicate Init | Existing Authority is found | Must not silently restore or refresh token delegate approval. Retry semantics must be distinguishable from explicit reauthorization. |
| Revoke / invalidate | Subscriber signs; expected Registry generation and action state match | Persistent invalidation state advances with checked arithmetic. If the old delegate is the Program's delegate, revocation and Authority transition/closure occur in the same atomic transaction. |
| Invalidate while Authority is absent | Subscriber signs; Registry can be created or loaded canonically | A durable tombstone/generation advance is committed so a stale signed Init fails if submitted later. |
| Reauthorize | Explicit new subscriber consent against current invalidated state | New Authority/delegate capability is created only under a new approved generation/action. It must not revive old Subscription or delegation records accidentally. |

The Program's writable Registry account must serialize competing instructions. Both transaction orderings must be tested:

1. Init lands before invalidation: the later invalidation must revoke/advance the lineage.
2. Invalidation lands before stale Init: the old Init must fail without creating or approving Authority.

All generation and action-counter arithmetic must fail closed on overflow. Wraparound, saturating counters that can repeat, caller-selected initial generations, and implicit reset on account recreation are prohibited.

### 4.2 Consent and permission-creation coverage

The current VNext Subscribe path binds new Subscription creation to the current Authority generation and Plan revision. VNext fixed and recurring delegation creation paths do not exist yet. The inherited legacy fixed/recurring paths remain unchanged and are not a VNext compatibility bridge. Before any product use, all permission-creating paths must be explicitly covered, including:

- VNext Subscription creation (implemented; exact-source tests pending);
- VNext fixed delegation creation (NOT IMPLEMENTED);
- VNext recurring delegation creation (NOT IMPLEMENTED);
- any future instruction that can create or restore spend authority.

The legacy UNKNOWN_INIT_ID behavior must not survive as a compatibility bypass. Every VNext permission-creating operation must use a value that the Program can validate against persistent state. Same-transaction convenience flows may be retained only if their transaction ordering, state initialization and replay behavior are safe under the final Registry state machine.

### 4.3 Authority transfer enforcement

A transfer instruction must prove that the Subscription/fixed/recurring permission, current Authority, Registry, subscriber, mint and exact source token account all belong to the same live consent lineage.

The VNext Subscription transfer path now revalidates the exact Subscription/Plan PDAs, current Plan revision and nonce, Subscription lifecycle revision and nonce, live Authority consent generation, exact source account/delegate, token program, caller authorization, destination allowlist and period allowance before CPI. Its signed payload carries those revision/generation snapshots plus a Program-enforced deadline. This does not cover legacy fixed/recurring transfer paths; those remain separate and must not be treated as VNext permissions.

## 5. Subscription and Plan lifecycle revisions

### 5.1 Persistent Subscription lifecycle identity

A separate persistent lifecycle lineage is required for each exact logical Subscription identity: (Plan PDA, subscriber, source token account). The source token account is part of the identity so two consent lineages for the same subscriber/Plan cannot share a lifecycle revision. The current Subscription PDA is closable/reusable, so placing the only revision in that PDA cannot prevent ABA after close/recreate.

The selected identity is (Plan PDA, subscriber, exact source token account), with a persistent 148-byte Registry under the `subscriptionLifecycle` seeds. Subscribe, ordinary Cancel, dual-authorized CancelNow, Resume and re-subscribe advance revision and action nonce with checked arithmetic. The current Subscription PDA is 260 bytes and keyed by the same identity tuple. The Registry is not closed when the Subscription is cancelled; re-subscription is a new lifecycle revision, not a reset. Subscribe checks Plan revision/nonce and Authority generation. Transfer checks live Plan revision/nonce, lifecycle revision/nonce and Authority generation.

Required action coverage includes Subscribe, ordinary cancellation, immediate dual-authorized cancellation, Resume, terminal close/revoke, and re-subscription. A stale CancelNow or Resume signed against an old revision must fail even if timestamps and business fields later return to exactly the same values.

### 5.2 Monotonic Plan revision

Plan administration requires a persistent monotonic revision. Each successful state-changing Plan operation increments the revision with checked arithmetic. Owner-signed updates must bind both the expected revision and the exact state/terms snapshot they were intended to modify.

A stale update must fail after any intervening update, even if Plan values have been changed and then restored (ABA). All mutable Plan actions and every instruction that relies on Plan state must use a consistent revision contract.

The VNext Plan retains the Plan Owner as an implicit Puller and preserves up to four configured Pullers. VNext Plan update currently permits mutable status, Puller and metadata changes only; amount, period, mint, destinations and end timestamp are not updateable. Finite VNext Plans are currently rejected at creation.

### 5.3 Cancellation and Resume semantics

CancelNow's current-period timestamp and Resume's expected expiry timestamp are not unique lifecycle identities. Both must use the persistent Subscription lifecycle revision and action freshness defined by the final protocol.

VNext CancelNow retains the dual-authorization requirement (subscriber and Plan Owner) and consumes the current lifecycle revision/nonce. Resume is supported and requires the current lifecycle revision/nonce plus a live Authority generation. The LiteSVM lifecycle test now exercises ordinary Cancel, Resume, CancelNow and re-subscribe.

## 6. Signed-action freshness, deadlines and smart wallets

Every state-changing authorization that could be delayed must have Program-enforced freshness in addition to a generation/revision check.

The final protocol must define an action-specific nonce or equivalent monotonic one-time value, an expected state revision, and a bounded validity deadline. The Program—not the client—must validate these at execution time.

For Authority Consent Registry v1, authorize and revoke use independent monotonic u64 counters, consumed only on successful state transitions. The on-chain clock is Unix timestamp seconds. The inclusive `not_after_ts` deadline must not be in the past and must be no more than **86,400 seconds (24 hours)** after execution time. Both state transition methods enforce this bound before writing. Expired and overlong actions fail closed. This is a protocol-selected maximum for the current Authority state slice, not a promise that every smart-wallet proposal will remain executable for 24 hours.

#### Versioned Authority instruction ABI — selected

Both instructions use a 24-byte packed payload following a one-byte instruction discriminator:

| Payload offset | Length | Field | Encoding |
|---:|---:|---|---|
| 0 | 8 | expected_generation | u64 little-endian |
| 8 | 8 | expected_nonce | u64 little-endian |
| 16 | 8 | not_after_ts | i64 little-endian |

- `AuthorizeSubscriptionAuthorityVNext`: discriminator **18**. Accounts in order: subscriber signer/writable, Registry writable, VNext Authority writable, mint readonly, source token account writable, System Program readonly, token program readonly, optional Authority rent payer signer/writable.
- `RevokeSubscriptionAuthorityVNext`: discriminator **19**. Accounts in order: subscriber signer/writable, Registry writable, VNext Authority writable (may be absent), mint readonly, source account writable (may be absent for a closed-account tombstone), System Program readonly, token program readonly, optional rent receiver writable.
- The Registry is always funded by the subscriber and is never rent-sponsored. The closeable VNext Authority may be funded by a separate payer; revoke requires the exact recorded payer as rent receiver when that payer differs from subscriber.

These assignments are implemented but not yet frozen; generated IDL synchronization, exact byte/account-meta golden tests and independent review remain required.

Durable Nonce transactions and supported program-controlled-wallet/multisig proposals remain in product scope. They may be enabled only when the Program rejects the operation after its on-chain deadline or after the expected generation/revision/action nonce has advanced. Recent blockhash expiry alone is insufficient. The test matrix must retain a signed proposal, invalidate the underlying state, and then execute the delayed transaction to prove it fails.

## 7. Legacy instruction closure and migration

### 7.1 Legacy instruction paths requiring explicit treatment

The following legacy instruction discriminators are verified from the pinned source:

| Legacy instruction | Current discriminator | Risk requiring VNext treatment |
|---|---:|---|
| InitSubscriptionAuthority | 0 | No generation input; can re-approve u64::MAX on an existing Authority. |
| CloseSubscriptionAuthority | 6 | Closes Authority without advancing a persistent consent generation. |
| Subscribe | 11 | Accepts the legacy init-id/sentinel model. |
| RevokeSubscriptionAuthority | 14 | Revokes/closes through an unversioned lifecycle path. |
| CreateFixedDelegation | 1 | Creates permission via shared Authority and accepts legacy init-id freshness. |
| CreateRecurringDelegation | 2 | Creates permission via shared Authority and accepts legacy init-id freshness. |

The final dispatch design must also review every other instruction that can initialize, mutate, close, reclaim or transfer through Authority, Subscription, Plan or delegation state. Merely adding new discriminators while leaving old unbound paths callable is not an acceptable fix.

No VNext discriminator numbers are assigned here. The complete enum and all data/account layouts must be enumerated at the chosen implementation commit before IDs are allocated.

### 7.2 Legacy account continuity

A migration path must be designed and tested using actual v0.5.0 account fixtures and exact serialized bytes. It must define:

- how active legacy Authority state is represented in the new Registry without resetting or overstating consent;
- how active legacy Subscription/fixed/recurring permissions are recognized;
- how old generation snapshots are compared during a compatibility period;
- what action permanently invalidates the old lineage;
- how a newly authorized VNext lineage avoids reviving stale legacy permissions;
- how rent payers/sponsors and any refund obligations are preserved;
- how interrupted migrations are retried idempotently without a second charge, duplicate entitlement or ambiguous ownership;
- how old Collector/Puller activity is stopped and reconciled before/at cutover;
- how already signed legacy transactions are prevented from reaching VNext funds.

A new Program ID and non-ATA account can provide a strong namespace boundary only after the complete old-program isolation tests pass. They do not silently migrate customer consent or legacy Plans/Subscriptions.

### 7.3 Rollback and recovery

Rollback must not restore an invalidated generation or replayable approval. A rollback plan must describe which Program version may process each account version, how migration state is recovered, and how duplicate billing/entitlement is prevented. A Program downgrade or legacy reactivation that restores a weaker authorization path is not an acceptable rollback.

## 8. ABI design constraints

### 8.1 Account layouts

The baseline uses repr(C, packed) account structures and fixed byte offsets/lengths. The existing Plan pins PLAN_LEN_V1 = 491; SubscriptionDelegation has a frozen V1_LEN used by recovery logic. These are compatibility constraints, not fields to casually edit.

The Authority Consent Registry v1 ABI is specified in §3.1 and is additive: existing v0.5.0 account layouts and discriminators 0–4 are unchanged. Its Rust struct has a compile-time length assertion in the test suite and fixed field offsets.

#### VNext SubscriptionAuthority v1 account ABI — selected

- Account discriminator: **8**; schema version: **1**.
- PDA seeds: `["SubscriptionAuthorityVNext", subscriber, mint, source_token_account]`.
- Total account length: **204 bytes**; integers are little-endian.

| Offset | Length | Field | Encoding |
|---:|---:|---|---|
| 0 | 1 | discriminator | u8 = 8 |
| 1 | 1 | version | u8 = 1 |
| 2 | 1 | bump | u8 |
| 3 | 1 | reserved | u8 = 0 |
| 4 | 32 | subscriber | public key |
| 36 | 32 | mint | public key |
| 68 | 32 | source_token_account | public key |
| 100 | 32 | Registry PDA | public key |
| 132 | 32 | token_program | public key |
| 164 | 32 | rent_payer | public key |
| 196 | 8 | authority_generation | u64 |

The Authority is closeable on revoke; its rent is returned to the recorded payer (or an explicitly supplied matching receiver). Its identity includes the exact non-ATA source account and cannot be substituted across accounts with the same subscriber/mint.

#### Persistent lifecycle revision v1 accounts — selected state slices

- `SubscriptionLifecycleRegistry`: discriminator **6**, version1, **148 bytes**, seeds `["subscriptionLifecycle", plan_pda, subscriber, source_token_account]`. It stores Plan, subscriber, exact source token account, recorded payer, monotonic revision and action nonce.
- `PlanRevisionRegistry`: discriminator **7**, version1, **116 bytes**, seeds `["planRevision", merchant, plan_pda]`. It stores Plan, merchant, recorded payer, monotonic revision and action nonce.
- Both are designed as persistent, non-closeable lineages. Their state methods use checked increments and expected revision/nonce comparisons.

#### VNext Plan and Subscription account ABI — implemented, pending freeze

- `VNextPlan`: discriminator **9**, version **1**, **500 bytes**, PDA seeds `["planVNext", merchant, plan_id_le]`. It stores the merchant owner, current Plan revision and the VNext PlanData snapshot. The persistent PlanRevisionRegistry is the monotonic authority for updates; VNext Plan creation initializes both at revision 1.
- `VNextSubscription`: discriminator **10**, version **1**, **260 bytes**, PDA seeds `["subscriptionVNext", plan_pda, subscriber, source_token_account]`. It stores the exact source token account, mint, token program, rent payer, immutable billing terms, period accounting, expiry timestamp, lifecycle revision and Authority generation.
- Neither VNext Plan nor Subscription has an ordinary close/reset instruction. There is no `DeletePlanVNext` or `CloseSubscriptionVNext` discriminator in the current enum. A cancelled Subscription can be re-subscribed only after its stop boundary; its persistent lifecycle Registry is advanced rather than reset.
- VNext Plan v1 rejects non-zero `end_ts`; finite Plan semantics and full-period/expiry policy remain open for a later version.

The state structs are allocated and consumed by the VNext runtime handlers. Subscribe, ordinary Cancel, dual-authorized CancelNow, Resume and re-subscribe advance the persistent lifecycle Registry atomically with the Subscription state. Plan create/update advance the persistent Plan revision Registry. Every VNext transfer checks the live revision/nonce snapshots. No VNext DeletePlan or Subscription-close instruction exists; re-subscribe reuses the existing Subscription PDA only after its cancellation boundary and never resets the persistent lifecycle Registry. No existing v1 layout may be changed in place unless a tested byte-compatible migration is proven.

### 8.2 Instruction data and account metas

The baseline uses a one-byte instruction discriminator followed by packed Codama-generated instruction data. The VNext ABI must specify:

- a non-colliding instruction discriminator;
- exact payload byte length and field offsets;
- exact required account order, signer and writable flags;
- optional-account encoding and remaining-account policy;
- all token program, system program, event-authority and self-program constraints;
- version and unknown-field handling;
- exact error behavior for stale generation, stale revision, stale nonce, expired action and wrong source account.

The current additive VNext instruction assignments are:

| Instruction | Discriminator | Payload |
|---|---:|---|
| AuthorizeSubscriptionAuthorityVNext | 18 | AuthorityActionData, 24 bytes |
| RevokeSubscriptionAuthorityVNext | 19 | AuthorityActionData, 24 bytes |
| CreatePlanVNext | 20 | VNextCreatePlanData, 464 bytes (deadline + PlanData) |
| UpdatePlanVNext | 21 | VNextPlanUpdateData, 538 bytes |
| SubscribeVNext | 22 | VNextSubscribeData, 113 bytes |
| CancelSubscriptionVNext | 23 | RevisionActionData, 24 bytes |
| CancelSubscriptionNowVNext | 24 | RevisionActionData, 24 bytes |
| ResumeSubscriptionVNext | 25 | RevisionActionData, 24 bytes |
| TransferSubscriptionVNext | 26 | VNextTransferData, 120 bytes |

The existing instruction discriminators 0–17 remain unchanged. The current Rust enum and Codama annotations define account order and signer/writable flags. TransferHook remaining accounts are forwarded through the existing Token-2022 helper. These assignments are implemented and the Codama IDL has been regenerated and committed at source checkpoint c7882a5. The exact-source CI equality check is pending; golden byte/account-meta tests and independent review remain required.

`VNextTransferData` v1 is exactly 120 bytes, little-endian/packed:

| Offset | Length | Field | Encoding |
|---:|---:|---|---|
| 0 | 8 | amount | u64 |
| 8 | 32 | delegator | public key |
| 40 | 32 | mint | public key |
| 72 | 8 | expected_plan_revision | u64 |
| 80 | 8 | expected_plan_nonce | u64 |
| 88 | 8 | expected_lifecycle_revision | u64 |
| 96 | 8 | expected_lifecycle_nonce | u64 |
| 104 | 8 | expected_authority_generation | u64 |
| 112 | 8 | not_after_ts | i64 |

The Program validates all snapshot values and the 24-hour deadline before token movement. No discriminator or payload should be renumbered or resized after SDK generation without an explicit versioned ABI migration.

### 8.3 IDL, Rust and TypeScript client contract

Codama annotations are part of the protocol surface. Every account and instruction change must update the canonical Rust source and generated IDL/client artifacts in one reviewed change. CI must fail if generation changes are missing, generated output is stale, or a release artifact does not match the checked-in source.

There is no Anchor.toml/Anchor IDL contract in this repository; do not introduce Anchor conventions by assumption.

## 9. Capability preservation requirements

No feature is permanently de-scoped as a shortcut for security. Each capability must have an explicit VNext state model, authorization rule, migration behavior and regression tests.

The intended retained surface remains:

- VNext Authority consent, invalidation and explicit reauthorization (runtime implemented; exact-source tests pending);
- independent source-account-bound permissions;
- VNext Plan create/update and persistent Plan revision (runtime implemented; no VNext delete/recovery path yet);
- VNext Subscribe, regular cancellation, immediate dual-authorized cancellation, Resume, transfer and re-subscription (runtime implemented; integration tests added; CI pending);
- Plan Owner plus up to four additional Pullers;
- SPL Token and Token-2022/TransferHook transfer forwarding (code path present; VNext-specific TransferHook tests pending);
- events and generated Codama IDL (VNext ABI regenerated and committed; exact-source CI equality check pending);
- fixed/recurring VNext permissions, finite Plan support, Plan deletion/rent recovery, full rent-sponsorship policy, legacy migration/recovery and smart-wallet/durable-nonce compatibility (NOT IMPLEMENTED / OPEN).

The exact financial/business semantics for partial final periods, rent sponsor quotas/recovery and split/multiple destinations must follow the approved product contract and executable tests. This document does not invent those values or policies.

## 10. Mandatory adversarial test matrix

Tests must run against the exact VNext Program source SHA and, where relevant, the exact old v0.5.0 binary/source. Unit-only mocks are insufficient for CPI and account-ownership assertions.

### Authority Registry and source-account isolation

1. Create a signed Init/Subscribe (and fixed/recurring permission) bundle at generation g, withhold it, invalidate to g+1, then submit the old bundle. It must fail without recreating Authority, approving a delegate or creating permission.
2. Repeat when no Authority exists at signing time; invalidation must create the durable Registry/tombstone and stale Init must fail.
3. Reverse ordering: Init lands first, followed by invalidate; final state must have the delegate revoked and generation advanced.
4. Repeat in the same slot, later slots, after Authority close/recreate and after reauthorization.
5. Revoke/invalidate while the Registry exists but the Authority does not.
6. Replay the same action nonce, use a nonce for a different action class, skip a nonce where final rules forbid it, and race two transactions against the same writable Registry.
7. Test generation and nonce overflow; all cases must fail closed.
8. Test wrong subscriber, mint, source account, token program, Registry PDA, bump, owner, discriminator and account version.
9. Test two non-ATA source accounts for the same subscriber/mint and an ATA/non-ATA pair; consent for one must not authorize the other.
10. Run all legacy Init/Close/Subscribe/Revoke/fixed/recurring instructions against the VNext source account using the exact old Program; prove no delegate mutation, close-authority mutation, debit or VNext Registry/Authority mutation.
11. Test external SPL Token delegate changes and raw Revoke separately. Do not claim a raw external SPL Revoke advances Program Registry state unless the protocol actually observes and commits that state.
12. Test atomic rollback when token CPI fails after Registry/Authority state validation or mutation.

### Subscription and Plan revisions

13. Sign CancelNow and Resume at revision r, change lifecycle state through a valid intervening action, recreate the Subscription account and submit the stale approvals. They must fail even if timestamps match.
14. Exercise same-second and same-timestamp ABA cases for CancelNow and Resume.
15. Sign UpdatePlan at revision p, mutate a Plan field and restore the original value, then submit the stale update. It must fail.
16. Test concurrent Subscribe/Cancel/Resume/Revoke actions using the same persistent Subscription lifecycle account.
17. Test Plan revision overflow, malformed Plan revision state, wrong Plan owner/PDA and stale Plan snapshots.
18. Test all Plan Owner and additional Puller combinations, including owner removal attempts and Puller rotation.
19. Test partial/final period semantics at exact boundaries, including timestamp equality, before expiry and after expiry.

### ABI, clients and migration

20. Golden-test exact VNext account bytes and instruction bytes, including discriminators, account order, signer/writable flags and payload length.
21. Verify generated Codama IDL, Rust client and TypeScript client agree byte-for-byte with the ABI.
22. Migrate real v0.5.0 fixtures, including absent/existing/sponsored Authority, active/inactive subscriptions, fixed/recurring delegations and close/recovery states.
23. Interrupt and retry migration at each boundary; no duplicated permissions, charges, rent refunds or entitlements may result.
24. Test durable-nonce and delayed smart-wallet/multisig proposals: after generation/revision/nonce advancement or deadline expiry, submission must fail at Program execution.
25. Run the complete inherited baseline test suite plus all new regression tests. No capability may be considered preserved solely because it compiles.

## 11. Program ID and governance decision

The existing v0.5.0 Program ID is De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44. The recorded Mainnet ProgramData governance path resolves to Squads V4 with a 3-of-5 threshold and zero-second timelock; member identity/custody is UNKNOWN. SolMint must not assume it can unilaterally upgrade this Program ID.

The independent route is therefore a new Program ID for VNext unless legitimate, separately verified upgrade authority is established. The exact VNext Program ID must not be invented or generated in this design document. Any keypair generation, authority assignment, Program deployment, upgrade, Squads proposal or transaction requires separate explicit authorization and key-custody procedure.

## 12. Design decisions still OPEN

The following decisions remain open for the next implementation slices:

1. Separate VNext Program ID and keypair generation/custody. The source still declares the legacy Program ID; no independent Program identity or deployment exists. Do not generate a keypair or deploy without explicit authorization.
2. Complete old Program isolation across every legacy Init/Close/Subscribe/Revoke/fixed/recurring/transfer/remaining-account path. Current LiteSVM coverage targets only legacy Init against a non-ATA source.
3. Legacy lazy-bootstrap versus explicit migration, and exact migration/rollback semantics for active legacy Plans, Subscriptions, balances, sponsors, Pullers, pending signatures and entitlements.
4. VNext fixed and recurring delegation handlers and their per-transfer Registry enforcement.
5. VNext Plan deletion, rent recovery and finite Plan policy. Current VNext CreatePlan rejects non-zero end_ts; no DeletePlanVNext instruction exists.
6. Complete token-account authority policy, including pre-existing delegate and close-authority replacement, supported Token-2022 extensions and VNext TransferHook adversarial tests.
7. Rent payer exposure, quota, sponsorship/refund and excess-rent recovery; no ordinary Registry close/reset path is permitted.
8. Durable nonce and smart-wallet/multisig delayed proposal compatibility under the on-chain deadlines.
9. Generated IDL/SDK/client synchronization, ABI golden tests, complete adversarial test coverage and independent audit.

The owner explicitly authorized continuing the design from the repository structure without the omitted prompt continuation. The Registry v1 field set and layout above are therefore selected engineering decisions, not claims that they appeared in the missing prompt. These remaining decisions must be resolved from source invariants and adversarial tests before their own ABI slices are frozen.

## 13. Checkpoint and implementation gates

Current status at document authoring:

- G1-0 baseline/branch checkpoint: PASS / COMPLETE according to the latest recorded progress checkpoint.
- G1-1 independent source intake: IN PROGRESS. The MIT fork and reproducible v0.5.0 baseline are established; fork-native CI visibility remains UNKNOWN.
- G1-2 protocol/ABI: IN PROGRESS. Authority Consent Registry and VNext Authority v1 account layouts plus authorize/revoke instruction payload/account order are specified. Complete Subscription, Plan, transfer, migration and client ABI is not frozen.
- G1-3 Program implementation: IN PROGRESS — Authority Registry, tuple-bound Authority, Subscription lifecycle and Plan revision state structs are added; authorize/revoke handlers are wired to dispatch; three LiteSVM scenarios are written. Exact-source Rust/LiteSVM execution and Codama IDL regeneration are pending.
- G1-4 migration: NOT STARTED.
- G1-5 adversarial proof: NOT STARTED.
- G1-6 independent audit: NOT STARTED.
- G1-7 Devnet deployment/rehearsal: NOT STARTED.
- G1-8 Mainnet deployment/migration: NOT STARTED.
- G1 overall: BLOCKED.

Before G1-3, the following must be checked in a single reviewed change set:

1. Complete prompt requirements and all OPEN decisions above are resolved.
2. Protocol transition tables and threat-model traceability are reviewed.
3. Account and instruction ABI is byte-specified and golden-tested.
4. Full legacy path inventory is complete.
5. Source-account isolation and Program ID decision are reviewed.
6. Migration and rollback contracts are defined.
7. Every supported capability has explicit state, authorization, migration and regression requirements.

VNext Authority, Plan and Subscription runtime handlers are now present. Plan create/update and Subscription Subscribe/Cancel/CancelNow/Resume/re-subscribe use persistent revision registries; VNext transfer revalidates live Plan/Subscription revisions, Authority generation and a bounded deadline. LiteSVM tests have been added for delayed signed Authority authorization, Plan ABA update, Subscription lifecycle transitions, valid token transfer, stale Subscribe/Transfer and legacy Program non-ATA isolation. On source SHA ebb3b87, Rust formatting, Program unit tests, deterministic SBF build, the full LiteSVM suite, exact immutable legacy v0.5.0 SBF build and the legacy non-ATA isolation regression all passed. The only failure was the generated-IDL byte comparison; the exact generated 187,274-character IDL was then committed at c7882a5. A final exact-source CI run with the synchronized IDL is pending. The source still declares the legacy Program ID, and no deployment Program ID/keypair has been generated. No signer, Devnet/Mainnet transaction, Production database/configuration, customer consent, accounting entry or customer funds were changed.
