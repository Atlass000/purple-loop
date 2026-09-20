# PURPLE-LOOP — Cybersecurity Attack / Defense Simulation (Red vs Blue)

A dynamic multi-agent orchestration in which an attacker agent, a defender agent and an
independent auditor argue over a shared state object until the auditor certifies
convergence or the round budget runs out. Control flow is decided per turn by two LLM
judgments — the auditor's verdict and the router's routing decision. There is no fixed
pipeline and no if/else decision tree.

**Input:** a free-text description of a system architecture (fictional).
**Output:** a negotiated security posture report with a 0–100 score, the disagreement
history, accepted residual risks, and a calibration ledger for each agent.

> **Scope and safety.** This is a tabletop exercise over a *fictional*, text-described
> architecture. Attack reasoning stays at the level of vulnerability classes and MITRE
> ATT&CK technique IDs. A dedicated `safety-guardian` agent inspects every attacker
> output before it reaches shared state and redacts anything operational. This is an
> architectural component, not a disclaimer.

---

## Agent team

| Agent | Node type | Role |
|---|---|---|
| `orchestrator-router` | **Chief** | Chooses the next agent and writes its mandate. Produces no security content. |
| `recon-analyst` | Sub-agent | Decomposes the target into assets, trust boundaries, coverage map. |
| `red-team` | Sub-agent | Attacker. Two lanes: software/logic and social engineering / human process. |
| `blue-team` | Sub-agent | Defender. Layered countermeasures: preventive + detective + containment. |
| `security-auditor` | Sub-agent | Independent judge. Scores, contests, routes, and authors the final report. |
| `safety-guardian` | Sub-agent | Filter on every `red-team` output before the state write. |

`red-team` and `blue-team` never communicate directly. **All inter-agent communication is
mediated by the shared state**, which makes every turn inspectable and replayable.

---

## 1. State management

One JSON object, `EngagementState`, is the only channel between agents. Keep it in
`state/engagement.json`. Full schema: `references/state-schema.json`.

Each agent receives only the fields it is entitled to read, and returns a **patch**,
never a full rewrite:

| Agent | May read | May write |
|---|---|---|
| `recon-analyst` | `target_spec` | `asset_inventory`, `trust_boundaries`, `coverage_map`, `unknowns` |
| `red-team` | `asset_inventory`, `trust_boundaries`, `coverage_map`, `findings`, `mitigations`, `audit_verdicts` | `findings[]` (via the guardian) |
| `blue-team` | `asset_inventory`, `findings`, `mitigations`, `audit_verdicts` | `mitigations[]` |
| `security-auditor` | everything except `target_spec` | `audit_verdicts[]`, `scorecard`, `calibration_ledger`, `convergence`, `final_report` |
| `safety-guardian` | candidate `red-team` output | sanitized finding, `guardian_log` |

### Invariants — enforce these before applying any patch

1. **Findings are append-only.** A finding is never deleted; it is `DISMISSED` or
   superseded, with a reason. The disagreement history is part of the deliverable.
2. **Every mitigation must reference a live finding.** Orphan defences are rejected —
   this stops the defender inflating the score by "fixing" imaginary problems.
3. **The auditor may not author findings or mitigations.** Separation of powers: the
   judge may only score, contest, and instruct.
4. **Only `safety-guardian` may write attacker content.** Raw `red-team` output never
   lands in shared state.
5. **No agent may extend `max_rounds`.** Only the human operator can.

If a patch violates an invariant, reject it, log it in `patch_history` with the reason,
and re-route. Do not silently repair it.

### Context economy

Prior-round findings are passed as one-line compactions, not full narratives. Never pass
another agent's raw reasoning transcript. This keeps token cost roughly flat as rounds
accumulate and forces agents to communicate in structured claims.

---

## 2. Reflection & feedback loops

### Loop A — intra-agent (inside one turn)

Every content agent drafts, self-critiques, and revises before emitting its patch. The
self-critique questions are written into each agent's own prompt. Rejected drafts are
reported in `self_rejected` rather than silently dropped — a withheld finding is
evidence of calibration, not a wasted turn.

### Loop B — adversarial cross-critique (round level)

The auditor's verdict on each finding/mitigation pair chooses the next move:

| Verdict | Meaning | Loop consequence |
|---|---|---|
| `SOUND` | Mitigation credibly closes the finding | → `MITIGATED`; budget moves to coverage gaps |
| `INSUFFICIENT` | Partial or shallow | → `blue-team` with a named deficiency |
| `CHALLENGE` | Plausible but untested | → `red-team`: *assume this patch is live, bypass it* |
| `OVERCLAIM` | Residual-risk claim unsupported | → `blue-team`; score penalty recorded |
| `SPECULATIVE` | Finding not reachable | → `DISMISSED`; attacker calibration penalised |
| `RESIDUAL_ACCEPT` | Real risk, no viable control | Recorded as accepted residual risk |

`CHALLENGE` is what makes this a loop rather than a pipeline: **the defender's own patch
becomes the attacker's next target.** A control that survives a challenge unbroken earns
a durability bonus (+3). A control that is merely asserted sound earns nothing.

### Loop C — convergence control (engagement level)

```
converged =  new_findings_last_round == 0
         AND unresolved_count == 0
         AND |score_delta| < 3.0
```

**Anti-premature-agreement guard:** if the attacker's average novelty falls below 0.25,
do *not* declare convergence — force a lane switch instead. A stalled debate is not a
secure system. Self-critiquing agent teams fail by agreeing too early; this is the
countermeasure.

**Cross-round calibration:** a high-confidence finding later dismissed lowers the
attacker's weight multiplier; an unsupported residual claim lowers the defender's.
Agents are held accountable across turns, not only within one.

---

## 3. Dynamic routing

At each turn the router receives a compact **state digest** (not the full state) plus the
set of **legal moves** computed from the invariants, and returns:

```json
{ "next_agent": "RED",
  "mandate": "Focus exclusively on the human layer; insider and vendor_chain are at 0.0 coverage.",
  "scope_filter": ["A1", "A4"],
  "lane": "social",
  "rationale": "Logic lane saturated (novelty 0.18); two untouched human vectors remain.",
  "expected_state_change": ">=1 new finding in human_layer" }
```

Three properties keep this non-arbitrary:

1. **Constrained action space.** `blue-team` is illegal when no finding is open;
   `security-auditor` is illegal before a mitigation exists. The router exercises LLM
   judgment *inside* a formally bounded set — never outside it.
2. **Mandate, not just destination.** Two calls to `red-team` in one engagement are
   different agents in effect, because the mandate reshapes the objective.
3. **Falsifiable prediction.** Every routing decision carries an `expected_state_change`
   that is checked next round. Repeated mispredictions push the router to change
   strategy — routing itself sits under a feedback loop.

**Routing signals** (reason over these; they are inputs, not rules): coverage cells near
zero → recon or a lane mandate · open findings with no mitigation → blue · pending
`INSUFFICIENT` → blue with the deficiency · pending `CHALLENGE` → red with a bypass
mandate · novelty below 0.25 → lane switch · budget nearly spent → auditor.

**Escalation.** If no legal move would meaningfully advance the engagement — for example
the target description is too thin — return `next_agent: "HUMAN"` with one specific
question. Pause rather than hallucinate depth.

---

## 4. Scoring

| Dimension | Weight |
|---|---|
| Attack surface coverage | 20% |
| Defense depth (layers per mitigated finding) | 25% |
| Detection coverage | 20% |
| Blast-radius control | 15% |
| Residual exploitability (inverse) | 20% |

Durability bonus +3 per mitigation surviving a `CHALLENGE`. Overclaim penalty −2.
Calibration penalty −0.5 per dismissed high-confidence finding.
Grades: A ≥ 85, B ≥ 75, C ≥ 65, D ≥ 55, F < 55. Full rubric: `references/scoring-rubric.md`.

---

## 5. Run protocol

1. Initialise `EngagementState` with `target_spec` and `max_rounds` (6–12 recommended).
2. Call `orchestrator-router`. It returns `next_agent` + `mandate`.
3. Run that agent against its state projection. If it is `red-team`, pass the output
   through `safety-guardian` **before** writing to state.
4. Validate the patch against the invariants; apply or reject with a logged reason.
5. Recompute the scorecard and convergence. Stop if converged or out of budget.
6. Otherwise return to step 2. Never hand control from one content agent to another.
7. **Closing turn:** call `security-auditor` once more with `summary_only: true` so the
   audit agent — not the harness — authors the final report over the finished state.

A reference implementation of this protocol, including a self-test that asserts every
invariant above, ships alongside this skill as `purple_loop.py`.
