# PURPLE-LOOP
### A Dynamic Multi-Agent Orchestration Architecture for Adversarial Security Evaluation

**Course:** Orchestration — Capstone Project
**Topic:** Cybersecurity Attack / Defense Simulation (Red vs Blue)
**Platform target:** Myskillos (myskillos.com) — agent definitions are platform-portable

---

## 0. Compliance Map — brief requirement → where it is satisfied

| Requirement (as stated in the brief) | Where it is satisfied | Verifiable how |
|---|---|---|
| Dynamic multi-agent orchestration architecture | §2 roster, §5 routing, orchestration map below | `--self-test` check 10 asserts the executed agent sequence is not a fixed cycle |
| LLM agents **critique** one another | §4 Loop B: six-verdict cross-critique; Blue's patch becomes Red's target | Report §4 "Disagreement history" — every verdict with its rationale |
| LLM agents **audit** one another | Independent `security-auditor` with separation of powers (§3.2 invariant 3) | `--self-test` check 3: the Auditor is structurally prevented from authoring findings |
| LLM agents **make decisions** with one another | §5: the Router's next move is an LLM decision inside a constrained legal-move set | Report §2 "Routing history" — legal moves vs. chosen move, per round |
| **Not** static/classic if-else code | Deterministic code only *validates* moves; it never chooses them | §7 rounds 5, 8 and 9–11 are unreachable in a pipeline |
| Built with Claude, uploaded to Myskillos | §11: importable `CLAUDE.md + .claude/agents/*.md` package, generated from this document | `python purple_loop.py --build-package` |
| Red Team: social engineering **and** software logic | `red-team` runs two lanes; the Router switches lanes on novelty collapse | Report §3 — `lane` column per finding |
| Red Team devises an attack scenario | `attack_narrative` per finding: abstract kill chain + MITRE ATT&CK IDs | Report §3 and `final_state.json` |
| Blue Team develops patches and countermeasures | Three mandatory layers: preventive / detective / containment | Report §3; missing layers are scored down, not silently accepted |
| Audit agent produces final security score | §6 weighted rubric, 0–100 with grade bands | Report §1 "Score breakdown" |
| Audit agent produces the report | The closing turn is the auditor authoring the report over the finished state | Report §0 — written by the agent, not by the harness |
| **State Management** | §3 | `--self-test` checks 1, 2, 8 |
| **Reflection & Feedback Loops** | §4 | `--self-test` check 9 (challenge → durability bonus) |
| **Dynamic Routing** | §5 | `--self-test` checks 9, 10 |

![PURPLE-LOOP orchestration map](architecture.png)

---

## 1. Problem Statement

A classic security-review script is static: it walks a checklist, matches patterns with `if/else`, and emits a score. It cannot reason about *novel* attack composition, it cannot argue with itself, and it cannot decide that a question deserves a second look.

**PURPLE-LOOP** replaces that with a debate. Three primary LLM agents — an attacker, a defender, and an auditor — are placed in an adversarial loop over a shared state object. None of them decides how long the engagement runs or who speaks next; a **Router agent** makes that call at every turn based on the *current epistemic state* of the engagement. The system halts only when the auditor certifies convergence, or when the round budget is exhausted.

The output is not a checklist. It is a negotiated security posture assessment with a documented disagreement history.

> **Scope and safety.** This is a *tabletop* simulation. The Red Team agent reasons at the level of vulnerability **classes**, MITRE ATT&CK **technique IDs**, and kill-chain **narratives** against a fictional architecture supplied as text. A dedicated Safety Guardian agent enforces that no agent ever emits working exploit code, live payloads, malware, or operational intrusion instructions. Attack reasoning that cannot be expressed abstractly is redacted, not produced. This constraint is an architectural component, not a disclaimer.

---

## 2. Agent Roster

| # | Agent | Role | Reads from state | Writes to state |
|---|-------|------|------------------|-----------------|
| 0 | **ORCHESTRATOR (Router)** | Meta-agent. Chooses the next agent and the *mandate* it receives. Never produces security content. | full state (summarized) | `routing_log`, `next_agent`, `mandate` |
| 1 | **RECON** | Decomposes the target architecture into an asset/trust-boundary/data-flow inventory. Runs once, plus on demand when Red claims missing information. | `target_spec` | `asset_inventory`, `trust_boundaries`, `coverage_map` |
| 2 | **RED** | Attacker. Produces attack hypotheses across two lanes: *software/logic* and *social engineering / human process*. | `asset_inventory`, `mitigations`, `audit_verdicts` | `findings[]` |
| 3 | **BLUE** | Defender. Produces layered countermeasures: preventive patch, detection rule, and containment/blast-radius control per finding. | `findings[]`, `audit_verdicts` | `mitigations[]` |
| 4 | **AUDITOR** | Independent judge. Scores each finding/mitigation pair, detects unaddressed residual risk, and issues the **verdict** that drives the loop. Produces the final report. | everything | `audit_verdicts[]`, `scorecard`, `convergence` |
| 5 | **SAFETY GUARDIAN** | Cross-cutting filter. Inspects every RED output before it enters shared state. Redacts operational detail, rewrites to abstract form, or rejects. | candidate RED output | `guardian_log`, sanitized finding |

Agents 2 and 3 never talk to each other directly. **All inter-agent communication is mediated by shared state**, which makes the system inspectable and replayable.

---

## 3. State Management

### 3.1 The blackboard

A single JSON object, `EngagementState`, is the only channel between agents. Each agent receives a *projection* of it (only the fields it is entitled to read), and returns a **patch**, never a full rewrite. Patches are applied by the orchestrator with an append-only history, so any turn can be replayed or diffed.

```jsonc
{
  "engagement_id": "eng-2026-001",
  "round": 3,
  "max_rounds": 6,
  "phase": "CHALLENGE",

  "target_spec": "<free-text system architecture supplied by the user>",

  "asset_inventory": [
    { "id": "A1", "name": "Customer PII store", "tier": "crown_jewel",
      "exposure": "internal", "owner": "platform" }
  ],
  "trust_boundaries": [
    { "id": "TB1", "from": "public internet", "to": "API gateway",
      "controls": ["WAF", "rate limit"] }
  ],

  "coverage_map": {
    "STRIDE": { "spoofing": 0.8, "tampering": 0.4, "repudiation": 0.0,
                "info_disclosure": 0.9, "dos": 0.3, "eop": 0.6 },
    "human_layer": { "phishing": 0.7, "pretexting": 0.2,
                     "insider": 0.0, "vendor_chain": 0.1 }
  },

  "findings": [
    { "id": "F3", "round_introduced": 2, "lane": "logic",
      "title": "Password-reset token not bound to session",
      "attack_narrative": "<abstract kill-chain, no payloads>",
      "attck": ["T1078", "T1556"],
      "assets_hit": ["A1"],
      "likelihood": 4, "impact": 5, "confidence": 0.7,
      "status": "CONTESTED",           // OPEN | MITIGATED | CONTESTED | RESIDUAL | DISMISSED
      "novelty": 0.8,
      "supersedes": ["F1"]
    }
  ],

  "mitigations": [
    { "id": "M3", "finding_id": "F3", "round": 2,
      "preventive": "...", "detective": "...", "containment": "...",
      "cost": "medium", "residual_risk_claim": 0.2,
      "assumptions": ["IdP supports token binding"] }
  ],

  "audit_verdicts": [
    { "round": 2, "finding_id": "F3", "verdict": "INSUFFICIENT",
      "rationale": "Detection rule covers only the happy path; no control for the vendor-support channel.",
      "residual_risk_assessed": 0.55,
      "instruction_to": "RED",
      "mandate": "Attack the proposed patch M3 directly; assume it is deployed." }
  ],

  "scorecard": {
    "attack_surface_coverage": 0.72,
    "defense_depth": 0.61,
    "detection_coverage": 0.45,
    "blast_radius_control": 0.58,
    "residual_exploitability": 0.34,
    "composite": 63.4, "grade": "C+"
  },

  "convergence": {
    "new_findings_last_round": 1,
    "unresolved_count": 2,
    "score_delta": 4.1,
    "converged": false
  },

  "routing_log": [
    { "round": 2, "chose": "BLUE", "why": "2 OPEN findings with no mitigation; Red novelty falling." }
  ],
  "guardian_log": [
    { "round": 2, "target": "F3", "action": "REDACT",
      "note": "Removed step-level request construction; kept abstract technique reference." }
  ]
}
```

### 3.2 State invariants (enforced by the orchestrator)

1. **Append-only findings.** A finding is never deleted; it is `DISMISSED` or `supersede`d, with a reason. The disagreement history is part of the deliverable.
2. **Every mitigation must reference a live finding.** Orphan defenses are rejected — this stops Blue from "defending" imaginary problems to inflate the score.
3. **The Auditor cannot author findings or mitigations.** Separation of powers: the judge may only score, contest, and instruct.
4. **Only the Guardian may write sanitized RED content.** Red's raw output never lands in shared state directly.
5. **Monotone round counter.** No agent can extend `max_rounds`; only the human operator can.

### 3.3 Context economy

Full state grows fast. Each agent receives:
- its entitled fields in full for the **current** round,
- a rolling **compaction** of prior rounds (Auditor-generated one-line summaries per finding),
- never the raw transcript of other agents' reasoning.

This keeps token cost roughly flat as rounds increase, and forces agents to communicate through structured claims rather than prose.

---

## 4. Reflection & Feedback Loops

Three nested loops operate at different timescales.

### Loop A — Intra-agent reflection (within one turn)

Every content agent runs a **draft → self-critique → revise** cycle inside a single turn before emitting its patch.

- **RED** drafts findings, then self-critiques against: *Is this actually reachable given the trust boundaries? Am I assuming a control that doesn't exist? Is this a restatement of an existing finding?* Findings that fail self-critique are dropped with a logged reason.
- **BLUE** drafts a mitigation, then attacks its own patch: *What does this control NOT stop? What new failure mode does it introduce? What does it assume about the environment?* The surviving assumptions become the `assumptions[]` field — which the Auditor later uses as attack surface.
- **AUDITOR** drafts a score, then checks it for anchoring: *Would I give the same score if this finding had arrived in round 1 instead of round 4?*

### Loop B — Adversarial cross-critique (round-level)

This is the core engine. The Auditor's verdict on each finding/mitigation pair selects the loop's next move:

| Verdict | Meaning | Loop consequence |
|---------|---------|------------------|
| `SOUND` | Mitigation credibly closes the finding | Finding → `MITIGATED`; freed budget goes to coverage gaps |
| `INSUFFICIENT` | Patch is partial or shallow | Back to **BLUE** with a specific deficiency to fix |
| `CHALLENGE` | Patch is plausible but untested | To **RED** with mandate *"assume this patch is live — bypass it"* |
| `OVERCLAIM` | Blue's residual-risk claim is not supported | Blue must re-state with evidence; score penalty recorded |
| `SPECULATIVE` | Red's finding is not reachable / unsupported | Finding → `DISMISSED`, Red's confidence calibration penalized |
| `RESIDUAL_ACCEPT` | Real risk, no viable mitigation at reasonable cost | Recorded as accepted residual risk in the report |

The `CHALLENGE` verdict is what makes this a genuine loop rather than a pipeline: **Blue's own patch becomes Red's next target.** A defense that survives two challenge rounds earns a durability bonus in the final score.

### Loop C — Convergence control (engagement-level)

After each round the orchestrator computes:

```
converged =  new_findings_last_round == 0
         AND unresolved_count == 0
         AND |score_delta| < 3.0
```

…or `round >= max_rounds`. If Red's `novelty` average drops below 0.25 for two consecutive rounds, the orchestrator forces a **lane switch** (logic ↔ social engineering) before allowing convergence — preventing premature agreement, which is the classic failure mode of self-critiquing agent systems.

**Calibration feedback.** Confidence scores are scored against outcomes: a Red finding claimed at 0.9 confidence that is later `DISMISSED` lowers Red's calibration multiplier, which the Auditor applies as a discount on subsequent Red claims. Agents are thus held accountable across rounds, not just within a turn.

---

## 5. Dynamic Routing

### 5.1 Why not `if/else`

A static flow (`Recon → Red → Blue → Audit → end`) wastes turns on solved areas and starves contested ones. PURPLE-LOOP instead treats routing as a **decision made by an LLM under constraints**.

### 5.2 The mechanism

At each turn the Router receives a compact **state digest** (not the full state) and must return:

```json
{ "next_agent": "RED",
  "mandate": "Focus exclusively on the human layer; insider and vendor-chain are at 0.0 coverage.",
  "scope_filter": ["A1", "A4"],
  "rationale": "Logic lane saturated (novelty 0.18); coverage_map shows two untouched human vectors.",
  "expected_state_change": "≥1 new finding in human_layer, coverage_map.human_layer.insider > 0"
}
```

Three properties make this safe and non-arbitrary:

1. **Constrained action space.** The orchestrator computes the set of *legal* moves from state invariants (e.g. BLUE is illegal when there are no `OPEN` findings; AUDITOR is illegal before at least one mitigation exists this round). The Router chooses only within that set — LLM judgment inside a formally bounded space.
2. **Mandate, not just destination.** The Router doesn't only pick *who* speaks, it writes *what they must accomplish*. Two calls to RED in the same engagement are different agents in effect, because the mandate reshapes their objective.
3. **Justification + falsifiable prediction.** Every routing decision carries a rationale and an `expected_state_change`. Next round the orchestrator checks whether the prediction held. Repeated mispredictions push the Router toward different strategies — routing itself is under a feedback loop.

### 5.3 Routing heuristics available to the Router

The Router is *told* these signals and reasons over them; it is not hard-coded to them.

| Signal | Typical routing pull |
|--------|---------------------|
| `coverage_map` cell near 0 | → RECON or RED with a lane mandate |
| `OPEN` findings, no mitigation | → BLUE |
| `INSUFFICIENT` verdicts pending | → BLUE with deficiency mandate |
| `CHALLENGE` verdicts pending | → RED with bypass mandate |
| Red novelty < 0.25 | → lane switch, or RECON to find new surface |
| Round budget nearly spent | → AUDITOR for final report |
| Guardian rejection rate high | → RED with reframing mandate |

### 5.4 Escalation to the human

If the Router twice fails to find a legal, useful move — for example when the `target_spec` is too thin to support further analysis — it emits `next_agent: "HUMAN"` with a specific question. The engagement pauses rather than hallucinating depth it doesn't have.

---

## 6. Scoring Model (Auditor's rubric)

Composite score on 0–100, weighted:

| Dimension | Weight | Definition |
|-----------|--------|------------|
| Attack surface coverage | 20% | Fraction of STRIDE + human-layer cells meaningfully probed |
| Defense depth | 25% | Mean layers per mitigated finding (preventive / detective / containment) |
| Detection coverage | 20% | Fraction of findings with a concrete detection signal |
| Blast-radius control | 15% | Containment quality for crown-jewel assets |
| Residual exploitability | 20% (inverse) | Auditor-assessed post-mitigation risk, weighted by asset tier |

**Durability bonus:** +3 per mitigation that survived a `CHALLENGE` round unbroken.
**Overclaim penalty:** −2 per `OVERCLAIM` verdict.
**Calibration penalty:** −0.5 × (dismissed high-confidence findings).

Grade bands: A ≥ 85, B ≥ 75, C ≥ 65, D ≥ 55, F < 55.

---

## 7. Worked Trace — actual run, not illustrative

The trace below is the real output of `purple_loop.py` against `sample_target.md` (the
fictional "NovaPay" fintech) with a 12-round budget. The full log is Appendix B; nothing
in this table is hand-written.

| R | Router chose | Why (routing rationale) | What happened |
|---|---|---|---|
| 1 | RECON | State has no asset inventory | 7 assets, 4 trust boundaries. Three assets — admin console, log/backup pipeline, CI/CD secrets — were **inferred**, not named in the spec |
| 2 | RED *(lane: social)* | Human-layer coverage cells all at 0.0 | F1 support-desk verification, F2 vendor standing access. A third draft was **withheld by self-critique**: reachability not established |
| 3 | BLUE | Two unmitigated findings; defender is behind | M1 (F1) — no detection layer, residual claimed 0.05; M2 (F2) — all three layers |
| 4 | AUDITOR | Mitigations await judgment | F1 → `INSUFFICIENT` (blind if prevention fails); F2 → `CHALLENGE` |
| 5 | RED *(mandate: bypass M2)* | An open CHALLENGE must be answered before scoring | F3 — bypass through M2's stated assumption "no legacy or emergency path bypasses the new control" |
| 6 | BLUE | F1 has an unresolved INSUFFICIENT verdict | M3 (F3); M4 (F1 **v2**, detection added) |
| 7 | AUDITOR | Mitigations await judgment | F2 → `INSUFFICIENT` (its challenge produced a working bypass); F3 → `CHALLENGE`; F1 → `SOUND` |
| 8 | RED *(mandate: bypass M3)* | Open CHALLENGE on F3 | **No finding produced.** RED reports honestly that the v2 control closes the assumption gap |
| 9 | BLUE | F2 rework outstanding | M5 (F2 v2) — regresses, drops the detection layer again |
| 10 | AUDITOR | Mitigations await judgment | F3 → `SOUND`, **durability bonus +3** (survived a challenge unbroken); F2 → `INSUFFICIENT` again |
| 11 | BLUE | F2 still unresolved | M6 (F2 **v3**) — all three layers |
| 12 | AUDITOR | Round budget nearly spent | F2 → `SOUND`, **+3**. Final: **82.6 / 100 (B)** |

Three moments in this trace are impossible in a static pipeline:

- **Round 5** exists only because a verdict sent control *backwards* from judge to attacker.
- **Round 8** is a turn where the attacker produces nothing and that is the correct, scored outcome — the defense earned its durability bonus by surviving, not by being asserted sound.
- **Rounds 9–11** are a defender who regressed and was caught twice by the same rubric. A checklist scorer would have accepted M5.

The engagement did **not** converge: it ran out of budget with `attack_surface_coverage` at
0.30, because the challenge loops consumed the turns that would otherwise have probed the
software-logic lane. That is an honest result, not a failure of the run — see §10.

---

## 8. Mapping to the Technical Expectations

| Requirement | Where it lives |
|-------------|----------------|
| **State Management** | §3 — single JSON blackboard, patch-based writes, append-only history, per-agent read projections, five enforced invariants, context compaction |
| **Reflection & Feedback Loops** | §4 — Loop A intra-agent draft/critique/revise; Loop B six-verdict adversarial cross-critique with `CHALLENGE` re-routing; Loop C convergence + cross-round confidence calibration |
| **Dynamic Routing** | §5 — LLM router over a formally constrained legal-move set, mandate generation, falsifiable routing predictions, novelty-driven lane switching, human escalation |
| **Not static if/else** | Control flow is decided per-turn by two LLM judgments (Auditor verdict, Router decision). Deterministic code only *validates* moves; it never chooses them. |

---

## 9. Files in this Deliverable

| File | Purpose |
|------|---------|
| `01_ARCHITECTURE.md` (this file) | Design document / report |
| `02_AGENT_PROMPTS.md` | Copy-paste system prompts for all six agents (Myskillos-ready) |
| `03_STATE_SCHEMA.json` | Formal JSON-Schema for `EngagementState` |
| `04_SCORING_RUBRIC.md` | The Auditor's full scoring rubric and anti-anchoring checks |
| `purple_loop.py` | Runnable orchestrator — mock mode, live API mode, self-test, package build |
| `myskillos_package/` | The importable agent team: `CLAUDE.md` + `.claude/agents/*.md` (§10) |
| `architecture.png` | The orchestration map reproduced in §0 |
| `sample_target.md` | Example target architecture ("NovaPay", fictional) |
| `sample_run_report.md` | Output of the run traced in §7 |
| `final_state.json` | The complete end-of-engagement state object from that run |

The orchestrator loads its prompts directly from `02_AGENT_PROMPTS.md`, so the document
and the implementation cannot drift apart — if a prompt is renamed or removed, the program
refuses to start.

### How to run

```bash
python purple_loop.py --self-test                       # assert the architectural invariants
python purple_loop.py --target sample_target.md         # full engagement, no API key needed
python purple_loop.py --target sample_target.md --live  # same, driven by real LLM agents
python purple_loop.py --build-package                   # emit the Myskillos-importable team
```

`--self-test` turns every claim in §3.2 into an executable assertion:

```
PASS  invariant 1 — findings are append-only, supersede marks not deletes
PASS  invariant 2 — orphan mitigations rejected
PASS  invariant 3 — Auditor cannot author findings
PASS  invariant 4 — RED output cannot bypass the Safety Guardian
PASS  verdict vocabulary is enforced
PASS  Guardian redacts operational detail
PASS  all six agent prompts load from 02_AGENT_PROMPTS.md
PASS  agents receive projections, not the whole blackboard
PASS  full engagement: budget, legal moves, challenge->durability
PASS  control flow is not a fixed pipeline
10/10 checks passed
```

The last check is the important one for grading: it asserts that the executed agent
sequence is **not** the fixed cycle RECON → RED → BLUE → AUDITOR.

---

## 10. Deploying to Myskillos

Myskillos stores an agent team as **`CLAUDE.md` + `.claude/agents/*.md`** — the same layout
its own published skills use, and the same layout its one-click installer downloads as a
zip. This project ships in exactly that format:

```
myskillos_package/
├── CLAUDE.md                          # orchestration spec: state, loops, routing, run protocol
├── .claude/agents/
│   ├── orchestrator-router.md         # node type: Chief
│   ├── recon-analyst.md               # node type: Sub-agent
│   ├── red-team.md
│   ├── blue-team.md
│   ├── security-auditor.md
│   └── safety-guardian.md
└── references/
    ├── state-schema.json
    ├── scoring-rubric.md
    └── example-target.md
```

Each agent file carries the frontmatter Myskillos and Claude both read:

```yaml
---
name: red-team
description: Attacker. Produces abstract attack hypotheses across two lanes …
tools: Read, Write
node_type: Sub-agent
---
```

The package is **generated**, not hand-maintained:

```bash
python purple_loop.py --build-package
```

It reads the agent bodies out of `02_AGENT_PROMPTS.md`, so the submitted document and the
uploaded skill cannot drift apart — if a prompt is renamed or deleted, the build fails
rather than shipping a silently broken agent.

**Upload path.** Sign in to myskillos.com → *My Repo* → create a project → import the
package (VS Code extension, GitHub import, or the editor's canvas), then wire
`orchestrator-router` as the Chief node with the other five as sub-agents reporting to it.
The Chief's outgoing edges are the four content agents; `red-team`'s outgoing edge must
pass through `safety-guardian` before the state write. That single constraint is what
makes the canvas match §3.2 invariant 4.

---

## 11. Limitations & Honest Notes

- LLM agents are not penetration testers. Scores are **relative** evaluations of an architecture description, not empirical measurements of a live system.
- Adversarial self-critique reduces but does not eliminate agreement bias; the novelty floor and lane switching are mitigations, not proofs.
- The Guardian's abstraction constraint deliberately reduces attack specificity. This trades a small amount of analytical fidelity for a safety property the project treats as non-negotiable.
- Convergence thresholds (0.25 novelty floor, 3.0 score delta) are chosen heuristically and would need tuning against real engagements.
- **The routing policy has a real weakness, visible in §7.** Answering outstanding verdicts is prioritised over exploring untouched coverage, so a run with many challenge loops can exhaust its budget having probed only one lane — the §7 run ended at 0.30 surface coverage. The fix is to make coverage a budgeted claim on turns rather than a fallback, e.g. reserving a fraction of the round budget for exploration. This was left visible rather than tuned away, because a routing policy that can be shown to have a failure mode is more informative than one that has merely never been measured.
- The mock brain is a deterministic stand-in used so the orchestration can be graded without an API key. It exercises the control flow faithfully, but the *security content* it produces is fixed text; only `--live` produces genuine agent reasoning.
