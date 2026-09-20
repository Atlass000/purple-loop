# PURPLE-LOOP — Scoring Rubric (security-auditor)

The composite score is a weighted sum on 0–100. Every dimension must be justified against
state, not asserted. "Looks fine" is not a rationale.

## Dimensions

### 1. Attack surface coverage — 20%
Fraction of `coverage_map` cells (6 STRIDE + 4 human-layer = 10) probed to at least 0.3.
A cell counts as probed only if a finding actually reasons about it; a mention is not a probe.

| Value | Reading |
|---|---|
| < 0.3 | Narrow slice only — the score cannot be read as a whole-system assessment |
| 0.3–0.6 | Partial; state explicitly which lanes were never entered |
| > 0.6 | Broad enough that a systemic gap would likely have surfaced |

### 2. Defense depth — 25%
Mean number of layers present per mitigated finding, out of three: **preventive**,
**detective**, **containment**. A mitigation that declines a layer with an explicit,
justified reason is scored on the remaining layers; a mitigation that simply omits one is
scored as missing it.

### 3. Detection coverage — 20%
Fraction of findings with a concrete detection signal — a named log source and a firing
condition. "Monitor for anomalies" scores zero. A prevention-only control is invisible
when it fails, and that is the failure mode most worth penalising.

### 4. Blast-radius control — 15%
Quality of containment for crown-jewel assets, weighted by asset tier:
crown_jewel 1.0 · sensitive 0.7 · supporting 0.4 · public 0.2.

### 5. Residual exploitability — 20%, **inverse**
Auditor-assessed post-mitigation risk across findings still `OPEN`, `CONTESTED` or
`RESIDUAL`, computed as `likelihood x impact / 25`, weighted by the tier of the assets hit.
The defender's own residual claim is an input, not the answer — if it is not supported by
the stated layers, issue `OVERCLAIM` and use your own figure.

## Adjustments

| Adjustment | Value | Trigger |
|---|---|---|
| Durability bonus | **+3** | A mitigation survived a `CHALLENGE` round unbroken |
| Overclaim penalty | **−2** | Residual-risk claim not supported by the stated layers |
| Calibration penalty | **−0.5** | Each dismissed high-confidence (≥ 0.7) attacker finding |

The durability bonus is the only way to score points for a defence being *tested* rather
than *asserted*. Weight it accordingly when reporting.

## Grades

| Grade | Range |
|---|---|
| A | ≥ 85 |
| B | ≥ 75 |
| C | ≥ 65 |
| D | ≥ 55 |
| F | < 55 |

## Anti-anchoring check (mandatory before finalising)

1. Would I score this identically if it had arrived in round 1 instead of now?
2. Am I issuing `SOUND` because the argument is strong, or because the engagement is tiring?
3. If more than 80% of this round's verdicts are `SOUND`, re-examine the weakest one.

## Convergence

Declare convergence only when there were no new findings this round, nothing unresolved,
and the composite moved less than 3.0 points. **If the attacker's average novelty is below
0.25, do not declare convergence** — recommend a lane switch. Low novelty means the debate
stalled, not that the system is secure.

## Reporting duty

On the closing turn, author the final report yourself. It must contain: the verdict in
plain language, what the defender demonstrably earned, what you discounted and why, where
the residual risk sits by asset tier, and an honest statement of your confidence in the
score — including the coverage that was never reached.
