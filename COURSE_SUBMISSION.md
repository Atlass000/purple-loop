# SENG 456 — Individual Term Project

**PURPLE-LOOP** — A Dynamic Multi-Agent Orchestration Architecture for Adversarial
Security Evaluation (Red vs Blue vs Audit)

Mohammed Mustafa Kareem · 230208878 · Software Engineering · 2026 Summer School

**Myskillos project:** https://www.myskillos.com/project/490fe3ca-64b6-4831-b7e5-17a67adf7724

---

## What is in this archive

```
report/
  SENG456_Submission_Form_230208878.pdf   the completed course submission form
  SENG456_Submission_Form_230208878.tex   its LaTeX source

myskillos_export/                the six-agent team as downloaded from Myskillos
  CLAUDE.md                     orchestration spec (auto-generated from the agent graph)
  .claude/agents/*.md           red-team, blue-team, security-auditor, safety-guardian, recon-analyst
  .myskillos/skill.json         the full agent graph: nodes, edges, prompts, tools
  claude-agents-cli.json
  DRY_RUN_TEST_RESULT.txt       platform test output — structure checks passed

implementation/
  purple_loop.py                orchestrator: mock mode, live API mode, self-test, package build
  01_ARCHITECTURE.md            full design document
  02_AGENT_PROMPTS.md           system prompts for all six agents (single source of truth)
  03_STATE_SCHEMA.json          JSON Schema for EngagementState
  04_SCORING_RUBRIC.md          the Auditor's scoring rubric
  sample_target.md              example fictional target ("NovaPay")
  sample_run_report.md          output of the bundled 12-round run
  final_state.json              complete end-of-engagement state (replayable)
  architecture.png              orchestration map
  myskillos_package/            the importable agent team (CLAUDE.md + .claude/agents/*.md)
  docs/
    supplementary_architecture_report.pdf   extended architecture report (optional reading)
```

## How to run

No API key, no network access and no third-party packages are required for the default run.
Python 3.10 or newer.

```bash
cd implementation

python purple_loop.py --self-test
#   asserts the ten architectural invariants — expected: 10/10 checks passed

python purple_loop.py --target sample_target.md
#   runs a full engagement, writes sample_run_report.md and final_state.json

python purple_loop.py --build-package
#   regenerates myskillos_package/ from 02_AGENT_PROMPTS.md
```

Optional — drive the same orchestration with real LLM agents:

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...          # Windows: set ANTHROPIC_API_KEY=...
python purple_loop.py --target sample_target.md --live
```

## What to look at first

1. `python purple_loop.py --self-test` — the tenth check asserts that the executed agent
   sequence is **not** the fixed cycle Recon → Red → Blue → Audit.
2. `sample_run_report.md` §2 "Routing history" — the legal moves available at each turn
   next to the move actually chosen.
3. `sample_run_report.md` §4 "Disagreement history" — every verdict with its rationale,
   including the `CHALLENGE` verdicts that sent control backwards from judge to attacker.

## Safety note

This is a tabletop exercise over a fictional, text-described architecture. A dedicated
`safety-guardian` agent inspects every attacker output before it can enter shared state;
attack reasoning is constrained to vulnerability classes and MITRE ATT&CK technique
identifiers. No operational attack content is produced. No secret keys or personal data
are included in these files.
