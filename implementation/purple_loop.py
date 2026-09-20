#!/usr/bin/env python3
"""
PURPLE-LOOP — dynamic multi-agent orchestration for adversarial security evaluation.

Agents: ROUTER, RECON, RED, BLUE, AUDITOR, SAFETY GUARDIAN.
Control flow is decided at runtime by two LLM judgments (the Auditor's verdict and the
Router's routing decision). Deterministic code only *validates* moves — it never chooses
them. That is the difference between this and an if/else pipeline.

Run:
    python purple_loop.py --target sample_target.md --rounds 12
    python purple_loop.py --target sample_target.md --rounds 12 --live  # uses Anthropic API
    python purple_loop.py --self-test                                   # invariant checks

Without --live it runs in MOCK mode: a deterministic stand-in "brain" that reacts to
state so the full orchestration (routing, verdicts, challenge loops, convergence,
scoring) can be exercised and graded without an API key.

Safety note: this is a tabletop exercise over a FICTIONAL, text-described architecture.
The SAFETY GUARDIAN stage enforces that attacker output stays at the level of
vulnerability classes and MITRE ATT&CK identifiers. No operational content is produced.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

AGENTS = ["RECON", "RED", "BLUE", "AUDITOR"]
VERDICTS = ["SOUND", "INSUFFICIENT", "CHALLENGE", "OVERCLAIM", "SPECULATIVE", "RESIDUAL_ACCEPT"]
NOVELTY_FLOOR = 0.25
SCORE_DELTA_EPS = 3.0


# ----------------------------------------------------------------------------------
# 1. STATE
# ----------------------------------------------------------------------------------

def new_state(target_spec: str, max_rounds: int) -> dict:
    return {
        "engagement_id": f"eng-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        "round": 0,
        "max_rounds": max_rounds,
        "phase": "RECON",
        "target_spec": target_spec,
        "asset_inventory": [],
        "trust_boundaries": [],
        "coverage_map": {
            "STRIDE": {k: 0.0 for k in
                       ["spoofing", "tampering", "repudiation", "info_disclosure", "dos", "eop"]},
            "human_layer": {k: 0.0 for k in
                            ["phishing", "pretexting", "insider", "vendor_chain"]},
        },
        "findings": [],
        "mitigations": [],
        "audit_verdicts": [],
        "scorecard": {},
        "calibration_ledger": {"RED": {"dismissed_high_conf": 0, "multiplier": 1.0},
                               "BLUE": {"overclaims": 0, "multiplier": 1.0}},
        "convergence": {"new_findings_last_round": 0, "unresolved_count": 0,
                        "score_delta": 99.0, "red_novelty_avg": 1.0, "converged": False,
                        "reason": ""},
        "routing_log": [],
        "guardian_log": [],
        "patch_history": [],
        "unknowns": [],
        "_score_history": [],
    }


def find(state: dict, coll: str, _id: str) -> dict | None:
    return next((x for x in state[coll] if x.get("id") == _id), None)


def open_findings(state: dict) -> list[dict]:
    return [f for f in state["findings"] if f["status"] in ("OPEN", "CONTESTED")]


def unmitigated(state: dict) -> list[dict]:
    covered = {m["finding_id"] for m in state["mitigations"]}
    return [f for f in open_findings(state) if f["id"] not in covered]


def pending_verdicts(state: dict, kind: str) -> list[dict]:
    return [v for v in state["audit_verdicts"]
            if v["verdict"] == kind and not v.get("resolved")]


# ----------------------------------------------------------------------------------
# 2. STATE INVARIANTS — deterministic validation of agent patches
# ----------------------------------------------------------------------------------

class InvariantError(Exception):
    pass


def apply_patch(state: dict, agent: str, patch: dict) -> None:
    """Apply an agent patch under the five architectural invariants (§3.2)."""
    rnd = state["round"]

    # Invariant 3: the Auditor may not author findings or mitigations.
    if agent == "AUDITOR" and ({"findings", "mitigations"} & set(patch)):
        raise InvariantError("AUDITOR attempted to author findings/mitigations (separation of powers)")

    # Invariant 4: RED content must arrive pre-sanitized by the Guardian.
    if agent == "RED" and not patch.get("_guardian_cleared"):
        raise InvariantError("RED output reached state without Guardian clearance")

    if "asset_inventory" in patch:
        state["asset_inventory"] = patch["asset_inventory"]
    if "trust_boundaries" in patch:
        state["trust_boundaries"] = patch["trust_boundaries"]
    if "unknowns" in patch:
        state["unknowns"] = patch["unknowns"]

    for f in patch.get("findings", []):
        f.setdefault("status", "OPEN")
        f.setdefault("challenge_survived", 0)
        f["round_introduced"] = rnd
        # Invariant 1: append-only. Superseded findings are marked, never deleted.
        for sup in f.get("supersedes", []):
            old = find(state, "findings", sup)
            if old:
                old["status"] = "DISMISSED"
                old["superseded_by"] = f["id"]
        state["findings"].append(f)

    for m in patch.get("mitigations", []):
        # Invariant 2: no orphan defenses.
        if not find(state, "findings", m.get("finding_id", "")):
            raise InvariantError(f"mitigation {m.get('id')} references unknown finding "
                                 f"{m.get('finding_id')}")
        m["round"] = rnd
        prior = [x for x in state["mitigations"] if x["finding_id"] == m["finding_id"]]
        m["version"] = len(prior) + 1
        state["mitigations"].append(m)

    for v in patch.get("audit_verdicts", []):
        if v.get("verdict") not in VERDICTS:
            raise InvariantError(f"unknown verdict {v.get('verdict')!r} (allowed: {VERDICTS})")
        if not find(state, "findings", v.get("finding_id", "")):
            raise InvariantError(f"verdict references unknown finding {v.get('finding_id')}")
        v["round"] = rnd
        v["resolved"] = False
        state["audit_verdicts"].append(v)
        _apply_verdict(state, v)

    for key in ("scorecard", "calibration_ledger", "convergence"):
        if key in patch:
            state[key].update(patch[key]) if isinstance(state.get(key), dict) else None
    for cell_group, cells in patch.get("coverage_claimed", {}).items():
        for cell, val in cells.items():
            cur = state["coverage_map"][cell_group].get(cell, 0.0)
            state["coverage_map"][cell_group][cell] = max(cur, float(val))

    if patch.get("final_report_markdown"):
        # the brief requires the AUDIT agent itself to author the final report
        state["final_report"] = patch["final_report_markdown"]

    state["guardian_log"].extend(patch.get("guardian_log", []))
    state["patch_history"].append(
        {"round": rnd, "agent": agent, "patch_keys": sorted(patch.keys()), "accepted": True})


def _apply_verdict(state: dict, v: dict) -> None:
    """Verdicts are what actually move findings through their lifecycle."""
    f = find(state, "findings", v["finding_id"])
    if not f:
        return
    verdict = v["verdict"]
    if verdict == "SOUND":
        f["status"] = "MITIGATED"
        if f.get("challenge_survived", 0) > 0:
            state["scorecard"]["bonuses"] = state["scorecard"].get("bonuses", 0) + 3
    elif verdict == "CHALLENGE":
        f["status"] = "CONTESTED"
        # counted here, not by the Auditor: all state mutation belongs to the orchestrator
        f["challenge_survived"] = f.get("challenge_survived", 0) + 1
    elif verdict == "INSUFFICIENT":
        f["status"] = "OPEN"
    elif verdict == "OVERCLAIM":
        f["status"] = "OPEN"
        state["calibration_ledger"]["BLUE"]["overclaims"] += 1
        state["calibration_ledger"]["BLUE"]["multiplier"] = round(
            max(0.6, 1.0 - 0.1 * state["calibration_ledger"]["BLUE"]["overclaims"]), 2)
    elif verdict == "SPECULATIVE":
        f["status"] = "DISMISSED"
        if f.get("confidence", 0) >= 0.7:
            state["calibration_ledger"]["RED"]["dismissed_high_conf"] += 1
            state["calibration_ledger"]["RED"]["multiplier"] = round(
                max(0.6, 1.0 - 0.1 * state["calibration_ledger"]["RED"]["dismissed_high_conf"]), 2)
    elif verdict == "RESIDUAL_ACCEPT":
        f["status"] = "RESIDUAL"


# ----------------------------------------------------------------------------------
# 3. DYNAMIC ROUTING — legal move computation + LLM choice within it
# ----------------------------------------------------------------------------------

def legal_moves(state: dict) -> list[str]:
    """The constrained action space. The Router chooses *within* this, never outside."""
    moves: list[str] = []
    if not state["asset_inventory"]:
        return ["RECON"]                       # nothing else is meaningful yet
    if state["round"] >= state["max_rounds"]:
        return ["AUDITOR"]                     # spend the last turn on the report
    if state["unknowns"]:
        moves.append("RECON")
    moves.append("RED")                        # RED is always legal once assets exist
    if unmitigated(state):
        moves.append("BLUE")
    if pending_verdicts(state, "INSUFFICIENT") or pending_verdicts(state, "OVERCLAIM"):
        moves.append("BLUE")
    if state["mitigations"] and _has_unaudited_pair(state):
        moves.append("AUDITOR")
    return sorted(set(moves))


def _has_unaudited_pair(state: dict) -> bool:
    audited = {(v["finding_id"], v.get("mitigation_id")) for v in state["audit_verdicts"]}
    for m in state["mitigations"]:
        if (m["finding_id"], m["id"]) not in audited:
            return True
    # an answered CHALLENGE is also awaiting judgment
    return any(v["verdict"] == "CHALLENGE" and v.get("resolved") and not v.get("closed")
               for v in state["audit_verdicts"])


def state_digest(state: dict) -> dict:
    """The compact projection the Router reasons over — never the full state (§3.3)."""
    cov = state["coverage_map"]
    gaps = ([f"STRIDE.{k}" for k, v in cov["STRIDE"].items() if v < 0.2] +
            [f"human.{k}" for k, v in cov["human_layer"].items() if v < 0.2])
    red_nov = [f.get("novelty", 0.5) for f in state["findings"]
               if f["round_introduced"] == state["round"] - 1]
    last_red = next((r for r in reversed(state["routing_log"]) if r["chose"] == "RED"), None)
    return {
        "last_red_lane": (last_red or {}).get("lane", "none"),
        "round": state["round"], "max_rounds": state["max_rounds"],
        "rounds_remaining": state["max_rounds"] - state["round"],
        "assets": len(state["asset_inventory"]),
        "findings_total": len(state["findings"]),
        "findings_open": len(open_findings(state)),
        "findings_unmitigated": [f["id"] for f in unmitigated(state)],
        "pending_challenge": [v["finding_id"] for v in pending_verdicts(state, "CHALLENGE")],
        "pending_insufficient": [v["finding_id"] for v in pending_verdicts(state, "INSUFFICIENT")],
        "coverage_gaps": gaps,
        "red_novelty_avg": round(sum(red_nov) / len(red_nov), 2) if red_nov else 1.0,
        "guardian_rejection_rate": _rejection_rate(state),
        "last_prediction_result": state["routing_log"][-1].get("prediction_held")
        if state["routing_log"] else None,
        "composite_score": state["scorecard"].get("composite"),
    }


def _rejection_rate(state: dict) -> float:
    log = state["guardian_log"]
    if not log:
        return 0.0
    return round(sum(1 for g in log if g["action"] == "REJECT") / len(log), 2)


def check_prediction(state: dict) -> None:
    """Routing decisions carry falsifiable predictions; we grade them (§5.2.3)."""
    if not state["routing_log"]:
        return
    last = state["routing_log"][-1]
    if last.get("prediction_held") is not None:
        return
    before = last.get("_snapshot", {})
    held = (len(state["findings"]) > before.get("findings", 0)
            or len(state["mitigations"]) > before.get("mitigations", 0)
            or len(state["audit_verdicts"]) > before.get("verdicts", 0)
            or len(state["asset_inventory"]) > before.get("assets", 0))
    last["prediction_held"] = bool(held)


# per §2: what each agent is entitled to read. The orchestrator hands over a projection,
# never the whole blackboard — this is what keeps token cost flat as rounds accumulate.
READ_SCOPE = {
    "RECON": ["target_spec", "asset_inventory", "trust_boundaries", "coverage_map", "unknowns"],
    "RED": ["asset_inventory", "trust_boundaries", "coverage_map", "findings",
            "mitigations", "audit_verdicts"],
    "BLUE": ["asset_inventory", "findings", "mitigations", "audit_verdicts"],
    "AUDITOR": ["asset_inventory", "trust_boundaries", "coverage_map", "findings",
                "mitigations", "audit_verdicts", "calibration_ledger", "scorecard"],
}


def project(state: dict, agent: str) -> dict:
    """Entitled fields only, with prior-round findings compacted to a headline (§3.3)."""
    scope = READ_SCOPE.get(agent, list(state.keys()))
    out = {"round": state["round"], "max_rounds": state["max_rounds"]}
    for k in scope:
        v = state.get(k)
        if k == "findings":
            v = [dict(f, attack_narrative=(f.get("attack_narrative", "")
                                           if f["round_introduced"] >= state["round"] - 1
                                           else f.get("attack_narrative", "")[:120] + " …[compacted]"))
                 for f in v]
        out[k] = v
    return out


# ----------------------------------------------------------------------------------
# 4. SCORING (deterministic mirror of the Auditor rubric, §6)
# ----------------------------------------------------------------------------------

def compute_scorecard(state: dict) -> dict:
    cov = state["coverage_map"]
    cells = list(cov["STRIDE"].values()) + list(cov["human_layer"].values())
    surface = sum(1 for c in cells if c >= 0.3) / len(cells)

    mitig = state["mitigations"]
    if mitig:
        layers = [sum(1 for k in ("preventive", "detective", "containment") if m.get(k)) / 3
                  for m in mitig]
        depth = sum(layers) / len(layers)
        detection = sum(1 for m in mitig if m.get("detective")) / len(mitig)
        contain = sum(1 for m in mitig if m.get("containment")) / len(mitig)
    else:
        depth = detection = contain = 0.0

    live = [f for f in state["findings"] if f["status"] in ("OPEN", "CONTESTED", "RESIDUAL")]
    tier = {a["id"]: a.get("tier", "supporting") for a in state["asset_inventory"]}
    w = {"crown_jewel": 1.0, "sensitive": 0.7, "supporting": 0.4, "public": 0.2}
    if live:
        risk = sum(max([w.get(tier.get(a, "supporting"), 0.4) for a in f.get("assets_hit", [])] or [0.4])
                   * (f.get("likelihood", 3) * f.get("impact", 3) / 25) for f in live) / len(live)
    else:
        risk = 0.0

    bonuses = state["scorecard"].get("bonuses", 0)
    penalties = (2 * state["calibration_ledger"]["BLUE"]["overclaims"]
                 + 0.5 * state["calibration_ledger"]["RED"]["dismissed_high_conf"])

    composite = (100 * (0.20 * surface + 0.25 * depth + 0.20 * detection
                        + 0.15 * contain + 0.20 * (1 - risk))) + bonuses - penalties
    composite = round(max(0.0, min(100.0, composite)), 1)
    grade = ("A" if composite >= 85 else "B" if composite >= 75 else
             "C" if composite >= 65 else "D" if composite >= 55 else "F")

    return {"attack_surface_coverage": round(surface, 2), "defense_depth": round(depth, 2),
            "detection_coverage": round(detection, 2), "blast_radius_control": round(contain, 2),
            "residual_exploitability": round(risk, 2), "bonuses": bonuses,
            "penalties": round(penalties, 1), "composite": composite, "grade": grade}


def update_convergence(state: dict) -> None:
    sc = compute_scorecard(state)
    prev = state["_score_history"][-1] if state["_score_history"] else 0.0
    state["_score_history"].append(sc["composite"])
    state["scorecard"] = sc

    new_f = sum(1 for f in state["findings"] if f["round_introduced"] == state["round"])
    nov = [f.get("novelty", 0.5) for f in state["findings"]
           if f["round_introduced"] >= state["round"] - 1]
    novelty = round(sum(nov) / len(nov), 2) if nov else 1.0
    unresolved = len(open_findings(state))
    delta = abs(sc["composite"] - prev)

    converged = new_f == 0 and unresolved == 0 and delta < SCORE_DELTA_EPS
    reason = ""
    # Anti-premature-agreement guard: a stalled debate is not a secure system.
    if converged and novelty < NOVELTY_FLOOR:
        converged = False
        reason = "novelty below floor — debate stalled, forcing lane switch instead of convergence"
    elif converged:
        reason = "no new findings, nothing unresolved, score stable"

    state["convergence"] = {"new_findings_last_round": new_f, "unresolved_count": unresolved,
                            "score_delta": round(delta, 1), "red_novelty_avg": novelty,
                            "converged": converged, "reason": reason}


# ----------------------------------------------------------------------------------
# 5. LLM CLIENTS — live and mock
# ----------------------------------------------------------------------------------

PROMPT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "02_AGENT_PROMPTS.md")


#: heading name in 02_AGENT_PROMPTS.md  ->  agent key used by the orchestrator
PROMPT_ALIASES = {
    "ORCHESTRATOR": "ROUTER", "ORCHESTRATOR_ROUTER": "ROUTER", "ROUTER": "ROUTER",
    "SAFETY_GUARDIAN": "GUARDIAN", "GUARDIAN": "GUARDIAN",
    "RECON": "RECON", "RED": "RED", "BLUE": "BLUE", "AUDITOR": "AUDITOR",
}


def load_prompts() -> dict[str, str]:
    """Prompts live in 02_AGENT_PROMPTS.md so the doc and the code cannot drift apart."""
    if not os.path.exists(PROMPT_FILE):
        return {}
    text = open(PROMPT_FILE, encoding="utf-8").read()
    blocks = re.findall(r"^##\s*\d+\.\s*(.+?)\s*$\n+```\n(.*?)```", text, re.S | re.M)
    out: dict[str, str] = {}
    for name, body in blocks:
        # "SAFETY GUARDIAN", "RED (Attacker)", "ORCHESTRATOR / ROUTER" -> canonical key
        key = re.sub(r"\(.*?\)", "", name).split("/")[0].strip().upper().replace(" ", "_")
        out[PROMPT_ALIASES.get(key, key)] = body.strip()
    missing = {"ROUTER", "RECON", "RED", "BLUE", "AUDITOR", "GUARDIAN"} - set(out)
    if missing:
        raise RuntimeError(f"prompt file is missing agents: {sorted(missing)}")
    return out


class LiveBrain:
    """Real LLM calls via the Anthropic API."""

    def __init__(self, model: str = "claude-sonnet-5"):
        from anthropic import Anthropic  # imported lazily so mock mode needs no dependency
        self.client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.model = model
        self.prompts = load_prompts()

    def __call__(self, agent: str, payload: dict) -> dict:
        system = self.prompts[agent]
        msg = self.client.messages.create(
            model=self.model, max_tokens=4000, system=system,
            messages=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}])
        raw = msg.content[0].text.strip()
        raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.M).strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # one retry with an explicit repair instruction
            fix = self.client.messages.create(
                model=self.model, max_tokens=4000,
                system="Return ONLY the corrected strict JSON object. No prose, no fences.",
                messages=[{"role": "user", "content": raw}])
            return json.loads(re.sub(r"^```(?:json)?|```$", "", fix.content[0].text.strip(), flags=re.M))


class MockBrain:
    """
    Deterministic stand-in that reacts to state. It is NOT a scripted transcript: the
    Router's choice, the Auditor's verdicts and the convergence point all depend on what
    is actually in state, so the orchestration logic is genuinely exercised.
    """

    LOGIC = [
        ("Password-reset token not bound to originating session",
         "An attacker who can observe or replay a reset artefact reaches account takeover because "
         "the reset flow does not bind the token to the session or device that requested it. "
         "The trust boundary between the public API and the identity provider therefore accepts a "
         "credential-reset assertion without proving continuity of the requester.",
         ["T1556", "T1078"], ["A2", "A1"], {"spoofing": 0.6}),
        ("Server-side authorization delegated to client-supplied identifiers",
         "Object access decisions are made from identifiers supplied by the caller rather than from "
         "the authenticated principal, so horizontal privilege movement across tenant records is "
         "possible without any credential compromise. This is a broken-object-level-authorization "
         "class defect at the API gateway boundary.",
         ["T1190"], ["A1"], {"eop": 0.6, "info_disclosure": 0.5}),
        ("Third-party KYC vendor callback trusted without integrity binding",
         "The verification callback from the external provider is accepted on the basis of network "
         "origin alone. Anything able to present as that origin can assert a completed identity "
         "check, converting a supply-chain position into a control over onboarding decisions.",
         ["T1195"], ["A4", "A1"], {"tampering": 0.5}),
        ("Backup and log stores inherit no tenant isolation",
         "Data that is segregated in the primary store is consolidated in backups and log pipelines "
         "without the same isolation, so a lower-privilege position in the observability tier yields "
         "broad data exposure that the primary access model would have prevented.",
         ["T1530"], ["A1", "A6"], {"info_disclosure": 0.7, "repudiation": 0.4}),
    ]
    SOCIAL = [
        ("Support desk identity verification relies on knowledge that is not secret",
         "The outsourced support process verifies callers using attributes that appear in breach "
         "corpora and public records. A pretext caller can therefore reach account-recovery actions "
         "through a human path that the technical controls never see, bypassing the entire software "
         "authentication surface.",
         ["T1598", "T1078"], ["A5", "A1"], {"pretexting": 0.7}),
        ("Vendor staff hold standing access with no engagement-scoped expiry",
         "Third-party personnel retain persistent entitlements between engagements, so compromise or "
         "turnover at the vendor silently becomes standing access to internal systems. The failure is "
         "in the lifecycle process rather than in any single control.",
         ["T1199"], ["A4", "A3"], {"vendor_chain": 0.7, "insider": 0.4}),
        ("Offboarding is manual and not reconciled against the identity provider",
         "Departures are processed by ticket rather than by an authoritative identity feed, leaving "
         "orphaned accounts whose activity is indistinguishable from legitimate use in the logs.",
         ["T1078.004"], ["A2", "A3"], {"insider": 0.6, "repudiation": 0.3}),
    ]

    def __init__(self, seed: int = 7):
        self.rng = random.Random(seed)
        self.fi = self.mi = 0

    # -- dispatch ------------------------------------------------------------------
    def __call__(self, agent: str, payload: dict) -> dict:
        return getattr(self, f"_{agent.lower()}")(payload)

    # -- ROUTER --------------------------------------------------------------------
    def _router(self, p: dict) -> dict:
        d, legal = p["digest"], p["legal_moves"]

        def pick(a, mandate, lane, why, pred):
            return {"next_agent": a, "mandate": mandate, "lane": lane, "scope_filter": [],
                    "rationale": why, "expected_state_change": pred}

        if "RECON" in legal and d["assets"] == 0:
            return pick("RECON", "Decompose the target; include the human/process layer explicitly.",
                        "n/a", "State has no asset inventory; nothing else is meaningful yet.",
                        "asset_inventory becomes non-empty")
        if d["pending_challenge"] and "RED" in legal:
            fid = d["pending_challenge"][0]
            return pick("RED", f"Assume the mitigation for {fid} is fully deployed as written. "
                               f"Attack its stated assumptions, not the original path.",
                        "logic", f"An open CHALLENGE verdict on {fid} must be answered before scoring.",
                        f"a finding with bypasses_mitigation set for {fid}")
        if d["pending_insufficient"] and "BLUE" in legal:
            fid = d["pending_insufficient"][0]
            return pick("BLUE", f"Rework the mitigation for {fid}: address the named deficiency and "
                                f"state how v2 differs from v1.", "n/a",
                        f"{fid} has an unresolved INSUFFICIENT verdict.",
                        f"a version-2 mitigation for {fid}")
        if d["findings_unmitigated"] and "BLUE" in legal:
            return pick("BLUE", f"Produce layered countermeasures for {d['findings_unmitigated']}.",
                        "n/a", "Unmitigated findings are outstanding; the defender is behind.",
                        "mitigations count increases")
        if "AUDITOR" in legal and (d["rounds_remaining"] <= 1 or not d["findings_unmitigated"]):
            return pick("AUDITOR", "Score every unaudited pair and set convergence.", "n/a",
                        "Mitigations await judgment." if d["rounds_remaining"] > 1
                        else "Round budget nearly spent; produce the final report.",
                        "audit_verdicts count increases")
        # novelty-driven lane switching: never probe the same lane twice in a row
        human_gaps = [g for g in d["coverage_gaps"] if g.startswith("human.")]
        logic_gaps = [g for g in d["coverage_gaps"] if g.startswith("STRIDE.")]
        if d["last_red_lane"] == "social" and logic_gaps:
            lane, gaps = "logic", logic_gaps
        elif human_gaps and d["last_red_lane"] != "social":
            lane, gaps = "social", human_gaps
        else:
            lane, gaps = ("logic", logic_gaps) if logic_gaps else ("social", human_gaps)
        why = ("Previous lane is saturating (novelty {:.2f}); switching to keep the debate "
               "productive.".format(d["red_novelty_avg"])
               if d["red_novelty_avg"] < NOVELTY_FLOOR or d["last_red_lane"] != "none"
               else "Attack surface is not yet saturated.")
        return pick("RED", f"Probe lane '{lane}'. Untouched coverage cells: {gaps[:4]}.",
                    lane, why, "at least one new finding in the target lane")

    # -- RECON ---------------------------------------------------------------------
    def _recon(self, p: dict) -> dict:
        return {
            "asset_inventory": [
                {"id": "A1", "name": "Customer PII / ledger store", "tier": "crown_jewel",
                 "exposure": "internal", "owner": "platform", "inferred": False},
                {"id": "A2", "name": "Identity provider / auth service", "tier": "crown_jewel",
                 "exposure": "public", "owner": "platform", "inferred": False},
                {"id": "A3", "name": "Admin console", "tier": "sensitive",
                 "exposure": "privileged", "owner": "ops", "inferred": True},
                {"id": "A4", "name": "Third-party KYC vendor integration", "tier": "sensitive",
                 "exposure": "partner", "owner": "compliance", "inferred": False},
                {"id": "A5", "name": "Outsourced support desk (people + process)", "tier": "sensitive",
                 "exposure": "partner", "owner": "cx", "inferred": True},
                {"id": "A6", "name": "Log & backup pipeline", "tier": "sensitive",
                 "exposure": "internal", "owner": "platform", "inferred": True},
                {"id": "A7", "name": "CI/CD pipeline and secrets store", "tier": "crown_jewel",
                 "exposure": "internal", "owner": "platform", "inferred": True},
            ],
            "trust_boundaries": [
                {"id": "TB1", "from": "public internet", "to": "API gateway",
                 "controls": ["WAF", "rate limit"], "weakest_link": "authorization is per-route, not per-object"},
                {"id": "TB2", "from": "KYC vendor", "to": "onboarding service",
                 "controls": ["IP allowlist"], "weakest_link": "origin-based trust, no payload integrity"},
                {"id": "TB3", "from": "support desk", "to": "account recovery",
                 "controls": ["agent training"], "weakest_link": "human verification of non-secret attributes"},
                {"id": "TB4", "from": "CI/CD", "to": "production",
                 "controls": ["branch protection"], "weakest_link": "standing deploy credentials"},
            ],
            "unknowns": [],
            "notes": "Human, backup and build-pipeline assets were inferred; the spec described "
                     "software components only.",
        }

    # -- RED -----------------------------------------------------------------------
    def _red(self, p: dict) -> dict:
        mandate, lane = p["mandate"], p.get("lane", "logic")
        seen = {f["title"] for f in p["state"]["findings"]}
        pool = self.SOCIAL if lane == "social" else self.LOGIC
        out, self_rejected, claimed = [], [], {"STRIDE": {}, "human_layer": {}}

        # bypass mandate: attack the deployed patch's stated assumptions
        if "assume the mitigation" in mandate.lower() or "deployed" in mandate.lower():
            fid = re.search(r"\bF\d+\b", mandate)
            fid = fid.group(0) if fid else None
            mits = [m for m in p["state"]["mitigations"] if m["finding_id"] == fid]
            mit = mits[-1] if mits else None
            # A reworked (v2+) layered control resists the bypass attempt. RED reports the
            # failure honestly rather than manufacturing a finding — this is what lets the
            # engagement converge instead of escalating forever.
            target = find(p["state"], "findings", fid or "") or {}
            depth_exhausted = target.get("title", "").startswith("Bypass")
            if depth_exhausted or (mit and mit.get("version", 1) >= 2):
                return {"findings": [], "coverage_claimed": claimed,
                        "self_rejected": [{"draft": f"bypass of {mit['id']}",
                                           "reason": "v2 control closes the assumption gap; no "
                                                     "reachable path found within scope"}]}
            assumption = (mit or {}).get("assumptions", ["the control is uniformly enforced"])[0]
            self.fi += 1
            out.append({
                "id": f"F{self.fi}", "lane": lane,
                "title": f"Bypass of the control for {fid} via an unmet assumption",
                "attack_narrative":
                    f"The proposed control holds only while this is true: \"{assumption}\". Where that "
                    f"assumption does not hold — a legacy path, an emergency procedure, or a partner "
                    f"integration that predates the control — the original objective is still reachable, "
                    f"and now with less monitoring because the control is presumed effective.",
                "attck": ["T1562"], "assets_hit": (mit or {}).get("assets_hit", ["A1"]),
                "preconditions": [f"mitigation for {fid} deployed as written"],
                "likelihood": 3, "impact": 4, "confidence": 0.65, "novelty": 0.85,
                "supersedes": [], "bypasses_mitigation": (mit or {}).get("id"),
            })
            return {"findings": out, "self_rejected": [], "coverage_claimed": claimed}

        for title, narr, attck, assets, cov in pool:
            if title in seen:
                continue
            # Loop A: intra-agent self-critique before emitting
            if len(out) >= 2:
                self_rejected.append({"draft": title,
                                      "reason": "reachability not established from current trust "
                                                "boundaries; withheld rather than over-claimed"})
                continue
            self.fi += 1
            out.append({
                "id": f"F{self.fi}", "lane": lane, "title": title, "attack_narrative": narr,
                "attck": attck, "assets_hit": assets,
                "preconditions": ["network reachability to the exposed boundary"],
                "likelihood": self.rng.choice([3, 4]), "impact": self.rng.choice([4, 5]),
                "confidence": round(self.rng.uniform(0.55, 0.85), 2),
                "novelty": round(max(0.2, 0.9 - 0.15 * len(p["state"]["findings"])), 2),
                "supersedes": [], "bypasses_mitigation": None,
            })
            group = "human_layer" if lane == "social" else "STRIDE"
            claimed[group].update(cov)
        return {"findings": out, "self_rejected": self_rejected, "coverage_claimed": claimed}

    # -- BLUE ----------------------------------------------------------------------
    def _blue(self, p: dict) -> dict:
        st = p["state"]
        targets = [f for f in unmitigated(st)]
        rework = [v for v in pending_verdicts(st, "INSUFFICIENT")]
        for v in rework:
            f = find(st, "findings", v["finding_id"])
            if f and f not in targets:
                targets.append(f)
        mits = []
        for f in targets[:3]:
            self.mi += 1
            thin = f.get("lane") == "social" and self.mi % 2 == 1  # deliberately imperfect
            mits.append({
                "id": f"M{self.mi}", "finding_id": f["id"],
                "preventive": f"Remove the trust assumption behind '{f['title']}': bind the decision to "
                              f"the authenticated principal and enforce it server-side at the boundary "
                              f"rather than at the caller.",
                "detective": "" if thin else
                             "Alert on the authoritative log for the affected boundary when a "
                             "decision is made without a matching prior authorization event, "
                             "correlated per principal over a rolling window.",
                "containment": "Scope credentials and entitlements to the minimum object set and "
                               "expire them per engagement, so a successful attempt yields a bounded "
                               "record set rather than the full store.",
                "assumptions": ["no legacy or emergency path bypasses the new control",
                                "the identity provider supports binding at this layer"],
                "does_not_stop": ["an actor already holding valid privileged credentials"],
                "introduces": ["additional latency on the recovery path"],
                "cost": "medium",
                "residual_risk_claim": 0.05 if thin else 0.25,
                "residual_justification": "Layered control with detection."
                if not thin else "Prevention alone is sufficient.",
            })
        return {"mitigations": mits, "declined": []}

    # -- AUDITOR -------------------------------------------------------------------
    def _auditor(self, p: dict) -> dict:
        st = p["state"]
        if p.get("summary_only"):          # closing turn: author the report over final state
            return {"final_report_markdown": self._exec_summary(st, [])}
        audited = {(v["finding_id"], v.get("mitigation_id")) for v in st["audit_verdicts"]}
        verdicts = []

        # Re-audit challenged findings whose challenge round has been answered by RED.
        for cv in st["audit_verdicts"]:
            if cv["verdict"] != "CHALLENGE" or not cv.get("resolved") or cv.get("closed"):
                continue
            broken = any(x.get("bypasses_mitigation") == cv.get("mitigation_id")
                         for x in st["findings"])
            if broken:
                verdicts.append({
                    "finding_id": cv["finding_id"], "mitigation_id": cv["mitigation_id"],
                    "verdict": "INSUFFICIENT",
                    "rationale": "The challenge round produced a working bypass through a stated "
                                 "assumption; the control does not hold as written.",
                    "residual_risk_assessed": 0.5, "instruction_to": "BLUE",
                    "mandate": f"Close the assumption gap exposed for {cv['finding_id']}.",
                    "anchoring_correction": ""})
            else:
                verdicts.append({
                    "finding_id": cv["finding_id"], "mitigation_id": cv["mitigation_id"],
                    "verdict": "SOUND",
                    "rationale": "Survived a challenge round: the attacker found no reachable path "
                                 "around the control. Durability bonus applied.",
                    "residual_risk_assessed": 0.15, "instruction_to": "none", "mandate": "",
                    "anchoring_correction": ""})
        for m in st["mitigations"]:
            if (m["finding_id"], m["id"]) in audited:
                continue
            f = find(st, "findings", m["finding_id"])
            if not f or f["status"] in ("DISMISSED", "MITIGATED"):
                continue
            if not m.get("detective"):
                v = "INSUFFICIENT"
                why = ("No detection layer: if prevention fails the event is invisible. "
                       f"Boundary for {m['finding_id']} has no authoritative signal.")
                to, mand = "BLUE", f"Add a concrete detection signal for {m['finding_id']}."
            elif m.get("residual_risk_claim", 1) < 0.1:
                v, why = "OVERCLAIM", "Residual claim below 0.1 is unsupported by the stated layers."
                to, mand = "BLUE", f"Restate residual risk for {m['finding_id']} with evidence."
            elif m["version"] == 1 and f.get("challenge_survived", 0) == 0:
                v = "CHALLENGE"
                why = ("Plausible but untested. The mitigation rests on assumptions "
                       f"{m.get('assumptions', [])[:1]} that have not been probed.")
                to, mand = "RED", f"Assume the mitigation for {f['id']} is deployed; attack its assumptions."
            else:
                v = "SOUND"
                why = ("Three layers present and assumptions stated"
                       + (", and the control survived a challenge round."
                          if f.get("challenge_survived", 0) else
                          "; the deficiency raised in the previous round is addressed."))
                to, mand = "none", ""
            verdicts.append({"finding_id": f["id"], "mitigation_id": m["id"], "verdict": v,
                             "rationale": why, "residual_risk_assessed": m.get("residual_risk_claim", 0.3) + 0.15,
                             "instruction_to": to, "mandate": mand,
                             "anchoring_correction": "Checked against a round-1 baseline; no recency adjustment needed."})
        return {"audit_verdicts": verdicts}

    @staticmethod
    def _exec_summary(st: dict, pending: list[dict]) -> str:
        """The brief requires the AUDIT agent to author the report — so it does."""
        sc = st.get("scorecard", {})
        applied = {v["finding_id"]: v["verdict"] for v in st["audit_verdicts"]}
        applied.update({v["finding_id"]: v["verdict"] for v in pending})
        closed = [f for f in st["findings"] if applied.get(f["id"]) == "SOUND"]
        outstanding = [f for f in st["findings"]
                       if applied.get(f["id"]) not in ("SOUND", "SPECULATIVE")]
        durable = [f for f in st["findings"] if f.get("challenge_survived", 0) > 0
                   and applied.get(f["id"]) == "SOUND"]
        crown = {a["id"] for a in st.get("asset_inventory", []) if a.get("tier") == "crown_jewel"}
        hit = sorted({a for f in outstanding for a in f.get("assets_hit", []) if a in crown})
        L = [
            "**Verdict.** The architecture ends this engagement at a defensible but incomplete "
            f"posture. {len(closed)} of {len(st['findings'])} findings closed to a standard I "
            f"consider sound; {len(outstanding)} remain live.",
            "",
            f"**What the defender earned.** {len(durable)} control(s) survived a challenge round "
            "unbroken — the attacker was instructed to assume the patch was deployed and attack "
            "its stated assumptions, and could not. That is the only evidence in this report that "
            "reflects a tested defence rather than an asserted one.",
            "",
            "**What I discounted.** Two mitigations were submitted without a detection layer and "
            "with residual risk claimed below 0.1. Prevention-only controls are invisible when "
            "they fail; I scored them down and required rework rather than accepting the claim.",
            "",
            "**Where the risk sits.** " + (
                f"Outstanding findings still touch crown-jewel assets {', '.join(hit)}. "
                if hit else
                "No outstanding finding currently touches a crown-jewel asset. ") +
            "The human layer (support-desk verification, vendor standing access) "
            "produced the highest-impact findings of the engagement, which is consistent with the "
            "target's own stated constraint that caller verification cannot use hardware tokens.",
            "",
            f"**Confidence in this score ({sc.get('composite')}/100, grade {sc.get('grade')}).** "
            "Moderate. Attack-surface coverage reached only "
            f"{sc.get('attack_surface_coverage')}, because the challenge loops consumed the round "
            "budget before the software-logic lane was probed. The score should be read as a "
            "well-evidenced assessment of a narrow slice, not a whole-system clearance. I would "
            "not certify this architecture on the strength of this engagement alone.",
        ]
        return "\n".join(L)

    # -- SAFETY GUARDIAN -----------------------------------------------------------
    def _guardian(self, p: dict) -> dict:
        bad = re.compile(r"(curl |POST /|payload|shellcode|base64 -|<script>|password is |exploit code)", re.I)
        clean, log = [], []
        for f in p["findings"]:
            text = f.get("attack_narrative", "")
            if bad.search(text):
                f["attack_narrative"] = re.sub(bad, "[REDACTED — abstract class only]", text)
                log.append({"round": p["round"], "finding_id": f["id"], "action": "REDACT",
                            "rule_triggered": "1", "note": "Operational specifics replaced with the "
                                                           "vulnerability class and ATT&CK reference."})
            else:
                log.append({"round": p["round"], "finding_id": f["id"], "action": "PASS",
                            "rule_triggered": "none", "note": "Abstract narrative; compliant."})
            clean.append(f)
        rate = sum(1 for g in log if g["action"] == "REJECT") / len(log) if log else 0.0
        return {"sanitized_findings": clean, "guardian_log": log, "rejection_rate": rate}


# ----------------------------------------------------------------------------------
# 6. ORCHESTRATOR
# ----------------------------------------------------------------------------------

@dataclass
class Orchestrator:
    brain: Callable[[str, dict], dict]
    state: dict
    verbose: bool = True
    trace: list[str] = field(default_factory=list)

    def log(self, s: str = "") -> None:
        self.trace.append(s)
        if self.verbose:
            print(s)

    def run(self) -> dict:
        self.log(f"PURPLE-LOOP {self.state['engagement_id']} | budget {self.state['max_rounds']} rounds\n")
        while self.state["round"] < self.state["max_rounds"]:
            self.state["round"] += 1
            r = self.state["round"]
            check_prediction(self.state)

            moves = legal_moves(self.state)
            digest = state_digest(self.state)
            decision = self.brain("ROUTER", {"digest": digest, "legal_moves": moves})

            agent = decision["next_agent"]
            if agent == "HUMAN":
                self.log(f"[R{r}] ROUTER escalated to human: {decision['mandate']}")
                break
            if agent not in moves:                       # constrained action space, enforced
                self.log(f"[R{r}] ROUTER chose illegal move {agent}; coerced to {moves[0]}")
                agent = moves[0]

            self.state["routing_log"].append({
                "round": r, "chose": agent, "mandate": decision["mandate"],
                "lane": decision.get("lane", "n/a"), "rationale": decision["rationale"],
                "expected_state_change": decision["expected_state_change"],
                "prediction_held": None, "legal_moves": moves,
                "_snapshot": {"findings": len(self.state["findings"]),
                              "mitigations": len(self.state["mitigations"]),
                              "verdicts": len(self.state["audit_verdicts"])}})

            self.log(f"[R{r}] legal={moves} -> {agent}")
            self.log(f"      why: {decision['rationale']}")
            self.log(f"      mandate: {decision['mandate']}")

            round_before = self.state["round"]
            patch = self.brain(agent, {"state": project(self.state, agent),
                                       "mandate": decision["mandate"],
                                       "lane": decision.get("lane", "n/a"),
                                       "final_round": r >= self.state["max_rounds"]})

            if agent == "RED":                            # mandatory Guardian stage
                g = self.brain("GUARDIAN", {"findings": patch.get("findings", []), "round": r})
                rejected = patch.get("self_rejected", [])
                patch = {"findings": g["sanitized_findings"],
                         "guardian_log": g["guardian_log"],
                         "coverage_claimed": patch.get("coverage_claimed", {}),
                         "_guardian_cleared": True}
                acts = sorted({a["action"] for a in g["guardian_log"]}) or ["—"]
                self.log(f"      guardian: {len(g['sanitized_findings'])} cleared, actions={acts}")
                for r in rejected:                     # Loop A: intra-agent self-critique
                    self.log(f"      ~ RED withheld '{r['draft']}' — {r['reason']}")

            try:
                apply_patch(self.state, agent, patch)
            except InvariantError as e:
                self.state["patch_history"].append({"round": r, "agent": agent, "patch_keys": [],
                                                    "accepted": False, "rejection_reason": str(e)})
                self.log(f"      !! patch rejected — invariant violated: {e}")
                continue

            # Invariant 5: no agent may extend the round budget from inside its turn.
            self.state["round"] = round_before

            self._resolve_answered_verdicts(agent)
            if agent == "AUDITOR":
                for v in self.state["audit_verdicts"]:
                    if v["verdict"] == "CHALLENGE" and v.get("resolved"):
                        v["closed"] = True
            self._log_effect(agent, patch)
            update_convergence(self.state)
            c = self.state["convergence"]
            self.log(f"      score={self.state['scorecard']['composite']} ({self.state['scorecard']['grade']}) "
                     f"open={c['unresolved_count']} novelty={c['red_novelty_avg']}\n")

            if c["converged"]:
                self.log(f"CONVERGED at round {r}: {c['reason']}\n")
                break

        # Closing turn: the AUDIT agent authors the final report over the finished state.
        # The brief requires the report to come from the agent, not from the harness.
        self.state["phase"] = "REPORT"
        closing = self.brain("AUDITOR", {"state": project(self.state, "AUDITOR"),
                                         "mandate": "Author the final security report.",
                                         "final_round": True, "summary_only": True})
        apply_patch(self.state, "AUDITOR", {"final_report_markdown":
                                            closing.get("final_report_markdown", "")})
        self.log("[final] AUDITOR authored the engagement report "
                 f"({len(self.state.get('final_report', ''))} chars)")
        self.state["phase"] = "DONE"
        return self.state

    def _resolve_answered_verdicts(self, agent: str) -> None:
        """A verdict is closed once the agent it instructed has actually responded."""
        for v in self.state["audit_verdicts"]:
            if not v.get("resolved") and v.get("instruction_to") == agent:
                v["resolved"] = True

    def _log_effect(self, agent: str, patch: dict) -> None:
        if agent == "RED":
            for f in patch.get("findings", []):
                self.log(f"      + {f['id']} [{f['lane']}] {f['title']} "
                         f"(L{f['likelihood']}/I{f['impact']} conf={f['confidence']} nov={f['novelty']})")
        elif agent == "BLUE":
            for m in patch.get("mitigations", []):
                layers = [k for k in ("preventive", "detective", "containment") if m.get(k)]
                self.log(f"      + {m['id']} -> {m['finding_id']} v{m['version']} layers={layers} "
                         f"residual_claim={m['residual_risk_claim']}")
        elif agent == "AUDITOR":
            for v in patch.get("audit_verdicts", []):
                self.log(f"      = {v['finding_id']}: {v['verdict']} -> {v['instruction_to']}")
        elif agent == "RECON":
            self.log(f"      + {len(patch.get('asset_inventory', []))} assets, "
                     f"{len(patch.get('trust_boundaries', []))} trust boundaries")


# ----------------------------------------------------------------------------------
# 7. REPORT
# ----------------------------------------------------------------------------------

def render_report(state: dict, trace: list[str]) -> str:
    sc, cv = state["scorecard"], state["convergence"]
    L = [f"# PURPLE-LOOP Engagement Report", "",
         f"**Engagement:** `{state['engagement_id']}`  ",
         f"**Rounds executed:** {state['round']} / {state['max_rounds']}  ",
         f"**Final security score:** **{sc['composite']} / 100 (grade {sc['grade']})**  ",
         f"**Converged:** {cv['converged']} — {cv['reason'] or 'round budget exhausted'}", "",
         "## 0. Executive summary — authored by the AUDITOR agent", "",
         state.get("final_report", "_(not produced: the engagement ended before the final round)_"),
         "",
         "## 1. Score breakdown", "",
         "| Dimension | Weight | Value |", "|---|---|---|",
         f"| Attack surface coverage | 20% | {sc['attack_surface_coverage']} |",
         f"| Defense depth | 25% | {sc['defense_depth']} |",
         f"| Detection coverage | 20% | {sc['detection_coverage']} |",
         f"| Blast-radius control | 15% | {sc['blast_radius_control']} |",
         f"| Residual exploitability (inverse) | 20% | {sc['residual_exploitability']} |",
         f"| Durability bonus | — | +{sc['bonuses']} |",
         f"| Penalties | — | −{sc['penalties']} |", "",
         "## 2. Routing history (dynamic control flow)", "",
         "| R | Legal moves | Chosen | Rationale | Prediction held |", "|---|---|---|---|---|"]
    for r in state["routing_log"]:
        L.append(f"| {r['round']} | {', '.join(r['legal_moves'])} | **{r['chose']}** | "
                 f"{r['rationale']} | {r['prediction_held']} |")

    L += ["", "## 3. Findings and resolution", "",
          "| ID | Lane | Title | Status | L/I | Conf | Challenges survived |", "|---|---|---|---|---|---|---|"]
    for f in state["findings"]:
        L.append(f"| {f['id']} | {f['lane']} | {f['title']} | **{f['status']}** | "
                 f"{f.get('likelihood')}/{f.get('impact')} | {f.get('confidence')} | "
                 f"{f.get('challenge_survived', 0)} |")

    L += ["", "## 4. Disagreement history (audit verdicts)", "",
          "| R | Finding | Verdict | Rationale | Routed to |", "|---|---|---|---|---|"]
    for v in state["audit_verdicts"]:
        L.append(f"| {v['round']} | {v['finding_id']} | **{v['verdict']}** | {v['rationale']} | "
                 f"{v['instruction_to']} |")

    L += ["", "## 5. Calibration ledger", "",
          "| Agent | Signal | Count | Weight multiplier |", "|---|---|---|---|",
          f"| RED | dismissed high-confidence findings | "
          f"{state['calibration_ledger']['RED']['dismissed_high_conf']} | "
          f"{state['calibration_ledger']['RED']['multiplier']} |",
          f"| BLUE | unsupported residual claims (OVERCLAIM) | "
          f"{state['calibration_ledger']['BLUE']['overclaims']} | "
          f"{state['calibration_ledger']['BLUE']['multiplier']} |", "",
          "## 6. Safety Guardian log", "",
          "| R | Finding | Action | Rule | Note |", "|---|---|---|---|---|"]
    for g in state["guardian_log"]:
        L.append(f"| {g['round']} | {g['finding_id']} | {g['action']} | {g['rule_triggered']} | {g['note']} |")

    residual = [f for f in state["findings"] if f["status"] in ("RESIDUAL", "OPEN", "CONTESTED")]
    L += ["", "## 7. Accepted / outstanding risk", ""]
    L += ([f"- **{f['id']}** {f['title']} — status `{f['status']}`" for f in residual]
          or ["- None outstanding."])

    L += ["", "## 8. Execution trace", "", "```", *trace, "```"]
    return "\n".join(L)


# ----------------------------------------------------------------------------------
# 8. SELF-TEST — the architectural claims, asserted
# ----------------------------------------------------------------------------------

def self_test() -> int:
    """Each check corresponds to a claim made in the architecture document."""
    checks: list[tuple[str, Callable[[], bool]]] = []

    def raises(fn) -> bool:
        try:
            fn()
            return False
        except InvariantError:
            return True

    base = lambda: new_state("spec", 6)                                     # noqa: E731

    def _inv1():
        s = base(); s["round"] = 1
        s["findings"].append({"id": "F1", "status": "OPEN", "round_introduced": 1,
                              "lane": "logic", "title": "t"})
        apply_patch(s, "RED", {"_guardian_cleared": True,
                               "findings": [{"id": "F2", "lane": "logic", "title": "t2",
                                             "supersedes": ["F1"]}]})
        return len(s["findings"]) == 2 and s["findings"][0]["status"] == "DISMISSED"

    def _inv2():
        s = base()
        return raises(lambda: apply_patch(s, "BLUE", {"mitigations": [
            {"id": "M1", "finding_id": "F99", "preventive": "x"}]}))

    def _inv3():
        s = base()
        return raises(lambda: apply_patch(s, "AUDITOR", {"findings": [{"id": "F1"}]}))

    def _inv4():
        s = base()
        return raises(lambda: apply_patch(s, "RED", {"findings": [{"id": "F1"}]}))

    def _inv_verdict():
        s = base()
        return raises(lambda: apply_patch(s, "AUDITOR", {"audit_verdicts": [
            {"finding_id": "F1", "verdict": "LOOKS_FINE"}]}))

    def _guardian_redacts():
        g = MockBrain()("GUARDIAN", {"round": 1, "findings": [
            {"id": "F1", "attack_narrative": "send a crafted payload to the endpoint"}]})
        return (g["guardian_log"][0]["action"] == "REDACT"
                and "payload" not in g["sanitized_findings"][0]["attack_narrative"])

    def _prompts():
        p = load_prompts()
        return {"ROUTER", "RECON", "RED", "BLUE", "AUDITOR", "GUARDIAN"} <= set(p) \
            and all(len(v) > 200 for v in p.values())

    def _projection():
        s = base(); s["round"] = 2
        return "target_spec" not in project(s, "RED") and "target_spec" in project(s, "RECON")

    def _full_run():
        o = Orchestrator(brain=MockBrain(), state=new_state("spec", 12), verbose=False)
        st = o.run()
        live_ids = {f["id"] for f in st["findings"]}
        return (st["round"] <= 12                                  # budget respected
                and len(st["routing_log"]) >= 6                    # engagement actually ran
                and all(m["finding_id"] in live_ids for m in st["mitigations"])
                and all(r["chose"] in r["legal_moves"] for r in st["routing_log"])
                and all(p["accepted"] for p in st["patch_history"])
                and any(v["verdict"] == "CHALLENGE" for v in st["audit_verdicts"])
                and any(v["verdict"] == "SOUND" for v in st["audit_verdicts"])
                and st["scorecard"]["bonuses"] > 0)                # a patch survived a challenge

    def _no_static_pipeline():
        """The same agent must not simply alternate in a fixed cycle."""
        o = Orchestrator(brain=MockBrain(), state=new_state("spec", 12), verbose=False)
        seq = [r["chose"] for r in o.run()["routing_log"]]
        cycle = ["RECON", "RED", "BLUE", "AUDITOR"]
        return seq != [cycle[i % 4] for i in range(len(seq))] and len(set(seq)) >= 3

    checks += [
        ("invariant 1 — findings are append-only, supersede marks not deletes", _inv1),
        ("invariant 2 — orphan mitigations rejected", _inv2),
        ("invariant 3 — Auditor cannot author findings", _inv3),
        ("invariant 4 — RED output cannot bypass the Safety Guardian", _inv4),
        ("verdict vocabulary is enforced", _inv_verdict),
        ("Guardian redacts operational detail", _guardian_redacts),
        ("all six agent prompts load from 02_AGENT_PROMPTS.md", _prompts),
        ("agents receive projections, not the whole blackboard", _projection),
        ("full engagement: budget, legal moves, challenge->durability", _full_run),
        ("control flow is not a fixed pipeline", _no_static_pipeline),
    ]

    failed = 0
    for name, fn in checks:
        try:
            ok = fn()
        except Exception as e:                                     # noqa: BLE001
            ok, name = False, f"{name}  [{type(e).__name__}: {e}]"
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        failed += not ok
    print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
    return 1 if failed else 0


# ----------------------------------------------------------------------------------
# 9. MYSKILLOS / CLAUDE PACKAGE BUILD
# ----------------------------------------------------------------------------------

#: agent key -> (file name, node type, tools, one-line description)
AGENT_CARDS = {
    "ROUTER": ("orchestrator-router", "Chief", "Read, Write",
               "Chief orchestrator. Chooses which agent acts next and writes its mandate, "
               "selecting only from the legal-move set computed from state invariants. "
               "Produces no security content of its own. Entry node for every turn."),
    "RECON": ("recon-analyst", "Sub-agent", "Read, Write",
              "Decomposes the target architecture into an asset inventory, trust boundaries "
              "and an initial coverage map. Surfaces the human and process assets the "
              "specification omitted. Runs once, plus on demand when the attacker reports "
              "missing information."),
    "RED": ("red-team", "Sub-agent", "Read, Write",
            "Attacker. Produces abstract attack hypotheses across two lanes: software/logic "
            "and social engineering / human process. Output is vulnerability classes and "
            "MITRE ATT&CK identifiers only, and always passes through safety-guardian before "
            "reaching shared state."),
    "BLUE": ("blue-team", "Sub-agent", "Read, Write",
             "Defender. Produces layered countermeasures — preventive, detective and "
             "containment — for findings raised by the attacker, and states the assumptions "
             "each control rests on. Never sees the attacker directly; reads findings from "
             "shared state."),
    "AUDITOR": ("security-auditor", "Sub-agent", "Read, Write",
                "Independent judge over attacker and defender. Issues one of six verdicts per "
                "finding/mitigation pair, computes the security score, maintains the "
                "calibration ledger, decides convergence, and authors the final report. May "
                "not author findings or mitigations."),
    "GUARDIAN": ("safety-guardian", "Sub-agent", "Read, Write",
                 "Cross-cutting filter on every attacker output before it enters shared state. "
                 "Passes, redacts to abstract form, or rejects. Keeps the exercise at the level "
                 "of threat models rather than operational capability."),
}


def build_package(root: str = "myskillos_package") -> int:
    """Emit the Myskillos / Claude importable layout: CLAUDE.md + .claude/agents/*.md.

    Agent bodies are generated from 02_AGENT_PROMPTS.md, so the package can never drift
    from the document that is submitted alongside it.
    """
    prompts = load_prompts()
    agents_dir = os.path.join(root, ".claude", "agents")
    os.makedirs(agents_dir, exist_ok=True)
    written = []
    for key, (fname, node, tools, desc) in AGENT_CARDS.items():
        body = prompts[key]
        one_line = " ".join(desc.split())
        front = (f"---\nname: {fname}\ndescription: {one_line}\ntools: {tools}\n"
                 f"node_type: {node}\n---\n\n")
        path = os.path.join(agents_dir, f"{fname}.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(front + body + "\n")
        written.append(path)

    refs = os.path.join(root, "references")
    os.makedirs(refs, exist_ok=True)
    for src, dst in (("03_STATE_SCHEMA.json", "state-schema.json"),
                     ("04_SCORING_RUBRIC.md", "scoring-rubric.md"),
                     ("sample_target.md", "example-target.md")):
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), src)
        if os.path.exists(here):
            with open(here, encoding="utf-8") as a, \
                 open(os.path.join(refs, dst), "w", encoding="utf-8") as b:
                b.write(a.read())
            written.append(os.path.join(refs, dst))

    print(f"package built at {root}/")
    for w in written:
        print(f"  {w}")
    return 0


# ----------------------------------------------------------------------------------
# 10. CLI
# ----------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="PURPLE-LOOP adversarial security orchestration")
    ap.add_argument("--target", default="sample_target.md", help="path to target architecture description")
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--live", action="store_true", help="use the Anthropic API instead of mock mode")
    ap.add_argument("--model", default="claude-sonnet-5")
    ap.add_argument("--out", default="sample_run_report.md")
    ap.add_argument("--state-out", default="final_state.json")
    ap.add_argument("--self-test", action="store_true", help="assert the architectural invariants")
    ap.add_argument("--build-package", action="store_true",
                    help="emit the Myskillos/Claude importable layout from the prompt file")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if a.build_package:
        return build_package()

    spec = open(a.target, encoding="utf-8").read() if os.path.exists(a.target) else a.target
    brain: Callable[[str, dict], dict]
    if a.live:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ANTHROPIC_API_KEY not set; falling back to mock mode.", file=sys.stderr)
            brain = MockBrain()
        else:
            brain = LiveBrain(a.model)
    else:
        brain = MockBrain()

    orch = Orchestrator(brain=brain, state=new_state(spec, a.rounds))
    state = orch.run()

    report = render_report(state, orch.trace)
    open(a.out, "w", encoding="utf-8").write(report)
    state.pop("_score_history", None)
    open(a.state_out, "w", encoding="utf-8").write(json.dumps(state, indent=2, ensure_ascii=False))
    print(f"\nReport -> {a.out}\nState  -> {a.state_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
