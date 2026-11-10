"""Portable report generated only from measured rows; no external assets."""

import html
import json
import statistics
from pathlib import Path

from .scenarios import DESCRIPTIONS, POLICIES, SCENARIOS


def render(destination, security, recovery, manifest):
    destination = Path(destination)
    rows = []
    for name in SCENARIOS:
        decisions = []
        for policy in POLICIES:
            values = [r for r in security if r["scenario"] == name and r["policy"] == policy]
            accepted = sum(r["accepted"] for r in values)
            label = "ACCEPT" if accepted == len(values) else "REJECT" if accepted == 0 else "MIXED"
            reason = values[0]["reason"] or "Verified by this policy"
            decisions.append(f'<td title="{html.escape(reason)}" class="{label.lower()}">{label}</td>')
        rows.append(f'<tr data-name="{name}"><th scope="row">{html.escape(name.replace("_", " "))}'
                    f'<small>{html.escape(DESCRIPTIONS[name])}</small></th>{"".join(decisions)}</tr>')
    timing = {p: statistics.median(r["elapsed_ms"] for r in security
                                  if r["policy"] == p and r["scenario"] == "legitimate") for p in POLICIES}
    maximum = max(timing.values()) or 1
    bars = []
    for i, (policy, elapsed) in enumerate(timing.items()):
        y = 55 + i * 65
        bars.append(f'<text x="16" y="{y + 20}" fill="#e6edf7">{policy}</text>'
                    f'<rect x="135" y="{y}" width="{max(1, elapsed / maximum * 330):.1f}" '
                    f'height="28" rx="4" fill="#5dd5ba"/>'
                    f'<text x="480" y="{y + 20}" fill="#e6edf7">{elapsed:.3f} ms</text>')
    chart = ('<svg xmlns="http://www.w3.org/2000/svg" width="640" height="270" '
             'viewBox="0 0 640 270" role="img" aria-label="Median verification time">'
             '<rect width="640" height="270" rx="12" fill="#172235"/>'
             '<g font-family="sans-serif" font-size="15"><text x="16" y="28" fill="#e6edf7">'
             'Legitimate update: median verification time</text>' + ''.join(bars) + '</g></svg>')
    (destination / "verification-time.svg").write_text(chart, encoding="utf-8")
    recovery_rows = []
    for point in ("image_written", "prepared", "trial", "healthy", "committed"):
        values = [r for r in recovery if r["checkpoint"] == point]
        recovery_rows.append(f'<tr><th>{point}</th><td>{values[0]["recovered_version"]}</td>'
                             f'<td>{sum(r["invariant_ok"] for r in values)}/{len(values)}</td></tr>')
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UpdateGuard — measured experiment report</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0d1522;color:#e6edf7;font:16px/1.6 system-ui,sans-serif}
main{max-width:1120px;margin:auto;padding:48px 24px}h1{font-size:clamp(36px,6vw,64px);line-height:1.1;margin:12px 0}h2{margin-top:38px}
.eyebrow{color:#5dd5ba;letter-spacing:2px;font-size:13px;text-transform:uppercase}.lede{max-width:760px;color:#b6c5d9;font-size:19px}
.cards{display:flex;gap:16px;flex-wrap:wrap}.card{background:#172235;padding:20px;border-radius:12px;flex:1;min-width:190px}.card strong{display:block;font-size:32px}
.notice{border-left:4px solid #f0be62;background:#211f23;padding:16px 20px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:12px;text-align:left;border-bottom:1px solid #2b3b50}thead th{color:#93a7c1}small{display:block;color:#9bacc2;font-weight:400;max-width:650px}.accept{color:#5dd5ba}.reject{color:#f0be62}.mixed{color:#ff8585}input{width:100%;background:#172235;color:#fff;border:1px solid #536780;border-radius:6px;padding:12px;margin:12px 0}a{color:#8ecbff}svg{max-width:100%;height:auto}.scroll{overflow-x:auto}footer{margin-top:40px;color:#9bacc2;font-size:14px}code{color:#a1d8ff}
</style><main><div class="eyebrow">Security • state machines • failure recovery</div>
<h1>UpdateGuard</h1><p class="lede">What a signed update protects — and what happens when installation stops halfway.</p>
<div class="cards"><div class="card"><strong>SECURITY_COUNT</strong>verifier decisions measured</div>
<div class="card"><strong>RECOVERY_COUNT</strong>hard process interruptions</div>
<div class="card"><strong>ASSERTION_STATE</strong>protocol & recovery assertions</div></div>
<p class="notice"><b>Acceptance is not automatically a success.</b> Replayed releases pass naive verification.
Compromise of all online signing roles also passes TUF in this configuration. Authentication does not establish software health.</p>
<h2>Verification matrix</h2><p>All clients check the device model. Only the TUF policy maintains metadata freshness and a confirmed-version floor.
These are explicit scenario tests, not estimates of real-world attack success rates.</p>
<label for="filter">Filter scenarios</label><input id="filter" placeholder="Try replay, key or health">
<div class="scroll"><table id="matrix"><thead><tr><th>Scenario and capability</th><th>Hash</th><th>Signature</th><th>TUF + policy</th></tr></thead><tbody>SECURITY_ROWS</tbody></table></div>
<h2>Recovery after process termination</h2><p>A worker exits immediately with code 75 at a persisted boundary.
A fresh process recovers the state. An independent reader checks the actual active image, its digest and the version floor.</p>
<table><thead><tr><th>Interruption boundary</th><th>Recovered version</th><th>Invariants met</th></tr></thead><tbody>RECOVERY_ROWS</tbody></table>
<p>v1 is retained before a successful health result is persisted. After that result, recovery completes v2.
The campaign uses two artifact sizes (about 315 bytes and 1 MiB). It does not emulate flash-controller behavior or physical power loss.</p>
<h2>Cost of verification</h2>CHART<p>Measured in-memory transport plus local metadata/file I/O, excluding setup.
Repeated runs describe local timing variability; no network-latency or embedded-performance claim is made.</p>
<h2>Reproduce and inspect</h2><p><code>python -m updateguard.cli benchmark --repetitions 3</code></p>
<p><a href="security.csv">Verification rows</a> · <a href="recovery.csv">Recovery rows</a> · <a href="experiment.json">Experiment manifest</a></p>
<footer>GENERATED · Software-only research prototype. Synthetic inert artifacts. No secure boot, physical key protection or Uptane certification.</footer>
</main><script>document.getElementById('filter').addEventListener('input',e=>{const q=e.target.value.toLowerCase();document.querySelectorAll('#matrix tbody tr').forEach(r=>{r.hidden=!r.textContent.toLowerCase().includes(q)})});</script></html>'''
    replacements = {"SECURITY_COUNT": str(len(security)), "RECOVERY_COUNT": str(len(recovery)),
                    "ASSERTION_STATE": "PASS" if manifest["security_expectations_met"] and manifest["recovery_invariants_met"] else "FAIL",
                    "SECURITY_ROWS": "".join(rows), "RECOVERY_ROWS": "".join(recovery_rows),
                    "CHART": chart, "GENERATED": html.escape(manifest["generated_utc"])}
    for key, value in replacements.items():
        page = page.replace(key, value)
    (destination / "index.html").write_text(page, encoding="utf-8")
    summary = f'''# Résultats mesurés — UpdateGuard

Date UTC : {manifest['generated_utc']}

- {len(security)} décisions de vérification : toutes conformes aux attentes = {manifest['security_expectations_met']}.
- {len(recovery)} interruptions réelles de processus : invariants de récupération respectés = {manifest['recovery_invariants_met']}.
- Durée de campagne : {manifest['elapsed_seconds']} secondes.

## Ce que montrent les expériences

Le rejeu passe les références empreinte et signature unique, mais est refusé par le client TUF avec état persistant.
La rotation de clé est acceptée par TUF ; le client à clé fixe refuse la nouvelle signature.
La compromission de toutes les clés en ligne reste acceptée : c'est une limite explicite de la configuration, pas une attaque bloquée.
Une image authentique peut être malsaine. La vérification et la récupération sont des responsabilités séparées.
Avant confirmation de santé, le redémarrage conserve v1. Après persistance de la santé, il termine v2.

## Limites

Les répétitions servent à observer les durées, pas à multiplier le nombre de menaces indépendantes.
Les attaques sont des scénarios construits. Aucun taux de risque réel ni intervalle de confiance de sécurité n'est déduit.
Le test de récupération interrompt le processus aux frontières persistantes ; il ne simule pas les défaillances électriques d'une mémoire flash.
Les résultats ont été consultés pendant le développement : étude exploratoire, sans test aveugle.
'''
    (destination / "RESULTS_FR.md").write_text(summary, encoding="utf-8")
