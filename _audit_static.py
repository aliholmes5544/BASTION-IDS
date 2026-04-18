"""Phase 1: static analysis of app.py — no runtime imports."""
import ast, re, sys
from pathlib import Path

src = Path('app.py').read_text(encoding='utf-8')

issues = []

# ── 1. Syntax parse ─────────────────────────────────────────────────────
try:
    ast.parse(src)
    print('[1.1] syntax: OK')
except SyntaxError as e:
    issues.append(f'syntax: {e}')
    print(f'[1.1] syntax: FAIL — {e}')

# ── 2. Rule ↔ label consistency ─────────────────────────────────────────
rule_block = re.search(r'_RULE_THRESHOLDS_LIST = \[(.*?)\n\]', src, re.DOTALL).group(1)
rules = re.findall(r"\('([a-z_]+)',\s*\[", rule_block)
label_block = re.search(r'_RULE_LABELS = \{(.*?)\n\}', src, re.DOTALL).group(1)
labels = re.findall(r"'([a-z_]+)':", label_block)
missing_labels = set(rules) - set(labels)
unused_labels  = set(labels) - set(rules)
print(f'[2.1] rules in list: {len(rules)}   labels mapped: {len(labels)}')
if missing_labels: issues.append(f'rules without label: {missing_labels}')
if unused_labels:  issues.append(f'labels without rule: {unused_labels}')
print(f'[2.2] rule↔label: {"OK" if not (missing_labels or unused_labels) else "FAIL"}')

# ── 3. Labels present in SEVERITY ──────────────────────────────────────
sev_block = re.search(r'SEVERITY = \{(.*?)^\}', src, re.DOTALL | re.MULTILINE).group(1)
sev_labels = re.findall(r"'([A-Za-z][A-Za-z0-9 \-/]*)':\s*\('", sev_block)
rule_display_labels = re.findall(r"'[a-z_]+':\s+\('([^']+)',", label_block)
# SEVERITY uses case-sensitive exact match (plus the fuzzy get_severity), but check exact first
missing_sev = [l for l in rule_display_labels if l not in sev_labels]
print(f'[3.1] SEVERITY entries: {len(sev_labels)}')
print(f'[3.2] rule-produced labels in SEVERITY: {"OK" if not missing_sev else "FAIL — "+str(missing_sev)}')
if missing_sev: issues.append(f'labels not in SEVERITY: {missing_sev}')

# Heuristic labels
for heur_label in ['Suspicious C2', 'Malicious C2']:
    if heur_label not in sev_labels:
        issues.append(f'heuristic label not in SEVERITY: {heur_label}')
        print(f'[3.3] {heur_label}: FAIL')
    else:
        print(f'[3.3] {heur_label}: OK')

# ── 4. rule_feature_cols completeness ──────────────────────────────────
feat_list = re.search(r'rule_feature_cols = \[(.*?)\]', src, re.DOTALL).group(1)
feat_cols = set(re.findall(r"'([^']+)'", feat_list))
# Features referenced in rules
rule_feats = set(re.findall(r"\('([A-Z][^']+)',\s*'[<>=]", rule_block))
# Features referenced in heuristics
heur_block = re.search(r'def suspicious_c2_check.*?return None, None', src, re.DOTALL).group(0)
sanity_block = re.search(r'def ml_sanity_check.*?return label, conf, False', src, re.DOTALL).group(0)
heur_feats = set(re.findall(r"row\.get\('([^']+)'", heur_block + sanity_block))
# Exclude meta features (src_ip/dst_ip/Destination Port is expected)
heur_feats -= {'Destination Port'}  # already in feat_cols? check
all_needed = rule_feats | heur_feats | {'Destination Port'}
missing_feats = all_needed - feat_cols
print(f'[4.1] rule_feature_cols has {len(feat_cols)} cols')
print(f'[4.2] rule+heuristic features covered: {"OK" if not missing_feats else "FAIL — "+str(missing_feats)}')
if missing_feats: issues.append(f'rule_feature_cols missing: {missing_feats}')

# ── 5. MITRE mapping for every rule-produced label ─────────────────────
mitre_block = re.search(r'MITRE_MAPPING = \{(.*?)^\}', src, re.DOTALL | re.MULTILINE).group(1)
mitre_labels = re.findall(r"'([^']+)':\s*\{", mitre_block)
# Only required for attack labels that land on the results UI
missing_mitre = [l for l in rule_display_labels if l not in mitre_labels and l != 'BENIGN']
print(f'[5.1] MITRE entries: {len(mitre_labels)}')
if missing_mitre:
    # Not fatal — MITRE is informational, but flag it
    print(f'[5.2] labels without MITRE mapping: {missing_mitre} (informational)')
else:
    print(f'[5.2] MITRE coverage: OK')

# ── 6. Route → template cross-check ────────────────────────────────────
routes = re.findall(r"@app\.route\('([^']+)'", src)
render_calls = re.findall(r"render_template\(\s*['\"]([^'\"]+)['\"]", src)
template_dir = Path('templates')
missing_templates = []
for t in set(render_calls):
    if not (template_dir / t).exists():
        missing_templates.append(t)
print(f'[6.1] routes: {len(set(routes))}  render_template calls: {len(set(render_calls))}')
print(f'[6.2] all rendered templates exist: {"OK" if not missing_templates else "FAIL — "+str(missing_templates)}')
if missing_templates: issues.append(f'missing templates: {missing_templates}')

# ── 7. No accidental merge conflicts / tabs-spaces mix ─────────────────
if '<<<<<<<' in src or '>>>>>>>' in src:
    issues.append('merge conflict markers present')
    print('[7.1] merge markers: FAIL')
else:
    print('[7.1] merge markers: OK')

print(f'\nSTATIC ISSUES: {len(issues)}')
for i in issues: print(f'  - {i}')
sys.exit(1 if issues else 0)
