"""Phase 4: end-to-end pipeline test. Feed a PCAP to pcap_to_flows_df,
classify through the full pipeline (ML → sanity → rules → C2 heuristic),
verify the labels are as expected.

Uses the existing test_real_dos_hulk.pcap (synthetic single-source Hulk,
known-good pattern the rule engine should catch as DoS Hulk)."""
import sys, importlib.util, os
os.environ.setdefault('SECRET_KEY', 'test-audit-secret')
os.environ.setdefault('BASTION_DATA_DIR', os.getcwd())

# Import app carefully — this loads the ML models (slow but necessary).
sys.path.insert(0, '.')
import app

print('[4.1] models loaded:', app.model is not None)
assert app.model is not None, 'ML models failed to load'

# Extract flows from our synthetic Hulk PCAP
pcap_path = 'test_real_dos_hulk.pcap'
df = app.pcap_to_flows_df(pcap_path)
print(f'[4.2] pcap_to_flows_df: {len(df)} flows extracted from {pcap_path}')

# Ensure both IP columns are present
assert 'src_ip' in df.columns and 'dst_ip' in df.columns, 'IP cols missing from PCAP extract'
print('[4.3] src_ip/dst_ip columns present: OK')

# Feed through full pipeline: reuse _run_scan? No — call pieces directly.
import pandas as pd, numpy as np
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
X = pd.DataFrame(0.0, index=df.index, columns=app.feature_names)
for col in app.feature_names:
    if col in df.columns:
        X[col] = df[col]
X = X.fillna(X.median(numeric_only=True)).fillna(0.0)
X_scaled = app.preprocessor.transform(X)

# Build raw_rows the way _run_scan does
rule_feat_cols = [
    'SYN Flag Count','ACK Flag Count','PSH Flag Count','FIN Flag Count',
    'Total Fwd Packets','Total Backward Packets',
    'Total Length of Fwd Packets','Total Length of Bwd Packets',
    'Fwd Packet Length Max','Bwd Packet Length Max','Init_Win_bytes_forward',
    'Flow Packets/s','Fwd Packets/s','Flow Duration','Destination Port','Protocol',
]
raw_rows = []
for idx in range(len(df)):
    row = {}
    for col in rule_feat_cols:
        if col in df.columns:
            try: row[col] = float(df[col].iloc[idx])
            except: row[col] = 0.0
        else:
            row[col] = 0.0
    raw_rows.append(row)

# Classify — simulate the pipeline as is_pcap=True
preds = app.model.predict(X_scaled)
probs = app.model.predict_proba(X_scaled)
lbls  = [app.clean_label(l) for l in app.label_encoder[preds]]
confs = probs[np.arange(len(preds)), preds] * 100

ml_labels = {}
final_labels = {}
for j, (label, conf) in enumerate(zip(lbls, confs)):
    ml_labels[label] = ml_labels.get(label, 0) + 1
    # Sanity
    label, conf, _ = app.ml_sanity_check(label, conf, raw_rows[j])
    # Rule engine (PCAP always runs rules on BENIGN)
    if label.upper() == 'BENIGN':
        rr = app.rule_based_label(raw_rows[j])
        if rr: label, conf, _ = rr
    # Suspicious C2 heuristic
    if label.upper() == 'BENIGN':
        src = str(df['src_ip'].iloc[j])
        dst = str(df['dst_ip'].iloc[j])
        c2l, c2c = app.suspicious_c2_check(raw_rows[j], src, dst)
        if c2l: label = c2l
    final_labels[label] = final_labels.get(label, 0) + 1

print(f'[4.4] ML raw labels       : {ml_labels}')
print(f'[4.5] Final pipeline labels: {final_labels}')

# Hulk PCAP should produce mostly "DoS Hulk" (rule engine catches it)
hulk_count = final_labels.get('DoS Hulk', 0)
pct = hulk_count / len(df) * 100
print(f'[4.6] DoS Hulk detection: {hulk_count}/{len(df)} ({pct:.0f}%)')
ok = pct >= 80
print(f'[4.7] detection accuracy: {"OK" if ok else "FAIL"} (expected >=80%)')
sys.exit(0 if ok else 1)
