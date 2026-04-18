"""Phase 7: detection accuracy on labeled ground-truth data.

Builds one PCAP containing 7 attack types (5 flows each = 35 attack flows)
plus 10 benign control flows. Ground truth is inferred from the 5-tuple used
to construct each group.

Runs the full BASTION pipeline:
  (a) PCAP path: pcap_to_flows_df -> ML -> sanity -> rules (on BENIGN) -> C2
  (b) CSV path:  same features from (a), fed as CSV (rules only fire when
                 ML says BENIGN with conf < 70%)

Reports:
  * Binary accuracy: attack vs benign
  * Per-class precision / recall / F1
  * Confusion list (ground truth -> predicted)
"""
import os, sys, random
from collections import defaultdict, Counter
from ipaddress import ip_address

os.environ.setdefault('SECRET_KEY', 'test-audit-secret')
os.environ.setdefault('BASTION_DATA_DIR', os.getcwd())
sys.path.insert(0, '.')
import app
import pandas as pd, numpy as np
from scapy.all import IP, TCP, UDP, Raw, wrpcap, PcapReader

random.seed(20260418)

# ─── Build labeled test PCAP ─────────────────────────────────────────────
# Each group produces 5 flows. Ground truth is stamped into the src IP range
# so we can recover it after pcap_to_flows_df merges packets into flows.

GROUND_TRUTH_RULES = [
    # (label, src_ip_predicate, dst_port_predicate)
    ('DDoS',         lambda s,d,dp: s.startswith('10.') and not s.startswith('10.10.')
                                    and not s.startswith('10.20.') and d == '192.168.1.100' and dp == 80),
    ('PortScan',     lambda s,d,dp: s == '172.16.0.10'),
    ('FTP-Patator',  lambda s,d,dp: s.startswith('172.16.1.') and dp == 21),
    ('SSH-Patator',  lambda s,d,dp: s.startswith('172.16.2.') and dp == 22),
    ('DoS GoldenEye',lambda s,d,dp: s.startswith('10.10.') and dp == 80),
    ('DoS slowloris',lambda s,d,dp: s.startswith('10.20.') and dp == 80),
    ('Bot',          lambda s,d,dp: s.startswith('192.168.10.') and dp == 8080),
    ('BENIGN',       lambda s,d,dp: s == '192.168.1.50'),
]

def ground_truth(src, dst, dst_port):
    for label, pred in GROUND_TRUTH_RULES:
        try:
            if pred(src, dst, int(dst_port)):
                return label
        except ValueError:
            pass
    return 'UNKNOWN'

packets = []
t = 1712700000.0

# DDoS (5 flows): single-source-per-flow SYN + 3 fast HTTP + server response
for i in range(5):
    src = f'10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'
    dst = '192.168.1.100'; sp = random.randint(49152, 65535); st = t + i * 5
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='S',window=256,seq=100));     packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=80,dport=sp,flags='SA',window=229,seq=200,ack=101)); packets[-1].time = st+0.003
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='A',window=256,seq=101,ack=201)); packets[-1].time = st+0.006
    for j in range(3):
        p = IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='A',window=256,seq=101+j*7,ack=201)/Raw(load=b'GET / H')
        p.time = st + 0.49*(j+1); packets.append(p)
    for j, sz in enumerate([5755, 1500, 548]):
        p = IP(src=dst,dst=src)/TCP(sport=80,dport=sp,flags='A',window=229,seq=201+j*sz,ack=122)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz)))
        p.time = st + 0.003 + 0.019*(j+1); packets.append(p)
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='A',window=256,seq=122,ack=9000); p.time = st+1.88; packets.append(p)

# PortScan (5 flows): SYN + RST-ACK on varied ports
for i in range(5):
    src = '172.16.0.10'; dst = '192.168.1.100'; sp = random.randint(49152, 65535)
    dport = random.choice([22, 443, 3306, 3690, 5432]); st = t + 50 + i * 0.5
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=dport,flags='S',window=29200,seq=100));     packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=dport,dport=sp,flags='RA',window=0,seq=0,ack=101));  packets[-1].time = st+0.000047

# FTP-Patator (5)
for i in range(5):
    src = f'172.16.1.{random.randint(1,254)}'; dst = '192.168.1.200'
    sp = random.randint(49152, 65535); st = t + 100 + i * 2
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=21,flags='S',window=29200,seq=100));     packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=21,dport=sp,flags='SA',window=227,seq=200,ack=101)); packets[-1].time = st+0.003
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=21,flags='A',window=29200,seq=101,ack=201)); packets[-1].time = st+0.006
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=21,flags='PA',window=29200,seq=101,ack=201)/Raw(load=b'USER admin\r\n'); p.time=st+0.5; packets.append(p)
    p = IP(src=dst,dst=src)/TCP(sport=21,dport=sp,flags='PA',window=227,seq=201,ack=113)/Raw(load=b'331 Password required\r\n'); p.time=st+0.51; packets.append(p)
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=21,flags='PA',window=29200,seq=113,ack=223)/Raw(load=b'PASS test123\r\n'); p.time=st+1.0; packets.append(p)
    p = IP(src=dst,dst=src)/TCP(sport=21,dport=sp,flags='PA',window=227,seq=223,ack=127)/Raw(load=b'530 Login incorrect\r\n'); p.time=st+1.01; packets.append(p)

# SSH-Patator (5)
for i in range(5):
    src = f'172.16.2.{random.randint(1,254)}'; dst = '192.168.1.200'
    sp = random.randint(49152, 65535); st = t + 200 + i * 10
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=22,flags='S',window=29200,seq=100));      packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=22,dport=sp,flags='SA',window=247,seq=200,ack=101));packets[-1].time = st+0.003
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=22,flags='A',window=29200,seq=101,ack=201));packets[-1].time = st+0.006
    seq = 101
    for j, sz in enumerate([640,80,80,80,80,80,80,0,0,0,0]):
        if sz > 0:
            p = IP(src=src,dst=dst)/TCP(sport=sp,dport=22,flags='A',window=29200,seq=seq,ack=201)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz))); seq+=sz
        else:
            p = IP(src=src,dst=dst)/TCP(sport=sp,dport=22,flags='A',window=29200,seq=seq,ack=201)
        p.time = st + 0.21*(j+1); packets.append(p)
    bseq = 201
    for j, sz in enumerate([976,80,80,40,40,40,40,0,0]):
        if sz > 0:
            p = IP(src=dst,dst=src)/TCP(sport=22,dport=sp,flags='A',window=247,seq=bseq,ack=seq)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz))); bseq+=sz
        else:
            p = IP(src=dst,dst=src)/TCP(sport=22,dport=sp,flags='A',window=247,seq=bseq,ack=seq)
        p.time = st + 0.24*(j+1); packets.append(p)
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=22,flags='FA',window=29200,seq=seq,ack=bseq); p.time=st+2.48; packets.append(p)

# DoS GoldenEye (5): Init_Win 29200 + large fwd + 12s flow
for i in range(5):
    src = f'10.10.{random.randint(1,254)}.{random.randint(1,254)}'
    dst = '192.168.1.100'; sp = random.randint(49152, 65535); st = t + 300 + i * 15
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='S',window=29200,seq=100));     packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=80,dport=sp,flags='SA',window=235,seq=200,ack=101));packets[-1].time = st+0.003
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='A',window=29200,seq=101,ack=201));packets[-1].time = st+0.006
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='A',window=29200,seq=101,ack=201)/Raw(load=bytes(random.getrandbits(8) for _ in range(370))); p.time=st+1.15; packets.append(p)
    for j in range(3):
        p = IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='A',window=29200,seq=471+j,ack=201); p.time=st+1.15*(j+2); packets.append(p)
    for j, sz in enumerate([3525,400]):
        p = IP(src=dst,dst=src)/TCP(sport=80,dport=sp,flags='A',window=235,seq=201+j*sz,ack=474)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz))); p.time=st+1.16+2.27*j; packets.append(p)
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='FA',window=29200,seq=474,ack=4126); p.time=st+11.59; packets.append(p)

# DoS slowloris (5): small payloads, no bwd data, 97s flow
for i in range(5):
    src = f'10.20.{random.randint(1,254)}.{random.randint(1,254)}'
    dst = '192.168.1.100'; sp = random.randint(49152, 65535); st = t + 500 + i * 5
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='S',window=29200,seq=100));     packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=80,dport=sp,flags='SA',window=28960,seq=200,ack=101));packets[-1].time = st+0.003
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='A',window=29200,seq=101,ack=201));packets[-1].time = st+0.006
    seq = 101
    for j in range(3):
        p = IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='PA',window=29200,seq=seq,ack=201)/Raw(load=b'X-a: b\r\n'); seq+=8; p.time=st+7.0*(j+1); packets.append(p)
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=80,flags='FA',window=29200,seq=seq,ack=201); p.time=st+97.0; packets.append(p)

# Bot (5): port 8080, tiny PING/PONG
for i in range(5):
    src = f'192.168.10.{random.randint(1,254)}'; dst = '10.0.0.1'
    sp = random.randint(49152, 65535); st = t + 600 + i * 2
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=8080,flags='S',window=237,seq=100));     packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=8080,dport=sp,flags='SA',window=110,seq=200,ack=101));packets[-1].time = st+0.003
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=8080,flags='A',window=237,seq=101,ack=201));packets[-1].time = st+0.006
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=8080,flags='A',window=237,seq=101,ack=201)/Raw(load=b'PING'); p.time=st+0.03; packets.append(p)
    p = IP(src=dst,dst=src)/TCP(sport=8080,dport=sp,flags='A',window=110,seq=201,ack=105)/Raw(load=b'PONG'); p.time=st+0.05; packets.append(p)

# BENIGN (10): normal HTTPS sessions with real bidirectional exchange
for i in range(10):
    src = '192.168.1.50'; dst = f'93.184.216.{random.randint(1,254)}'  # example.com-ish
    sp  = random.randint(49152, 65535); dport = random.choice([80, 443])
    st  = t + 800 + i * 5
    win = 64240  # normal Windows Init_Win
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=dport,flags='S',window=win,seq=100));  packets[-1].time = st
    packets.append(IP(src=dst,dst=src)/TCP(sport=dport,dport=sp,flags='SA',window=29200,seq=200,ack=101)); packets[-1].time = st+0.05
    packets.append(IP(src=src,dst=dst)/TCP(sport=sp,dport=dport,flags='A',window=win,seq=101,ack=201));packets[-1].time = st+0.06
    for j in range(4):
        p = IP(src=src,dst=dst)/TCP(sport=sp,dport=dport,flags='PA',window=win,seq=101+j*500,ack=201)/Raw(load=bytes(random.getrandbits(8) for _ in range(500))); p.time=st+0.1+j*0.3; packets.append(p)
    for j in range(4):
        p = IP(src=dst,dst=src)/TCP(sport=dport,dport=sp,flags='PA',window=29200,seq=201+j*1400,ack=101+(j+1)*500)/Raw(load=bytes(random.getrandbits(8) for _ in range(1400))); p.time=st+0.12+j*0.3; packets.append(p)
    p = IP(src=src,dst=dst)/TCP(sport=sp,dport=dport,flags='FA',window=win,seq=2101,ack=5801); p.time=st+2.5; packets.append(p)

packets.sort(key=lambda p: p.time)
pcap_path = '_audit_testdata.pcap'
wrpcap(pcap_path, packets)
print(f'[7.1] wrote {pcap_path} — {len(packets)} packets')

# ─── Extract flows with BASTION's own extractor ─────────────────────────
df = app.pcap_to_flows_df(pcap_path)
print(f'[7.2] pcap_to_flows_df extracted {len(df)} flows')

# Stamp ground truth per flow
df['gt'] = df.apply(lambda r: ground_truth(str(r['src_ip']), str(r['dst_ip']), r['Destination Port']), axis=1)
gt_counts = Counter(df['gt'])
print(f'[7.3] ground truth breakdown: {dict(gt_counts)}')

# Save CSV variant for the CSV-path test
csv_path = '_audit_testdata.csv'
df.drop(columns=['gt']).to_csv(csv_path, index=False)
print(f'[7.4] wrote {csv_path} for CSV-path test')

# ─── Classify via full BASTION pipeline ─────────────────────────────────
def classify(df_in, is_pcap_scan):
    work = df_in.copy()
    work.columns = work.columns.str.strip()
    work.replace([np.inf, -np.inf], np.nan, inplace=True)
    X = pd.DataFrame(0.0, index=work.index, columns=app.feature_names)
    for col in app.feature_names:
        if col in work.columns:
            X[col] = work[col]
    X = X.fillna(X.median(numeric_only=True)).fillna(0.0)
    X_scaled = app.preprocessor.transform(X)
    preds = app.model.predict(X_scaled)
    probs = app.model.predict_proba(X_scaled)
    lbls  = [app.clean_label(l) for l in app.label_encoder[preds]]
    confs = probs[np.arange(len(preds)), preds] * 100
    rule_feat_cols = [
        'SYN Flag Count','ACK Flag Count','PSH Flag Count','FIN Flag Count',
        'Total Fwd Packets','Total Backward Packets',
        'Total Length of Fwd Packets','Total Length of Bwd Packets',
        'Fwd Packet Length Max','Bwd Packet Length Max','Init_Win_bytes_forward',
        'Flow Packets/s','Fwd Packets/s','Flow Duration','Destination Port','Protocol',
    ]
    raw_rows = []
    for idx in range(len(work)):
        row = {}
        for col in rule_feat_cols:
            if col in work.columns:
                try: row[col] = float(work[col].iloc[idx])
                except: row[col] = 0.0
            else:
                row[col] = 0.0
        raw_rows.append(row)
    out = []
    for j, (label, conf) in enumerate(zip(lbls, confs)):
        ml_label = label
        # sanity
        label, conf, _ = app.ml_sanity_check(label, conf, raw_rows[j])
        # rule engine gating — mirrors current _run_scan (unified gate):
        # run rules on every BENIGN, plus low-confidence DDoS.
        run_rules = False
        if label.upper() == 'BENIGN': run_rules = True
        elif label.upper() == 'DDOS' and conf < 70: run_rules = True
        if run_rules:
            rr = app.rule_based_label(raw_rows[j])
            if rr: label = rr[0]; conf = rr[1]
        # Suspicious C2 heuristic
        if label.upper() == 'BENIGN':
            src = str(work['src_ip'].iloc[j]) if 'src_ip' in work else 'N/A'
            dst = str(work['dst_ip'].iloc[j]) if 'dst_ip' in work else 'N/A'
            c2l, c2c = app.suspicious_c2_check(raw_rows[j], src, dst)
            if c2l: label = c2l; conf = c2c
        out.append((ml_label, label, conf))
    return out

# Binary helpers
def is_attack(label):
    return label.upper() not in ('BENIGN', 'UNKNOWN')

def metrics(name, predictions, df_):
    gt  = df_['gt'].tolist()
    pred = [p[1] for p in predictions]
    tp = fp = tn = fn = 0
    per_class = defaultdict(lambda: {'tp':0,'fp':0,'fn':0})
    for g, p in zip(gt, pred):
        ga = is_attack(g); pa = is_attack(p)
        if ga and pa: tp += 1
        elif not ga and pa: fp += 1
        elif not ga and not pa: tn += 1
        elif ga and not pa: fn += 1
        # per-class multiclass metrics
        if g == p:
            per_class[g]['tp'] += 1
        else:
            if g != 'UNKNOWN': per_class[g]['fn'] += 1
            if p != 'UNKNOWN': per_class[p]['fp'] += 1
    total = tp + fp + tn + fn
    acc = (tp + tn) / total if total else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec  = tp / (tp + fn) if (tp + fn) else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0
    print(f'\n=== {name} ===')
    print(f'  binary  accuracy={acc:.1%}  precision={prec:.1%}  recall={rec:.1%}  F1={f1:.1%}')
    print(f'          TP={tp}  FP={fp}  TN={tn}  FN={fn}')
    print(f'  per-class (precision / recall / F1):')
    for cls in sorted(per_class):
        c = per_class[cls]
        p = c['tp']/(c['tp']+c['fp']) if (c['tp']+c['fp']) else 0
        r = c['tp']/(c['tp']+c['fn']) if (c['tp']+c['fn']) else 0
        f = 2*p*r/(p+r) if (p+r) else 0
        print(f'    {cls:25s}  P={p:.1%}  R={r:.1%}  F1={f:.1%}   (tp={c["tp"]}, fp={c["fp"]}, fn={c["fn"]})')
    # Confusion
    print(f'  confusion (ground-truth -> predicted counts):')
    conf = defaultdict(Counter)
    for g, p in zip(gt, pred): conf[g][p] += 1
    for g in sorted(conf):
        parts = ', '.join(f'{k}:{v}' for k, v in conf[g].most_common())
        print(f'    {g:25s} -> {parts}')
    return acc, prec, rec, f1

# PCAP pipeline (all rules active on BENIGN)
pcap_preds = classify(df.drop(columns=['gt']), is_pcap_scan=True)
metrics('PCAP pipeline', pcap_preds, df)

# CSV pipeline (rules only fire when ML says BENIGN with conf<70)
csv_df = pd.read_csv(csv_path)
csv_df['gt'] = df['gt'].values  # Align ground truth (same rows, same order)
csv_preds = classify(csv_df.drop(columns=['gt']), is_pcap_scan=False)
metrics('CSV pipeline', csv_preds, csv_df)
