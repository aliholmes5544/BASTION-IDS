"""Phase 3: exhaustive tests for ml_sanity_check + suspicious_c2_check."""
import ast, re, sys, ipaddress
src = open('app.py', encoding='utf-8').read()
tree = ast.parse(src)
wanted = {'is_private_ip','_BENIGN_SERVICE_PORTS','_C2_BENIGN_PORTS',
          'ml_sanity_check','suspicious_c2_check'}
pieces = []
for n in tree.body:
    if isinstance(n, ast.FunctionDef) and n.name in wanted:
        pieces.append(ast.get_source_segment(src, n))
    elif isinstance(n, ast.Assign):
        if any(isinstance(t, ast.Name) and t.id in wanted for t in n.targets):
            pieces.append(ast.get_source_segment(src, n))
ns = {'ipaddress': ipaddress}
exec('\n\n'.join(pieces), ns)
sanity = ns['ml_sanity_check']
c2     = ns['suspicious_c2_check']

results = []
def t(name, got, want):
    ok = got == want
    results.append((ok, name, got, want))

# ── ml_sanity_check ───────────────────────────────────────────────────

# DDoS branch — attack signals should PRESERVE label
t('sanity DDoS keep: low Init_Win',
  sanity('DDoS', 99, {'Init_Win_bytes_forward': 256}),
  ('DDoS', 99, False))
t('sanity DDoS keep: SYN flood',
  sanity('DDoS', 99, {'Init_Win_bytes_forward': 64240, 'SYN Flag Count': 10}),
  ('DDoS', 99, False))
t('sanity DDoS keep: flood rate',
  sanity('DDoS', 99, {'Init_Win_bytes_forward': 64240, 'Flow Packets/s': 100}),
  ('DDoS', 99, False))
t('sanity DDoS keep: lopsided many-pkt',
  sanity('DDoS', 99, {'Init_Win_bytes_forward': 64240,
                      'Total Backward Packets': 1, 'Total Fwd Packets': 20}),
  ('DDoS', 99, False))
# DDoS branch — no attack signal → demote
t('sanity DDoS demote: normal conv with bwd data',
  sanity('DDoS', 99, {'Init_Win_bytes_forward': 64240,
                      'Total Fwd Packets': 10, 'Total Backward Packets': 8,
                      'Total Length of Bwd Packets': 5000}),
  ('BENIGN', 99, True))
t('sanity DDoS demote: too few fwd packets',
  sanity('DDoS', 99, {'Init_Win_bytes_forward': 64240,
                      'Total Fwd Packets': 1, 'Total Backward Packets': 0}),
  ('BENIGN', 99, True))

# PortScan branch
t('sanity PortScan keep: 1 SYN no data',
  sanity('PortScan', 99, {'Total Fwd Packets': 1, 'Fwd Packet Length Max': 0}),
  ('PortScan', 99, False))
t('sanity PortScan demote: real conversation',
  sanity('PortScan', 99, {'Total Fwd Packets': 5, 'Total Backward Packets': 4,
                          'Fwd Packet Length Max': 100}),
  ('BENIGN', 99, True))
t('sanity PortScan demote: has payload',
  sanity('PortScan', 99, {'Total Fwd Packets': 2, 'Total Backward Packets': 2,
                          'Fwd Packet Length Max': 500,
                          'Total Length of Fwd Packets': 500}),
  ('BENIGN', 99, True))

# DoS family
t('sanity DoS Hulk keep: one-sided flood',
  sanity('DoS Hulk', 99, {'Total Fwd Packets': 50,
                          'Total Backward Packets': 2,
                          'Total Length of Bwd Packets': 200}),
  ('DoS Hulk', 99, False))
t('sanity DoS Hulk demote: balanced short conv',
  sanity('DoS Hulk', 99, {'Total Fwd Packets': 5,
                          'Total Backward Packets': 5,
                          'Total Length of Bwd Packets': 2000}),
  ('BENIGN', 99, True))

# Bot branch
t('sanity Bot demote: on port 443',
  sanity('Bot', 99, {'Destination Port': 443}),
  ('BENIGN', 99, True))
t('sanity Bot keep: on obscure port',
  sanity('Bot', 99, {'Destination Port': 8080}),
  ('Bot', 99, False))

# Unrelated labels pass through
t('sanity BENIGN passthrough', sanity('BENIGN', 90, {}),
  ('BENIGN', 90, False))
t('sanity FTP-Patator passthrough',
  sanity('FTP-Patator', 90, {'Destination Port': 21}),
  ('FTP-Patator', 90, False))

# ── suspicious_c2_check ───────────────────────────────────────────────

# Positive: Pattern A (non-standard port)
t('c2 A+: public, port 47074, 50KB/5s',
  c2({'Destination Port': 47074, 'Total Length of Fwd Packets': 10_000,
      'Total Length of Bwd Packets': 60_000, 'Total Backward Packets': 50,
      'Flow Duration': 6_000_000},
     '192.168.1.1', '8.8.8.8'),
  ('Suspicious C2', 75.0))

# Positive: Pattern B (HTTP lopsided download)
t('c2 B+: public, port 80, tiny req big resp',
  c2({'Destination Port': 80, 'Total Length of Fwd Packets': 4743,
      'Total Length of Bwd Packets': 1_390_800, 'Total Backward Packets': 1060,
      'Flow Duration': 27_000_000},
     '192.168.122.126', '34.104.35.123'),
  ('Suspicious C2', 75.0))

# Negative: private dst IP
t('c2-: private dst',
  c2({'Destination Port': 47074, 'Total Length of Fwd Packets': 10_000,
      'Total Length of Bwd Packets': 60_000, 'Total Backward Packets': 50,
      'Flow Duration': 6_000_000},
     '192.168.1.1', '10.0.0.5'),
  (None, None))

# Negative: N/A dst
t('c2-: N/A dst',
  c2({'Destination Port': 47074}, '192.168.1.1', 'N/A'),
  (None, None))

# Negative: port 0
t('c2-: port 0',
  c2({'Destination Port': 0}, '192.168.1.1', '8.8.8.8'),
  (None, None))

# Negative: Pattern A threshold not met (too small/short)
t('c2-: non-std port but small flow',
  c2({'Destination Port': 47074, 'Total Length of Fwd Packets': 1000,
      'Total Length of Bwd Packets': 2000, 'Total Backward Packets': 5,
      'Flow Duration': 1_000_000},
     '192.168.1.1', '8.8.8.8'),
  (None, None))

# Negative: Pattern B but fwd too big (normal keep-alive browsing)
t('c2-: normal browsing large fwd',
  c2({'Destination Port': 443, 'Total Length of Fwd Packets': 50_000,
      'Total Length of Bwd Packets': 2_000_000, 'Total Backward Packets': 500,
      'Flow Duration': 30_000_000},
     '192.168.1.1', '104.16.1.1'),
  (None, None))

# Negative: standard port, not HTTP (covered by benign-port exclusion)
t('c2-: standard port 443 small response',
  c2({'Destination Port': 443, 'Total Length of Fwd Packets': 5_000,
      'Total Length of Bwd Packets': 50_000, 'Total Backward Packets': 50,
      'Flow Duration': 5_000_000},
     '192.168.1.1', '8.8.8.8'),
  (None, None))

# Edge: Pattern A threshold exactly at the cutoff
t('c2+: exactly 50KB, 5s, non-std port',
  c2({'Destination Port': 47074, 'Total Length of Fwd Packets': 25_000,
      'Total Length of Bwd Packets': 25_000, 'Total Backward Packets': 20,
      'Flow Duration': 5_000_000},
     '192.168.1.1', '8.8.8.8'),
  ('Suspicious C2', 75.0))

# Edge: Pattern B threshold exactly at cutoff
t('c2+: exactly 500KB bwd, 200 pkts, 10s, 10KB fwd',
  c2({'Destination Port': 80, 'Total Length of Fwd Packets': 10_000,
      'Total Length of Bwd Packets': 500_000, 'Total Backward Packets': 200,
      'Flow Duration': 10_000_000},
     '192.168.1.1', '8.8.8.8'),
  ('Suspicious C2', 75.0))

passed = sum(1 for r in results if r[0])
failed = len(results) - passed
for ok, name, got, want in results:
    if ok:
        print(f'  PASS  {name}  → {got}')
    else:
        print(f'  FAIL  {name}  → got {got}, expected {want}')

print(f'\nHEURISTICS: {passed}/{len(results)} passed')
sys.exit(1 if failed else 0)
