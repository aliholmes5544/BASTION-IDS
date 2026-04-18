"""Phase 2: every rule with a POS case (must fire) and a NEG case (must not fire)."""
import ast, re, sys, ipaddress

src = open('app.py', encoding='utf-8').read()
tree = ast.parse(src)
wanted = {
    'is_private_ip', '_BENIGN_SERVICE_PORTS', '_C2_BENIGN_PORTS',
    'ml_sanity_check', 'suspicious_c2_check', '_RULE_THRESHOLDS_LIST',
    '_RULE_LABELS', '_rule_check', 'rule_based_label', 'SEVERITY',
    'get_severity', 'clean_label',
}
pieces = []
for n in tree.body:
    if isinstance(n, ast.FunctionDef) and n.name in wanted:
        pieces.append(ast.get_source_segment(src, n))
    elif isinstance(n, ast.Assign):
        if any(isinstance(t, ast.Name) and t.id in wanted for t in n.targets):
            pieces.append(ast.get_source_segment(src, n))
ns = {'ipaddress': ipaddress}
exec('\n\n'.join(pieces), ns)
RB = ns['rule_based_label']

cases = []  # (name, row, expected_label_or_None)

# 1. ftp_patator
cases += [
    ('ftp_patator POS: port 21, 3+ fwd, 2 PSH, real cmds',
     {'Destination Port': 21, 'Protocol': 6, 'Total Fwd Packets': 4,
      'PSH Flag Count': 2, 'Fwd Packet Length Max': 12},  'FTP-Patator'),
    ('ftp_patator NEG: port 21 but no PSH (passive handshake)',
     {'Destination Port': 21, 'Protocol': 6, 'Total Fwd Packets': 3,
      'PSH Flag Count': 0, 'Fwd Packet Length Max': 0},  None),
    ('ftp_patator NEG: port 21 but too few fwd (just SYN)',
     {'Destination Port': 21, 'Protocol': 6, 'Total Fwd Packets': 1,
      'PSH Flag Count': 5, 'Fwd Packet Length Max': 50},  None),
]

# 2. ssh_patator
cases += [
    ('ssh_patator POS: port 22, 5+ fwd, 3+ bwd, big fwd',
     {'Destination Port': 22, 'Protocol': 6, 'Total Fwd Packets': 10,
      'Total Backward Packets': 5, 'Fwd Packet Length Max': 640}, 'SSH-Patator'),
    ('ssh_patator NEG: port 22 but tiny fwd (scan probe)',
     {'Destination Port': 22, 'Protocol': 6, 'Total Fwd Packets': 1,
      'Total Backward Packets': 1, 'Fwd Packet Length Max': 0,
      'SYN Flag Count': 1, 'Total Length of Fwd Packets': 0}, 'PortScan'),  # falls to portscan
    ('ssh_patator NEG: port 22 with 5 fwd but <80B max payload',
     {'Destination Port': 22, 'Protocol': 6, 'Total Fwd Packets': 6,
      'Total Backward Packets': 4, 'Fwd Packet Length Max': 50}, None),
]

# 3. bot
cases += [
    ('bot POS: port 8080, tiny beacons, 1s flow',
     {'Destination Port': 8080, 'Protocol': 6, 'Total Fwd Packets': 3,
      'Total Backward Packets': 2, 'Fwd Packet Length Max': 5,
      'Flow Duration': 1_000_000}, 'Bot'),
    ('bot NEG: port 49000 (Windows ephemeral, out of range)',
     {'Destination Port': 49000, 'Protocol': 6, 'Total Fwd Packets': 3,
      'Total Backward Packets': 2, 'Fwd Packet Length Max': 5,
      'Flow Duration': 1_000_000}, None),
    ('bot NEG: port 8080 but big payload (normal HTTP-alt)',
     {'Destination Port': 8080, 'Protocol': 6, 'Total Fwd Packets': 3,
      'Total Backward Packets': 2, 'Fwd Packet Length Max': 500,
      'Flow Duration': 1_000_000}, None),
]

# 4. ddos (SYN flood)
cases += [
    ('ddos POS: SYN>=5, lopsided, fast',
     {'SYN Flag Count': 10, 'Total Backward Packets': 1,
      'Total Fwd Packets': 20, 'Flow Packets/s': 50}, 'DDoS'),
    ('ddos NEG: SYN=3 only (normal retransmit)',
     {'SYN Flag Count': 3, 'Total Backward Packets': 1,
      'Total Fwd Packets': 20, 'Flow Packets/s': 50}, None),
    ('ddos NEG: SYN=10 but slow rate',
     {'SYN Flag Count': 10, 'Total Backward Packets': 1,
      'Total Fwd Packets': 20, 'Flow Packets/s': 5}, None),
]

# 5. ddos_http (distributed HTTP)
cases += [
    ('ddos_http POS: port 80, Init_Win 256, 6 fwd',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 256,
      'Total Fwd Packets': 6}, 'DDoS'),
    ('ddos_http NEG: port 80, Init_Win 64240 (normal Windows)',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 64240,
      'Total Fwd Packets': 6}, None),
    ('ddos_http NEG: port 80, Init_Win 256 but 50 fwd → dos_hulk territory',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 256,
      'Total Fwd Packets': 50, 'Flow Packets/s': 30}, 'DoS Hulk'),
]

# 6. dos_hulk (single-source flood)
cases += [
    ('dos_hulk POS: port 80, Init_Win 256, 50 fwd, 30 pps',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 256,
      'Total Fwd Packets': 50, 'Flow Packets/s': 30}, 'DoS Hulk'),
    ('dos_hulk NEG: 30 fwd but low pps',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 256,
      'Total Fwd Packets': 35, 'Flow Packets/s': 5}, None),
    ('dos_hulk NEG: 50 fwd but Init_Win out of range',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 5000,
      'Total Fwd Packets': 50, 'Flow Packets/s': 30}, None),
]

# 7. web_brute
cases += [
    ('web_brute POS: port 80, PSH 10, 12 fwd, normal Init_Win',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 64240,
      'PSH Flag Count': 10, 'Total Fwd Packets': 12,
      'Total Backward Packets': 2}, 'Web Attack Brute Force'),
    ('web_brute NEG: same but attack-tool Init_Win → dos_hulk fires first',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 256,
      'PSH Flag Count': 10, 'Total Fwd Packets': 50,
      'Total Backward Packets': 2, 'Flow Packets/s': 30}, 'DoS Hulk'),
    ('web_brute NEG: few fwd packets',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 64240,
      'PSH Flag Count': 10, 'Total Fwd Packets': 5,
      'Total Backward Packets': 2}, None),
]

# 8. dos_slowloris
cases += [
    ('dos_slowloris POS: tiny fwd, no bwd data, long duration',
     {'Destination Port': 80, 'Protocol': 6, 'Fwd Packet Length Max': 8,
      'Total Fwd Packets': 6, 'Total Backward Packets': 1,
      'Bwd Packet Length Max': 0, 'Flow Duration': 97_000_000}, 'DoS slowloris'),
    ('dos_slowloris NEG: same but short duration (failed HTTP)',
     {'Destination Port': 80, 'Protocol': 6, 'Fwd Packet Length Max': 8,
      'Total Fwd Packets': 6, 'Total Backward Packets': 1,
      'Bwd Packet Length Max': 0, 'Flow Duration': 2_000_000}, None),
    ('dos_slowloris NEG: bwd has data (normal browse)',
     {'Destination Port': 80, 'Protocol': 6, 'Fwd Packet Length Max': 8,
      'Total Fwd Packets': 6, 'Total Backward Packets': 1,
      'Bwd Packet Length Max': 1460, 'Flow Duration': 97_000_000}, None),
]

# 9. dos_goldeneye
cases += [
    ('dos_goldeneye POS: Init_Win 29200, fwd 6, max 370, dur 12s',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 29200,
      'Total Fwd Packets': 6, 'Fwd Packet Length Max': 370,
      'Flow Duration': 12_000_000}, 'DoS GoldenEye'),
    ('dos_goldeneye NEG: Init_Win 29200 but tiny payload',
     {'Destination Port': 80, 'Protocol': 6, 'Init_Win_bytes_forward': 29200,
      'Total Fwd Packets': 6, 'Total Backward Packets': 3,
      'Fwd Packet Length Max': 100, 'Flow Duration': 12_000_000}, None),
]

# 10. dos_slowhttp
cases += [
    ('dos_slowhttp POS: long duration, no bwd',
     {'Destination Port': 80, 'Protocol': 6, 'Flow Duration': 20_000_000,
      'Total Backward Packets': 0, 'Total Fwd Packets': 5}, 'DoS Slowhttptest'),
    ('dos_slowhttp NEG: short duration',
     {'Destination Port': 80, 'Protocol': 6, 'Flow Duration': 3_000_000,
      'Total Backward Packets': 0, 'Total Fwd Packets': 5}, None),
]

# 11. portscan
cases += [
    ('portscan POS: 1 SYN, 0 payload',
     {'Total Fwd Packets': 1, 'SYN Flag Count': 1,
      'Total Backward Packets': 1, 'Fwd Packet Length Max': 0,
      'Total Length of Fwd Packets': 0}, 'PortScan'),
    ('portscan NEG: 2 fwd but has payload',
     {'Total Fwd Packets': 2, 'SYN Flag Count': 1,
      'Total Backward Packets': 1, 'Fwd Packet Length Max': 100,
      'Total Length of Fwd Packets': 100}, None),
    ('portscan NEG: 4 fwd (too many)',
     {'Total Fwd Packets': 4, 'SYN Flag Count': 1,
      'Total Backward Packets': 1, 'Fwd Packet Length Max': 0,
      'Total Length of Fwd Packets': 0}, None),
]

# Totally benign — no rule fires
cases += [
    ('BENIGN NEG: HTTPS session',
     {'Destination Port': 443, 'Protocol': 6,
      'Init_Win_bytes_forward': 64240, 'Total Fwd Packets': 10,
      'Total Backward Packets': 10, 'Flow Duration': 500_000}, None),
    ('BENIGN NEG: short HTTP',
     {'Destination Port': 80, 'Protocol': 6,
      'Init_Win_bytes_forward': 64240, 'Total Fwd Packets': 3,
      'Total Backward Packets': 3, 'Fwd Packet Length Max': 800,
      'Bwd Packet Length Max': 1460, 'Flow Duration': 300_000}, None),
]

passed = failed = 0
for name, row, expected in cases:
    got = RB(row)
    got_label = got[0] if got else None
    ok = (got_label == expected)
    if ok:
        passed += 1
        print(f'  PASS  {name}  ({got_label})')
    else:
        failed += 1
        print(f'  FAIL  {name}  → got {got_label}, expected {expected}')
        print(f'        row={row}')

print(f'\nRULE ENGINE: {passed}/{passed+failed} passed')
sys.exit(1 if failed else 0)
