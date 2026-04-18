"""
Generate a CSV of genuine DoS Hulk flows (single-source HTTP flood).
Each flow: one attacker IP pounding one victim on port 80 with 50+
HTTP requests, Init_Win=256 (Hulk tool signature), ~35 pps.

Triggers BASTION's dos_hulk rule (port 80 + Init_Win 200-300 +
fwd_packets >= 30 + Flow Packets/s >= 20).
"""
import csv
import random

ATTACKER = '198.51.100.77'   # TEST-NET-2 (RFC 5737)
VICTIM   = '203.0.113.10'    # TEST-NET-3 (RFC 5737)
N_FLOWS  = 30

COLS = [
    'Bwd Packet Length Std','Packet Length Variance','Bwd Packet Length Mean',
    'Packet Length Std','Avg Bwd Segment Size','Total Length of Bwd Packets',
    'Subflow Bwd Bytes','Bwd Packet Length Max','Subflow Fwd Bytes',
    'Max Packet Length','Total Length of Fwd Packets','Fwd Packet Length Max',
    'Avg Fwd Segment Size','Average Packet Size','Fwd IAT Std',
    'Total Fwd Packets','Packet Length Mean','Destination Port',
    'Subflow Fwd Packets','Fwd Packet Length Mean','Fwd Packet Length Std',
    'Flow IAT Max','act_data_pkt_fwd','Fwd Header Length.1','Bwd Header Length',
    'Idle Mean','min_seg_size_forward','Fwd Header Length','Flow Bytes/s',
    'Init_Win_bytes_backward','Flow IAT Std','Init_Win_bytes_forward',
    'Idle Min','PSH Flag Count','Fwd IAT Mean','Subflow Bwd Packets',
    'Fwd IAT Min','Flow Packets/s','Fwd Packets/s','Bwd Packets/s',
    'ACK Flag Count','Fwd IAT Max','Total Backward Packets','Idle Max',
    'Fwd IAT Total','Flow Duration','Flow IAT Mean','Bwd IAT Max',
    'Bwd Packet Length Min','Fwd Packet Length Min','Min Packet Length',
    'Flow IAT Min','Bwd IAT Mean','URG Flag Count','FIN Flag Count',
    'Active Min','Bwd IAT Total','Bwd IAT Min','Active Max','Active Mean',
    'Bwd IAT Std','Down/Up Ratio','Protocol','Active Std','Idle Std',
    'SYN Flag Count','Fwd PSH Flags','Fwd URG Flags','CWE Flag Count',
    'ECE Flag Count','Source IP','Destination IP','Source Port',
]

def make_flow(src_port: int) -> dict:
    fwd_pkts   = random.randint(45, 65)     # >= 30 -> triggers dos_hulk
    bwd_pkts   = random.randint(1, 2)       # victim overwhelmed: minimal response
    duration   = random.randint(1_200_000, 1_800_000)  # 1.2-1.8 s
    fwd_len_max  = random.randint(280, 340)
    fwd_len_min  = random.randint(60, 90)
    fwd_len_mean = (fwd_len_max + fwd_len_min) / 2
    fwd_bytes    = int(fwd_len_mean * fwd_pkts)
    bwd_len_max  = random.randint(100, 250)  # small responses (RST, partial)
    bwd_len_mean = bwd_len_max // 2
    bwd_bytes    = bwd_len_mean * bwd_pkts   # < 1000 so sanity filter won't demote
    pps = (fwd_pkts + bwd_pkts) / (duration / 1_000_000)

    return {
        'Bwd Packet Length Std':       random.uniform(400, 600),
        'Packet Length Variance':      random.uniform(150_000, 250_000),
        'Bwd Packet Length Mean':      bwd_len_mean,
        'Packet Length Std':           random.uniform(350, 500),
        'Avg Bwd Segment Size':        bwd_len_mean,
        'Total Length of Bwd Packets': bwd_bytes,
        'Subflow Bwd Bytes':           bwd_bytes,
        'Bwd Packet Length Max':       bwd_len_max,
        'Subflow Fwd Bytes':           fwd_bytes,
        'Max Packet Length':           max(fwd_len_max, bwd_len_max),
        'Total Length of Fwd Packets': fwd_bytes,
        'Fwd Packet Length Max':       fwd_len_max,
        'Avg Fwd Segment Size':        fwd_len_mean,
        'Average Packet Size':         (fwd_bytes + bwd_bytes) / (fwd_pkts + bwd_pkts),
        'Fwd IAT Std':                 random.uniform(20_000, 40_000),
        'Total Fwd Packets':           fwd_pkts,
        'Packet Length Mean':          (fwd_bytes + bwd_bytes) / (fwd_pkts + bwd_pkts),
        'Destination Port':            80,
        'Subflow Fwd Packets':         fwd_pkts,
        'Fwd Packet Length Mean':      fwd_len_mean,
        'Fwd Packet Length Std':       random.uniform(60, 100),
        'Flow IAT Max':                random.uniform(90_000, 150_000),
        'act_data_pkt_fwd':            fwd_pkts - 2,   # minus SYN/ACK handshake
        'Fwd Header Length.1':         fwd_pkts * 32,
        'Bwd Header Length':           bwd_pkts * 32,
        'Idle Mean':                   0,
        'min_seg_size_forward':        32,
        'Fwd Header Length':           fwd_pkts * 32,
        'Flow Bytes/s':                (fwd_bytes + bwd_bytes) / (duration / 1_000_000),
        'Init_Win_bytes_backward':     229,
        'Flow IAT Std':                random.uniform(15_000, 35_000),
        'Init_Win_bytes_forward':      256,            # Hulk signature
        'Idle Min':                    0,
        'PSH Flag Count':              fwd_pkts - 2,
        'Fwd IAT Mean':                duration / fwd_pkts,
        'Subflow Bwd Packets':         bwd_pkts,
        'Fwd IAT Min':                 random.uniform(5_000, 15_000),
        'Flow Packets/s':              pps,
        'Fwd Packets/s':               fwd_pkts / (duration / 1_000_000),
        'Bwd Packets/s':               bwd_pkts / (duration / 1_000_000),
        'ACK Flag Count':              fwd_pkts + bwd_pkts - 1,
        'Fwd IAT Max':                 random.uniform(100_000, 160_000),
        'Total Backward Packets':      bwd_pkts,
        'Idle Max':                    0,
        'Fwd IAT Total':               duration,
        'Flow Duration':               duration,
        'Flow IAT Mean':               duration / (fwd_pkts + bwd_pkts),
        'Bwd IAT Max':                 duration // 2,
        'Bwd Packet Length Min':       random.randint(60, 100),
        'Fwd Packet Length Min':       fwd_len_min,
        'Min Packet Length':           min(fwd_len_min, 60),
        'Flow IAT Min':                random.uniform(1_000, 10_000),
        'Bwd IAT Mean':                duration / bwd_pkts,
        'URG Flag Count':              0,
        'FIN Flag Count':              1,
        'Active Min':                  0,
        'Bwd IAT Total':               duration,
        'Bwd IAT Min':                 random.uniform(1_000, 5_000),
        'Active Max':                  0,
        'Active Mean':                 0,
        'Bwd IAT Std':                 random.uniform(10_000, 30_000),
        'Down/Up Ratio':               bwd_pkts / fwd_pkts,
        'Protocol':                    6,
        'Active Std':                  0,
        'Idle Std':                    0,
        'SYN Flag Count':              2,     # handshake only
        'Fwd PSH Flags':               fwd_pkts - 2,
        'Fwd URG Flags':               0,
        'CWE Flag Count':              0,
        'ECE Flag Count':              0,
        'Source IP':                   ATTACKER,
        'Destination IP':              VICTIM,
        'Source Port':                 src_port,
    }

def write_pcap():
    """Emit a matching PCAP so BASTION's PCAP rule engine sees real packets."""
    try:
        from scapy.all import IP, TCP, Raw, wrpcap
    except ImportError:
        print('scapy not installed, skipping PCAP output')
        return
    packets = []
    t = 1712700000.0
    for i in range(N_FLOWS):
        sp = random.randint(49152, 65535)
        flow_start = t + i * 2.0
        fwd_pkts = random.randint(45, 65)
        duration = random.uniform(1.2, 1.8)
        pkt_interval = duration / fwd_pkts
        packets.append(IP(src=ATTACKER, dst=VICTIM) /
                       TCP(sport=sp, dport=80, flags='S', window=256, seq=100))
        packets[-1].time = flow_start
        packets.append(IP(src=VICTIM, dst=ATTACKER) /
                       TCP(sport=80, dport=sp, flags='SA', window=229, seq=200, ack=101))
        packets[-1].time = flow_start + 0.001
        packets.append(IP(src=ATTACKER, dst=VICTIM) /
                       TCP(sport=sp, dport=80, flags='A', window=256, seq=101, ack=201))
        packets[-1].time = flow_start + 0.002
        seq = 101
        for j in range(fwd_pkts - 2):
            payload_len = random.randint(150, 320)
            p = (IP(src=ATTACKER, dst=VICTIM) /
                 TCP(sport=sp, dport=80, flags='PA', window=256, seq=seq, ack=201) /
                 Raw(load=b'G' * payload_len))
            p.time = flow_start + 0.003 + (j + 1) * pkt_interval
            packets.append(p)
            seq += payload_len
        p = (IP(src=VICTIM, dst=ATTACKER) /
             TCP(sport=80, dport=sp, flags='R', window=0, seq=201, ack=seq))
        p.time = flow_start + duration
        packets.append(p)
    packets.sort(key=lambda p: p.time)
    wrpcap('test_real_dos_hulk.pcap', packets)
    print(f'Wrote test_real_dos_hulk.pcap: {len(packets)} packets / {N_FLOWS} flows')

def main():
    random.seed(42)
    with open('test_real_dos_hulk.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for _ in range(N_FLOWS):
            w.writerow(make_flow(random.randint(49152, 65535)))
    print(f'Wrote test_real_dos_hulk.csv: {N_FLOWS} single-source DoS Hulk flows')
    print(f'  attacker {ATTACKER} -> victim {VICTIM}:80')
    print(f'  ~50 fwd packets/flow, Init_Win=256, ~35 pps')
    write_pcap()

if __name__ == '__main__':
    main()
