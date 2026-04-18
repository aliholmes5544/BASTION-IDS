from scapy.all import *
import random

packets = []
t = 1712700000.0

# === 5 DDoS (ML detects correctly) ===
for i in range(5):
    src = f'10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'
    dst = '192.168.1.100'
    sp = random.randint(49152, 65535)
    st = t + i * 5
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='S', window=256, seq=100))
    packets[-1].time = st
    packets.append(IP(src=dst, dst=src)/TCP(sport=80, dport=sp, flags='SA', window=229, seq=200, ack=101))
    packets[-1].time = st + 0.003
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='A', window=256, seq=101, ack=201))
    packets[-1].time = st + 0.006
    for j in range(3):
        p = IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='A', window=256, seq=101+j*7, ack=201)/Raw(load=b'GET / H')
        p.time = st + 0.49 * (j + 1)
        packets.append(p)
    for j, sz in enumerate([5755, 1500, 548]):
        p = IP(src=dst, dst=src)/TCP(sport=80, dport=sp, flags='A', window=229, seq=201+j*sz, ack=122)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz)))
        p.time = st + 0.003 + 0.019 * (j + 1)
        packets.append(p)
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='A', window=256, seq=122, ack=9000)
    p.time = st + 1.88
    packets.append(p)

# === 5 PortScan (Rule: SYN probe, no payload, <=4 fwd, <=2 bwd) ===
for i in range(5):
    src = '172.16.0.10'
    dst = '192.168.1.100'
    sp = random.randint(49152, 65535)
    dport = random.choice([22, 443, 3306, 3690, 5432])
    st = t + 50 + i * 0.5
    # SYN probe (0 payload)
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=dport, flags='S', window=29200, seq=100))
    packets[-1].time = st
    # RST-ACK response (0 payload)
    packets.append(IP(src=dst, dst=src)/TCP(sport=dport, dport=sp, flags='RA', window=0, seq=0, ack=101))
    packets[-1].time = st + 0.000047

# === 5 FTP-Patator (Rule: port 21, TCP) ===
for i in range(5):
    src = f'172.16.1.{random.randint(1,254)}'
    dst = '192.168.1.200'
    sp = random.randint(49152, 65535)
    st = t + 100 + i * 2
    # SYN
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=21, flags='S', window=29200, seq=100))
    packets[-1].time = st
    # SYN-ACK
    packets.append(IP(src=dst, dst=src)/TCP(sport=21, dport=sp, flags='SA', window=227, seq=200, ack=101))
    packets[-1].time = st + 0.003
    # ACK
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=21, flags='A', window=29200, seq=101, ack=201))
    packets[-1].time = st + 0.006
    # FTP USER command
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=21, flags='PA', window=29200, seq=101, ack=201)/Raw(load=b'USER admin\r\n')
    p.time = st + 0.5
    packets.append(p)
    # FTP 331 response
    p = IP(src=dst, dst=src)/TCP(sport=21, dport=sp, flags='PA', window=227, seq=201, ack=113)/Raw(load=b'331 Password required\r\n')
    p.time = st + 0.51
    packets.append(p)
    # FTP PASS command
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=21, flags='PA', window=29200, seq=113, ack=223)/Raw(load=b'PASS test123\r\n')
    p.time = st + 1.0
    packets.append(p)
    # FTP 530 response
    p = IP(src=dst, dst=src)/TCP(sport=21, dport=sp, flags='PA', window=227, seq=223, ack=127)/Raw(load=b'530 Login incorrect\r\n')
    p.time = st + 1.01
    packets.append(p)

# === 5 SSH-Patator (Rule: port 22, >=2 fwd packets) ===
for i in range(5):
    src = f'172.16.2.{random.randint(1,254)}'
    dst = '192.168.1.200'
    sp = random.randint(49152, 65535)
    st = t + 200 + i * 10
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=22, flags='S', window=29200, seq=100))
    packets[-1].time = st
    packets.append(IP(src=dst, dst=src)/TCP(sport=22, dport=sp, flags='SA', window=247, seq=200, ack=101))
    packets[-1].time = st + 0.003
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=22, flags='A', window=29200, seq=101, ack=201))
    packets[-1].time = st + 0.006
    fwd_sizes = [640, 80, 80, 80, 80, 80, 80, 0, 0, 0, 0]
    seq = 101
    for j, sz in enumerate(fwd_sizes):
        if sz > 0:
            p = IP(src=src, dst=dst)/TCP(sport=sp, dport=22, flags='A', window=29200, seq=seq, ack=201)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz)))
            seq += sz
        else:
            p = IP(src=src, dst=dst)/TCP(sport=sp, dport=22, flags='A', window=29200, seq=seq, ack=201)
        p.time = st + 0.21 * (j + 1)
        packets.append(p)
    bwd_sizes = [976, 80, 80, 40, 40, 40, 40, 0, 0]
    bseq = 201
    for j, sz in enumerate(bwd_sizes):
        if sz > 0:
            p = IP(src=dst, dst=src)/TCP(sport=22, dport=sp, flags='A', window=247, seq=bseq, ack=seq)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz)))
            bseq += sz
        else:
            p = IP(src=dst, dst=src)/TCP(sport=22, dport=sp, flags='A', window=247, seq=bseq, ack=seq)
        p.time = st + 0.24 * (j + 1)
        packets.append(p)
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=22, flags='FA', window=29200, seq=seq, ack=bseq)
    p.time = st + 2.48
    packets.append(p)

# === 5 DoS GoldenEye (ML detects correctly) ===
for i in range(5):
    src = f'10.10.{random.randint(1,254)}.{random.randint(1,254)}'
    dst = '192.168.1.100'
    sp = random.randint(49152, 65535)
    st = t + 300 + i * 15
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='S', window=29200, seq=100))
    packets[-1].time = st
    packets.append(IP(src=dst, dst=src)/TCP(sport=80, dport=sp, flags='SA', window=235, seq=200, ack=101))
    packets[-1].time = st + 0.003
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='A', window=29200, seq=101, ack=201))
    packets[-1].time = st + 0.006
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='A', window=29200, seq=101, ack=201)/Raw(load=bytes(random.getrandbits(8) for _ in range(370)))
    p.time = st + 1.15
    packets.append(p)
    for j in range(3):
        p = IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='A', window=29200, seq=471+j, ack=201)
        p.time = st + 1.15 * (j + 2)
        packets.append(p)
    for j, sz in enumerate([3525, 400]):
        p = IP(src=dst, dst=src)/TCP(sport=80, dport=sp, flags='A', window=235, seq=201+j*sz, ack=474)/Raw(load=bytes(random.getrandbits(8) for _ in range(sz)))
        p.time = st + 1.16 + 2.27 * j
        packets.append(p)
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='FA', window=29200, seq=474, ack=4126)
    p.time = st + 11.59
    packets.append(p)

# === 5 DoS slowloris (Rule: port 80, small fwd max <=250, few bwd) ===
for i in range(5):
    src = f'10.20.{random.randint(1,254)}.{random.randint(1,254)}'
    dst = '192.168.1.100'
    sp = random.randint(49152, 65535)
    st = t + 500 + i * 5
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='S', window=29200, seq=100))
    packets[-1].time = st
    packets.append(IP(src=dst, dst=src)/TCP(sport=80, dport=sp, flags='SA', window=28960, seq=200, ack=101))
    packets[-1].time = st + 0.003
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='A', window=29200, seq=101, ack=201))
    packets[-1].time = st + 0.006
    # 3 tiny partial HTTP headers (8 bytes each — classic slowloris)
    seq = 101
    for j in range(3):
        p = IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='PA', window=29200, seq=seq, ack=201)/Raw(load=b'X-a: b\r\n')
        seq += 8
        p.time = st + 7.0 * (j + 1)
        packets.append(p)
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=80, flags='FA', window=29200, seq=seq, ack=201)
    p.time = st + 97.0
    packets.append(p)

# === 5 Bot (Rule: port >=8000, <=5 fwd+bwd) ===
for i in range(5):
    src = f'192.168.10.{random.randint(1,254)}'
    dst = '10.0.0.1'
    sp = random.randint(49152, 65535)
    st = t + 600 + i * 2
    # C2 beacon: SYN to port 8080
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=8080, flags='S', window=237, seq=100))
    packets[-1].time = st
    # SYN-ACK
    packets.append(IP(src=dst, dst=src)/TCP(sport=8080, dport=sp, flags='SA', window=110, seq=200, ack=101))
    packets[-1].time = st + 0.003
    # ACK
    packets.append(IP(src=src, dst=dst)/TCP(sport=sp, dport=8080, flags='A', window=237, seq=101, ack=201))
    packets[-1].time = st + 0.006
    # Small beacon data
    p = IP(src=src, dst=dst)/TCP(sport=sp, dport=8080, flags='A', window=237, seq=101, ack=201)/Raw(load=b'PING')
    p.time = st + 0.03
    packets.append(p)
    p = IP(src=dst, dst=src)/TCP(sport=8080, dport=sp, flags='A', window=110, seq=201, ack=105)/Raw(load=b'PONG')
    p.time = st + 0.05
    packets.append(p)

packets.sort(key=lambda p: p.time)
wrpcap('test_all_attacks.pcap', packets)
print(f'Created test_all_attacks.pcap: {len(packets)} packets')
print('  5 DDoS | 5 PortScan | 5 FTP-Patator | 5 SSH-Patator')
print('  5 DoS GoldenEye | 5 DoS slowloris | 5 Bot')
print('  Total: 35 flows')
