# HSRPForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for enterprise campus network engineers, infrastructure architects, and NetDevOps teams deploying Zero-Trust First-Hop Redundancy Protocol (HSRPv1 & HSRPv2).**

---

## 1\. Quickstart: Web Application Studio

The **HSRPForge Pro Web Studio** is 100% client-side and requires zero installation or external dependencies. Open `source-code/index.html` directly in any web browser:

\# Optional local web server

cd product\_123/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Industry Presets**:  
   - **Campus Core HSRPv2 MD5 (Grade A+)**: Complete Zero-Trust campus gateway with HSRPv2, MD5 authentication, 180s preempt delay, object tracking, and BFD.  
   - **Data Center MHSRP Active/Active (Grade A+)**: Multi-Group HSRP distributing traffic evenly across paired distribution switches.  
   - **Vulnerable Cleartext No Delay (Grade F)**: Insecure baseline exposing missing preempt delay (instant blackhole), cleartext default password, and missing object tracking.  
2. **HSRP Protocol Parameters**: Configure Protocol Version (v1 vs v2), Group Number (0–4095), Priority (0–255), Current State (Active, Standby, Speak, Listen, Initial), Virtual IP, and Authentication.  
3. **Deterministic Virtual MAC Display**: Displays exact calculated Cisco Virtual MAC address (`0000.0c07.acXX` for v1, `0000.0c9f.fXXX` for v2).  
4. **Preempt Delay Blackhole Simulator**: Calculates exact outage seconds and dropped packets based on core routing convergence time vs configured preempt delay.  
5. **Dual-Active Split-Brain Detector**: Real-time diagnostic assessing inter-switch trunk status, version compatibility, and authentication synchronization.  
6. **10-Point Zero-Trust Scorecard**: Real-time compliance rating (0–100%, Grades A+ to F) with actionable remediation instructions.  
7. **Wireshark Hex Dissector**: Monospace byte-aligned hex dump with 1-click clipboard export and binary `.pcap` capture file generation.  
8. **Multi-Platform Synthesizer**: Instant production configuration generation for Cisco IOS-XE (Catalyst 9000), Cisco NX-OS (Nexus), Arista EOS (VARP), Linux Keepalived, and Prometheus alerting rules.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/hsrpforge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/hsrpforge-cli.py \--dissect

### 2.2 Calculating Deterministic Virtual MAC Address

\# Calculate Virtual MAC for HSRPv2 Group 100

./build/hsrpforge-cli.py \--vmac

### 2.3 Simulating Preempt Delay Blackhole Outages

\# Inspect vulnerable preset (0s delay, 90s IGP convergence)

./build/hsrpforge-cli.py \--preset build/presets/vulnerable-cleartext-no-delay.json \--preempt

\# Inspect hardened campus core preset (180s delay)

./build/hsrpforge-cli.py \--preset build/presets/campus-core-hsrpv2-md5.json \--preempt

### 2.4 Running 10-Point Zero-Trust FHRP Audits

./build/hsrpforge-cli.py \--preset build/presets/campus-core-hsrpv2-md5.json \--audit

### 2.5 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing network decoders or validating with Wireshark:

./build/hsrpforge-cli.py \--preset build/presets/campus-core-hsrpv2-md5.json \--pcap campus-hsrp.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-n \-r campus-hsrp.pcap

### 2.6 Automated CI/CD Pipeline Gating (`--strict`)

Integrate HSRPForge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit First-Hop Redundancy Security & Preempt Delay

  run: |

    python3 build/hsrpforge-cli.py \\

      \--preset build/presets/production-hsrp.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and zero reload blackhole. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or reload blackhole detected. Pipeline halts.*

---

## 3\. Production Hardening & Configuration Guide

### 3.1 Cisco IOS-XE Catalyst 9000 Hardened Configuration

track 100 interface GigabitEthernet0/0/0 line-protocol

track 200 ip route 0.0.0.0/0 reachability

interface Vlan100

 description GATEWAY-CAMPUS-VLAN-100

 ip address 10.100.0.2 255.255.255.0

 no ip redirects

 standby version 2

 standby 100 ip 10.100.0.1

 standby 100 priority 110

 standby 100 preempt delay minimum 180

 standby 100 timers msec 250 msec 750

 standby bfd

 standby 100 authentication md5 key-string CampusCore\$HSRP2026

 standby 100 track 100 decrement 30

 standby 100 track 200 decrement 30

---

## 4\. Troubleshooting & High-Impact Failure Modes

1. **Catastrophic Outage on Core Switch Reboot (Preempt Delay Blackhole)**:  
   - *Cause*: Preempt is enabled without delay (`preempt delay minimum <seconds>`). The primary switch seizes the active gateway role immediately upon boot while its OSPF/BGP uplinks are still synchronizing.  
   - *Resolution*: Configure `standby <group> preempt delay minimum 180`.  
2. **Dual-Active Split-Brain & MAC Flapping**:  
   - *Cause*: Inter-switch trunk link failure or mismatched HSRP versions (v1 vs v2). Both switches transition to ACTIVE and reply to ARP with identical Virtual MACs.  
   - *Resolution*: Restore inter-switch trunk, verify `standby version 2` on both routers, and synchronize MD5 authentication keys.  
3. **Blackholing on Uplink WAN Cut**:  
   - *Cause*: Missing Object Tracking. The active router loses its upstream WAN link, but remains ACTIVE because its downlink to users is still up.  
   - *Resolution*: Configure `track 100 interface <WAN> line-protocol` and `standby <group> track 100 decrement 30`.  
4. **Slow 10-Second Convergence**:  
   - *Cause*: Default timers (3s Hello / 10s Hold).  
   - *Resolution*: Configure millisecond timers (`timers msec 250 msec 750`) or enable BFD (`standby bfd`).