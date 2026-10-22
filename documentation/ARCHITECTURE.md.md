# HSRPForge Pro \- Architecture & Technical Specification

> **Cisco RFC 2281 (HSRPv1), RFC 7868 (HSRPv2), Deterministic Virtual MAC Generation & Preempt Delay Blackhole Architecture**

---

## 1\. Executive Summary & Protocol Overview

The **Hot Standby Router Protocol (HSRP / IETF RFC 2281 & RFC 7868\)** is Cisco's premier First-Hop Redundancy Protocol (FHRP) deployed across hundreds of thousands of enterprise campus LANs, healthcare networks, financial institutions, and data centers worldwide.

HSRP provides transparent Layer 3 default gateway redundancy by grouping two or more physical routers into a single **Virtual Router** sharing a **Virtual IP (VIP)** and a deterministic **Virtual MAC (VMAC)** address. Hosts configure the single VIP as their default gateway, remaining unaffected when physical distribution switches fail.

\+-----------------------------------------------------------------------------------------+

|                                HSRP ARCHITECTURAL OVERVIEW                              |

\+--------------------------+---------------------------------------+----------------------+

| Domain                   | Standard Mechanism                    | Operational Impact   |

\+--------------------------+---------------------------------------+----------------------+

| Layer 3 Transport        | HSRPv1: UDP 1985 (224.0.0.2)          | Local subnet         |

|                          | HSRPv2: UDP 2026 (224.0.0.102)        | multicast exchange.  |

\+--------------------------+---------------------------------------+----------------------+

| State Machine            | Initial \-\> Learn \-\> Listen \-\>         | Deterministic active |

|                          | Speak \-\> Standby \-\> Active            | gateway election.    |

\+--------------------------+---------------------------------------+----------------------+

| Reload Blackhole Trap    | Preempt without Delay                 | Seizes VIP before    |

|                          | Active before IGP/BGP converges       | core routes exist\!   |

\+--------------------------+---------------------------------------+----------------------+

| Split-Brain Hazard       | Inter-Switch Trunk / Peer-Link Cut    | Both routers Active; |

|                          | Dual-Active MAC flap storm            | resets TCP sessions. |

\+--------------------------+---------------------------------------+----------------------+

| Sub-Second Failover      | BFD for HSRP / Millisecond Timers     | Sub-500ms failover   |

|                          | (e.g. 250ms Hello / 750ms Hold)       | vs 10s default.      |

\+--------------------------+---------------------------------------+----------------------+

---

## 2\. HSRPv1 (RFC 2281\) vs HSRPv2 Protocol Comparison

\+-----------------------------+-------------------------------+-------------------------------+

| Protocol Attribute          | HSRP Version 1 (RFC 2281\)     | HSRP Version 2 (RFC 7868\)     |

\+-----------------------------+-------------------------------+-------------------------------+

| Transport UDP Port          | UDP 1985                      | UDP 2026                      |

| Multicast Destination IP    | 224.0.0.2 (All-Routers)       | 224.0.0.102 (Dedicated HSRP)  |

| Supported Group Range       | 0 – 255 (8-bit)               | 0 – 4095 (12-bit, matches VLAN|

| Virtual MAC Address Base    | 00:00:0c:07:ac:XX             | 00:00:0c:9f:fX:XX             |

| Timer Granularity           | Seconds only                  | Milliseconds (64-bit TLVs)    |

| Packet Format               | Fixed 20-octet binary struct  | Type-Length-Value (TLV) 40B+  |

| Router Identification       | Source IP address             | 6-octet Physical B-MAC ID     |

| IPv6 Support                | No (IPv4 only)                | Yes (HSRP for IPv6)           |

\+-----------------------------+-------------------------------+-------------------------------+

### 2.1 Deterministic Virtual MAC Derivation

- **HSRPv1**: \$\$\\text{VMAC} \= \\text{00:00:0c:07:ac:}\\mathbf{XX} \\quad (\\mathbf{XX} \= \\text{Group Number in 2-digit Hex})\$\$ *Example*: Group 1 \$\\implies\$ `00:00:0c:07:ac:01`. Group 100 \$\\implies\$ `00:00:0c:07:ac:64`.  
- **HSRPv2**: \$\$\\text{VMAC} \= \\text{00:00:0c:9f:f}\\mathbf{X:XX} \\quad (\\mathbf{X:XX} \= \\text{Group Number in 3-digit Hex})\$\$ *Example*: Group 100 \$\\implies\$ `00:00:0c:9f:f0:64`. Group 1000 \$\\implies\$ `00:00:0c:9f:f3:e8`.

---

## 3\. The Preempt Delay Blackhole Trap

The single most common cause of multi-minute campus LAN outages during scheduled maintenance is **HSRP Preemption without Minimum Delay**:

\[ Core / WAN Routers \] \<--- OSPF / BGP (takes 45-90s to converge)

        |

   \+----+----+

   |         |

\[ Dist-A \] \[ Dist-B \]

 (Active)   (Standby)

   |         |

   \+----+----+

        |

  \[ Access Switches \]

        |

   \[ User Clients \]

### 3.1 The Outage Sequence

1. Primary switch `Dist-A` reboots following a software upgrade or power event.  
2. Downlink switchports transition to Spanning Tree Forwarding.  
3. If `standby <group> preempt` is configured **without delay**, `Dist-A` immediately sends an HSRP Coup/Hello with priority 110, preempting `Dist-B` and assuming the `ACTIVE` role.  
4. `Dist-A` broadcasts Gratuitous ARPs for the Virtual IP and Virtual MAC.  
5. All downstream access switches update their CAM tables to point gateway traffic to `Dist-A`.  
6. **The Blackhole**: While `Dist-A`'s downlinks are up, its upstream core links, OSPF/EIGRP/BGP sessions, and default routes take **45 to 90 seconds** to establish\!  
7. `Dist-A` receives gigabits of client traffic but has **no upstream routes** in its FIB \$\\implies\$ **100% of campus client traffic is dropped\!**

### 3.2 Mathematical Derivation of Dropped Packets

\$\$T\_{\\text{blackhole}} \= \\max\\left(0, , T\_{\\text{IGP\_converge}} \- T\_{\\text{preempt\_delay}}\\right)\$\$ \$\$\\text{Dropped Packets} \= T\_{\\text{blackhole}} \\times \\left( \\frac{\\text{Traffic Rate (bps)}}{\\text{Avg Packet Size (bytes)} \\times 8} \\right)\$\$

*Example*: At 1 Gbps traffic rate, a 90-second convergence window drops **11.25 million packets** (90 Gigabits of data)\!

### 3.3 Zero-Trust Remediation

Always configure:

standby \<group\> preempt delay minimum 180

This forces the rebooted router to wait in `STANDBY` state for 3 full minutes, allowing all routing tables to settle before assuming active forwarding.

---

## 4\. Dual-Active Split-Brain Hazards

When the trunk link between redundant distribution switches fails or becomes unidirectionally blocked:

1. `Dist-A` and `Dist-B` stop receiving each other's Hellos.  
2. `Dist-B`'s hold timer expires (10 seconds), and it transitions from `STANDBY` to `ACTIVE`.  
3. Both switches become `ACTIVE` for the identical Virtual IP and Virtual MAC.  
4. Downstream access switches receive frames sourced from the same Virtual MAC on two different uplinks, triggering **continuous CAM table flapping**.  
5. Asymmetric return traffic causes stateful firewalls to drop TCP connections with `SYN-ACK` or `RST` out-of-order errors.

**Mitigation**:

- Maintain redundant Layer 2 trunk links across distinct physical ASIC line cards.  
- Implement an out-of-band Layer 3 keepalive link.

---

## 5\. Enhanced Object Tracking & Multi-Group HSRP (MHSRP)

### 5.1 Object Tracking

If `Dist-A` loses its WAN uplink, its downlink to users remains up. Without tracking, `Dist-A` remains ACTIVE, blackholing traffic.

- Enhanced Object Tracking monitors the uplink interface or default route:  
    
  track 100 interface GigabitEthernet0/0/0 line-protocol  
    
  standby 100 track 100 decrement 30  
    
- Priority drops from `110` to `80`, falling below `Dist-B`'s priority of `100`, triggering clean preemption to `Dist-B`.

### 5.2 Multi-Group HSRP (MHSRP) Active/Active

- **VLAN 10**: `Dist-A` Priority 110 (Active), `Dist-B` Priority 100 (Standby).  
- **VLAN 20**: `Dist-B` Priority 110 (Active), `Dist-A` Priority 100 (Standby).  
- Utilizes 100% of available distribution switch bandwidth.

---

## 6\. 10-Point Zero-Trust FHRP (HSRP) Audit Framework

| Control ID | Evaluation Domain | Weight | Standards Baseline |
| :---- | :---- | :---: | :---- |
| **HSRP-SEC-01** | Cryptographic MD5 / Key-Chain Authentication | 15 pts | Mandatory MD5 key-string; prevents rogue gateway injection. |
| **HSRP-SEC-02** | Preempt Delay Minimum Hardening (\$\\ge 60\$s) | 15 pts | Minimum 180s delay prevents reload blackholes. |
| **HSRP-SEC-03** | Enhanced Object Tracking on Uplinks | 12 pts | Priority decrement forces failover on WAN core failure. |
| **HSRP-SEC-04** | HSRPv2 Protocol Standard Enforced | 10 pts | Groups 0–4095, dedicated multicast 224.0.0.102, ms timers. |
| **HSRP-SEC-05** | Sub-Second Failover (BFD / Millisecond Timers) | 10 pts | Sub-500ms failover vs 10s default hold timer. |
| **HSRP-SEC-06** | Dual-Active Split-Brain Protection | 8 pts | Redundant peer-links prevent simultaneous Active state. |
| **HSRP-SEC-07** | Multi-Group HSRP (MHSRP) Active/Active | 8 pts | Even/odd VLAN distribution for 100% capacity utilization. |
| **HSRP-SEC-08** | Control Plane Policing (CoPP) Port 1985/2026 | 8 pts | Hardware rate-limiting protects supervisor CPU. |
| **HSRP-SEC-09** | Deterministic Priority & Preempt Matrix | 7 pts | Explicit priorities (110 vs 100); eliminates IP tie-breakers. |
| **HSRP-SEC-10** | Gratuitous ARP Refresh on State Change | 7 pts | Refreshes downstream CAM tables instantly on failover. |

