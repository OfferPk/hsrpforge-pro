/**
 * HSRPForge Pro - 10-Point Zero-Trust First-Hop Redundancy (HSRP) Security Auditor
 * 
 * Evaluates HSRP configurations against RFC 2281, Cisco best practices, and enterprise high-availability standards.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.HSRPSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_CONTROLS = [
    {
      id: 'HSRP-SEC-01',
      title: 'Cryptographic MD5 / Key-Chain Authentication',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (cfg.authMode === 'MD5' || cfg.authMode === 'KEY_CHAIN') {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: 'Cryptographic MD5 authentication active on HSRP group.',
            remediation: 'Compliant. Thwarts rogue router takeover and Man-in-the-Middle default gateway attacks.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL VULNERABILITY: Cleartext or unauthenticated HSRP control plane. Any rogue host on VLAN can claim default gateway.',
          remediation: 'Configure `standby <group> authentication md5 key-string <SECRET>` or utilize a key-chain.'
        };
      }
    },
    {
      id: 'HSRP-SEC-02',
      title: 'Preempt Delay Minimum Hardening (>= 60s)',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (!cfg.preemptEnabled) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'Preempt disabled. No risk of immediate reload blackhole, but failback requires manual intervention.',
            remediation: 'Consider enabling preempt with at least 180s delay for deterministic active gateway recovery.'
          };
        }
        const delay = cfg.preemptDelaySec || 0;
        if (delay >= 60) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: `Preempt delay minimum configured to ${delay} seconds.`,
            remediation: 'Compliant. Prevents active gateway takeover while uplink routing tables (OSPF/BGP) converge.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: `FATAL BLACKHOLE HAZARD: Preempt enabled with ${delay}s delay (< 60s). Primary router will seize gateway role before uplinks converge!`,
          remediation: 'Configure `standby <group> preempt delay minimum 180` to protect client traffic during reload.'
        };
      }
    },
    {
      id: 'HSRP-SEC-03',
      title: 'Enhanced Object Tracking for Uplink Failure',
      maxPoints: 12,
      evaluate: function (cfg) {
        if (cfg.objectTracking) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: 'Enhanced Object Tracking configured to decrement priority on WAN/core uplink failure.',
            remediation: 'Compliant. Forces clean gateway preemption to standby router when upstream connectivity drops.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Missing Object Tracking: Router remains ACTIVE even if all its upstream WAN/core interfaces go down!',
          remediation: 'Configure `track 1 interface <UPLINK> line-protocol` and `standby <group> track 1 decrement 30`.'
        };
      }
    },
    {
      id: 'HSRP-SEC-04',
      title: 'HSRPv2 Protocol Standard Enforced',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.version === 2) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'HSRPv2 active: Supports groups 0–4095, dedicated multicast 224.0.0.102, and millisecond timers.',
            remediation: 'Compliant. Aligns HSRP group IDs 1:1 with 802.1Q VLAN IDs.'
          };
        }
        return {
          passed: false,
          score: 3,
          level: 'WARN',
          finding: 'Legacy HSRPv1 in use: Restricted to groups 0–255, overlaps with CGMP on 224.0.0.2.',
          remediation: 'Upgrade to HSRPv2 with `standby version 2` on both distribution routers.'
        };
      }
    },
    {
      id: 'HSRP-SEC-05',
      title: 'Sub-Second Failover (BFD / Millisecond Timers)',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.bfdEnabled || (cfg.helloMs && cfg.helloMs < 1000)) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'Sub-second failure detection active (BFD or millisecond Hellos).',
            remediation: 'Compliant. Failover converges in sub-500ms rather than 10 seconds.'
          };
        }
        return {
          passed: false,
          score: 3,
          level: 'WARN',
          finding: 'Default 3s Hello / 10s Hold timers: Active gateway crash causes 10 full seconds of packet loss.',
          remediation: 'Enable `standby bfd` or tune timers to `standby <group> timers msec 250 msec 750`.'
        };
      }
    },
    {
      id: 'HSRP-SEC-06',
      title: 'Dual-Active Split-Brain Protection',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.splitBrainProtection) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'Redundant peer-link or out-of-band heartbeat mechanism protecting against split-brain.',
            remediation: 'Compliant. Prevents simultaneous ACTIVE states when member VLAN trunks bounce.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Single Heartbeat Path: If inter-switch trunk fails, both routers become ACTIVE (MAC flap storm).',
          remediation: 'Maintain redundant Layer 2 trunk links or dedicated keepalive links between distribution switches.'
        };
      }
    },
    {
      id: 'HSRP-SEC-07',
      title: 'Multi-Group HSRP (MHSRP) Active/Active Load Balancing',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.mhsrpLoadSharing) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'MHSRP Active/Active load sharing active across alternate VLANs (even/odd distribution).',
            remediation: 'Compliant. Utilizes 100% of redundant distribution switch bandwidth.'
          };
        }
        return {
          passed: false,
          score: 3,
          level: 'INFO',
          finding: 'Active/Passive single-group topology: Standby router sits idle without forwarding client traffic.',
          remediation: 'Deploy Multi-Group HSRP to share traffic across both distribution switches.'
        };
      }
    },
    {
      id: 'HSRP-SEC-08',
      title: 'Control Plane Policing (CoPP) for Port 1985 / 2026',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.coppActive) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'Hardware CoPP filter policing UDP port 1985/2026 HSRP traffic to Route Processor.',
            remediation: 'Compliant. Protects supervisor CPU from denial-of-service flood attacks.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'Unpoliced Control Plane: HSRP multicast packets punted to supervisor CPU without rate limits.',
          remediation: 'Apply CoPP policy policing UDP 1985 and UDP 2026 to trusted distribution switch peers.'
        };
      }
    },
    {
      id: 'HSRP-SEC-09',
      title: 'Deterministic Priority & Preempt Hierarchy',
      maxPoints: 7,
      evaluate: function (cfg) {
        const prio = cfg.priority || 100;
        if (prio !== 100 && prio > 0) {
          return {
            passed: true,
            score: 7,
            level: 'PASS',
            finding: `Explicit non-default priority configured (${prio}). Deterministic active/standby hierarchy established.`,
            remediation: 'Compliant. Eliminates IP address tie-breaker dependencies.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Default Priority 100: Active router election relies on highest IP address tie-breaker.',
          remediation: 'Explicitly set priority: 110 on Primary router and 100 on Secondary router.'
        };
      }
    },
    {
      id: 'HSRP-SEC-10',
      title: 'Gratuitous ARP Refresh on State Change',
      maxPoints: 7,
      evaluate: function (cfg) {
        if (cfg.garpActive !== false) {
          return {
            passed: true,
            score: 7,
            level: 'PASS',
            finding: 'Gratuitous ARP (GARP) transmission active upon transition to ACTIVE state.',
            remediation: 'Compliant. Instantly updates downstream switch CAM tables with Virtual MAC port binding.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'GARP suppressed: Access switches will retain stale CAM entries until 300s timer expires.',
          remediation: 'Ensure GARP is enabled on HSRP state transitions.'
        };
      }
    }
  ];

  function auditConfiguration(cfg) {
    let totalScore = 0;
    const findings = [];

    AUDIT_CONTROLS.forEach(ctrl => {
      const res = ctrl.evaluate(cfg);
      totalScore += res.score;
      findings.push({
        id: ctrl.id,
        title: ctrl.title,
        maxPoints: ctrl.maxPoints,
        score: res.score,
        level: res.level,
        passed: res.passed,
        finding: res.finding,
        remediation: res.remediation
      });
    });

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 60) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      passed: totalScore >= 80,
      findings: findings,
      evaluatedAt: new Date().toISOString()
    };
  }

  return {
    AUDIT_CONTROLS,
    auditConfiguration
  };
}));
