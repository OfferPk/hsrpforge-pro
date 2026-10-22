/**
 * HSRPForge Pro - Multi-Platform HSRP Configuration Synthesizer
 * 
 * Synthesizes production-hardened configurations for Cisco IOS-XE, Cisco NX-OS,
 * Arista EOS, Linux Keepalived, and Prometheus alerting rules.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.HSRPConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoIosXe(params) {
    const group = params.group || 100;
    const virtualIp = params.virtualIp || '10.100.0.1';
    const priority = params.priority || 110;
    const authKey = params.authKey || 'Hsrp$ecureKey2026!';
    const preemptDelay = params.preemptDelaySec || 180;
    const vlan = params.vlan || 100;

    return `! ==============================================================================
! Cisco IOS-XE Catalyst 9000 Production HSRPv2 Hardened Configuration
! Standards: RFC 2281 / RFC 7868, Enhanced Object Tracking & Preempt Delay
! ==============================================================================

! 1. Enhanced Object Tracking on WAN Core Uplinks
track 100 interface GigabitEthernet0/0/0 line-protocol
!
track 200 ip route 0.0.0.0/0 reachability
!

! 2. Downlink SVI Interface Configuration
interface Vlan${vlan}
 description GATEWAY-CLIENT-SUBNET-${vlan}
 ip address 10.100.0.2 255.255.255.0
 no ip redirects
 !
 ! Enforce HSRPv2 for Group 0-4095 and Multicast 224.0.0.102
 standby version 2
 !
 ! Virtual IP and Deterministic Priority
 standby ${group} ip ${virtualIp}
 standby ${group} priority ${priority}
 !
 ! Preempt with 180-Second Delay to Prevent Reload Blackholes
 standby ${group} preempt delay minimum ${preemptDelay}
 !
 ! Sub-Second Failure Detection with BFD & Millisecond Timers
 standby ${group} timers msec 250 msec 750
 standby bfd
 !
 ! Cryptographic MD5 Authentication
 standby ${group} authentication md5 key-string ${authKey}
 !
 ! Object Tracking: Decrement Priority by 30 on Uplink Failure
 standby ${group} track 100 decrement 30
 standby ${group} track 200 decrement 30
!
`;
  }

  function synthesizeCiscoNxos(params) {
    const group = params.group || 100;
    const virtualIp = params.virtualIp || '10.100.0.1';
    const priority = params.priority || 110;
    const authKey = params.authKey || 'Hsrp$ecureKey2026!';
    const vlan = params.vlan || 100;

    return `! ==============================================================================
! Cisco NX-OS Nexus Data Center HSRPv2 Configuration
! ==============================================================================
feature hsrp
!
track 10 interface Ethernet1/1 line-protocol
!
interface Vlan${vlan}
 description DATA-CENTER-VLAN-${vlan}
 no shutdown
 ip address 10.100.0.2/24
 no ip redirects
 hsrp version 2
 hsrp ${group}
  ip ${virtualIp}
  priority ${priority}
  preempt delay minimum 180
  timers msec 250 msec 750
  authentication md5 key-string 7 ${authKey}
  track 10 decrement 30
!
`;
  }

  function synthesizeAristaEos(params) {
    const virtualIp = params.virtualIp || '10.100.0.1';
    const vlan = params.vlan || 100;

    return `! ==============================================================================
! Arista EOS Active-Active Virtual ARP (VARP) & HSRP Interop
! ==============================================================================
ip virtual-router mac-address 00:00:0c:9f:f0:64
!
interface Vlan${vlan}
 description ARISTA-CAMPUS-VLAN-${vlan}
 ip address 10.100.0.2/24
 ip virtual-router address ${virtualIp}
!
`;
  }

  function synthesizeLinuxKeepalived(params) {
    const group = params.group || 100;
    const virtualIp = params.virtualIp || '10.100.0.1';
    const priority = params.priority || 110;
    const authKey = params.authKey || 'Hsrp$26';

    return `# ==============================================================================
# Linux Keepalived Redundant Gateway Daemon
# File: /etc/keepalived/keepalived.conf
# ==============================================================================
vrrp_instance HSRP_REDUNDANT_${group} {
    state MASTER
    interface eth0
    virtual_router_id ${group % 256}
    priority ${priority}
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass ${authKey.slice(0, 8)}
    }
    virtual_ipaddress {
        ${virtualIp}/24 dev eth0
    }
}
`;
  }

  function synthesizePrometheusAlerts(params) {
    return `# ==============================================================================
# Prometheus Alerting Rules for First-Hop Redundancy (HSRP)
# ==============================================================================
groups:
  - name: hsrp_monitoring
    rules:
      - alert: HSRPStateFlapping
        expr: changes(cisco_hsrp_state[5m]) > 3
        for: 1m
        labels:
          severity: warning
          tier: gateway_redundancy
        annotations:
          summary: "HSRP Gateway Flapping on {{ $labels.interface }} (Group {{ $labels.group }})"
          description: "Gateway state changed more than 3 times in 5 minutes, indicating timer mismatch or link instability."

      - alert: HSRPDualActiveSplitBrain
        expr: count(cisco_hsrp_state == 16) by (group, vlan) > 1
        for: 15s
        labels:
          severity: critical
          tier: gateway_redundancy
        annotations:
          summary: "CRITICAL: HSRP Dual-Active Split-Brain Detected on Group {{ $labels.group }}"
          description: "Multiple routers report ACTIVE state simultaneously for VIP, inducing MAC flapping."

      - alert: HSRPAuthFailureSpike
        expr: rate(cisco_hsrp_auth_failures_total[2m]) > 0
        for: 1m
        labels:
          severity: critical
          tier: gateway_security
        annotations:
          summary: "HSRP Authentication Failures Detected"
          description: "Router is rejecting HSRP packets with invalid MD5 auth keys, possible rogue gateway attack."
`;
  }

  return {
    synthesizeCiscoIosXe,
    synthesizeCiscoNxos,
    synthesizeAristaEos,
    synthesizeLinuxKeepalived,
    synthesizePrometheusAlerts
  };
}));
