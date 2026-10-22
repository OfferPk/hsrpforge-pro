/**
 * HSRPForge Pro - Cisco RFC 2281 (HSRPv1) & HSRPv2 Protocol Engine
 * 
 * Implements:
 * - RFC 2281 HSRPv1 packet encoding (UDP 1985, Multicast 224.0.0.2, 20 bytes).
 * - Cisco HSRPv2 packet encoding (UDP 2026, Multicast 224.0.0.102, TLV format).
 * - Deterministic Virtual MAC calculator (0000.0c07.acXX vs 0000.0c9f.fXXX).
 * - Preempt Delay Blackhole simulator (calculates exact drop duration & packets lost).
 * - Split-Brain Dual-Active Gateway detector.
 * - Wireshark-style hex dump formatting and binary PCAP generation.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.HSRPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // HSRP OpCodes (RFC 2281)
  const OPCODES = {
    HELLO: 0,
    COUP: 1,
    RESIGN: 2
  };

  // HSRP States (RFC 2281)
  const STATES = {
    INITIAL: 0,
    LEARN: 1,
    LISTEN: 2,
    SPEAK: 4,
    STANDBY: 8,
    ACTIVE: 16
  };

  function parseIpv4(ipStr) {
    if (!ipStr || typeof ipStr !== 'string') return [0, 0, 0, 0];
    const parts = ipStr.trim().split('.');
    if (parts.length !== 4) return [0, 0, 0, 0];
    return parts.map(p => {
      const n = parseInt(p, 10);
      return (isNaN(n) || n < 0 || n > 255) ? 0 : n;
    });
  }

  function parseMac(macStr) {
    if (!macStr || typeof macStr !== 'string') return [0, 0, 0, 0, 0, 0];
    const clean = macStr.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length !== 12) return [0, 0, 0, 0, 0, 0];
    const bytes = [];
    for (let i = 0; i < 12; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16));
    }
    return bytes;
  }

  /**
   * Calculates the deterministic HSRP Virtual MAC Address
   */
  function calculateVirtualMac(version, group) {
    const grp = parseInt(group, 10) || 0;
    if (version === 1) {
      const g = Math.min(255, Math.max(0, grp));
      const hexGrp = g.toString(16).padStart(2, '0').toLowerCase();
      return {
        formatted: `0000.0c07.ac${hexGrp}`,
        colon: `00:00:0c:07:ac:${hexGrp}`,
        bytes: [0x00, 0x00, 0x0c, 0x07, 0xac, g],
        standard: 'RFC 2281 (HSRPv1, 0000.0c07.acXX)'
      };
    } else {
      const g = Math.min(4095, Math.max(0, grp));
      const hexGrp = g.toString(16).padStart(3, '0').toLowerCase();
      const b4 = parseInt('9f', 16);
      const b5 = parseInt('f' + hexGrp[0], 16);
      const b6 = parseInt(hexGrp.substr(1, 2), 16);
      return {
        formatted: `0000.0c9f.f${hexGrp}`,
        colon: `00:00:0c:9f:${(b5).toString(16).padStart(2, '0')}:${(b6).toString(16).padStart(2, '0')}`,
        bytes: [0x00, 0x00, 0x0c, b4, b5, b6],
        standard: 'Cisco HSRPv2 (0000.0c9f.fXXX)'
      };
    }
  }

  /**
   * Forges an RFC 2281 (HSRPv1) or HSRPv2 binary wireframe
   */
  function forgePacket(config) {
    const version = config.version === 2 ? 2 : 1;
    const opCode = config.opCode !== undefined ? config.opCode : OPCODES.HELLO;
    const state = config.state !== undefined ? config.state : STATES.ACTIVE;
    const priority = config.priority !== undefined ? config.priority : 110;
    const group = config.group !== undefined ? config.group : (version === 1 ? 1 : 100);
    const helloSec = config.helloSec || 3;
    const holdSec = config.holdSec || 10;
    const virtualIp = config.virtualIp || '10.100.0.1';
    const authKey = (config.authKey || 'cisco').slice(0, 8);
    const authMode = config.authMode || 'NONE'; // NONE, TEXT, MD5
    const vMac = calculateVirtualMac(version, group);

    const ipBytes = parseIpv4(virtualIp);
    const rawBytes = [];

    if (version === 1) {
      // RFC 2281 20-byte base packet
      rawBytes.push(0x00); // Version: 0 (HSRPv1)
      rawBytes.push(opCode & 0xff); // OpCode
      rawBytes.push(state & 0xff);  // State
      rawBytes.push(helloSec & 0xff); // Hellotime
      rawBytes.push(holdSec & 0xff);  // Holdtime
      rawBytes.push(priority & 0xff); // Priority
      rawBytes.push(group & 0xff);    // Group
      rawBytes.push(0x00);            // Reserved

      // 8-byte Authentication Data
      const authBytes = [];
      for (let i = 0; i < 8; i++) {
        authBytes.push(authKey.charCodeAt(i) || 0);
      }
      rawBytes.push(...authBytes);

      // 4-byte Virtual IP
      rawBytes.push(...ipBytes);

    } else {
      // HSRPv2 TLV packet (40 bytes base)
      rawBytes.push(0x02); // Version: 2
      rawBytes.push(opCode & 0xff); // OpCode
      rawBytes.push(state & 0xff);  // State
      rawBytes.push(0x04); // IP Version: 4

      // Group Number (16 bits)
      rawBytes.push((group >> 8) & 0xff, group & 0xff);

      // Router Identifier / B-MAC (6 bytes)
      const bMac = parseMac(config.routerMac || '00:1a:2b:3c:4d:5e');
      rawBytes.push(...bMac);

      // Priority (32 bits)
      rawBytes.push((priority >> 24) & 0xff, (priority >> 16) & 0xff, (priority >> 8) & 0xff, priority & 0xff);

      // Hellotime (32 bits, in ms)
      const helloMs = helloSec * 1000;
      rawBytes.push((helloMs >> 24) & 0xff, (helloMs >> 16) & 0xff, (helloMs >> 8) & 0xff, helloMs & 0xff);

      // Holdtime (32 bits, in ms)
      const holdMs = holdSec * 1000;
      rawBytes.push((holdMs >> 24) & 0xff, (holdMs >> 16) & 0xff, (holdMs >> 8) & 0xff, holdMs & 0xff);

      // Virtual IP Address (4 bytes)
      rawBytes.push(...ipBytes);

      // Text Authentication TLV (Type 0x01, Len 8)
      rawBytes.push(0x01, 0x08);
      for (let i = 0; i < 8; i++) {
        rawBytes.push(authKey.charCodeAt(i) || 0);
      }
    }

    const uint8 = new Uint8Array(rawBytes);

    return {
      version: version,
      opCode: opCode,
      state: state,
      priority: priority,
      group: group,
      virtualIp: virtualIp,
      virtualMac: vMac.formatted,
      virtualMacColon: vMac.colon,
      rawBytes: uint8,
      totalLength: uint8.length,
      hexString: Array.from(uint8).map(b => b.toString(16).padStart(2, '0')).join('')
    };
  }

  /**
   * Formats raw bytes into standard Wireshark hex dump format
   */
  function formatHexDump(rawBytes) {
    const bytes = Array.from(rawBytes);
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const offsetHex = i.toString(16).padStart(4, '0');
      const hexPart1 = slice.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const hexPart2 = slice.slice(8, 16).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const hexPart = `${hexPart1.padEnd(23, ' ')}  ${hexPart2.padEnd(23, ' ')}`;
      const asciiPart = slice.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
      lines.push(`${offsetHex}   ${hexPart.padEnd(48, ' ')}   |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  /**
   * Simulates Preempt Delay & Routing Convergence Blackhole Risk
   */
  function simulatePreemptDelay(params) {
    const preemptEnabled = !!params.preemptEnabled;
    const preemptDelaySec = params.preemptDelaySec || 0;
    const igpConvergenceSec = params.igpConvergenceSec || 60; // Typical OSPF/BGP reload convergence
    const stpForwardDelaySec = 30; // Spanning tree listen + learn
    const trafficMbps = params.trafficMbps || 1000;
    const avgPacketSizeBytes = 1000;

    if (!preemptEnabled) {
      return {
        status: 'STABLE_NO_PREEMPT',
        blackholeSec: 0,
        droppedPackets: 0,
        trafficLostMegabits: 0,
        title: 'STABLE: Preempt Disabled (No Immediate Failback)',
        summary: 'When the primary router reboots, it will remain in STANDBY until the current active router fails. Zero blackhole drops, but requires manual intervention to restore primary role.',
        grade: 'PASS'
      };
    }

    // If preempt is enabled, evaluate if delay covers IGP convergence
    const totalRequiredConvergenceSec = igpConvergenceSec;
    const blackholeDuration = Math.max(0, totalRequiredConvergenceSec - preemptDelaySec);
    const droppedPackets = Math.round((trafficMbps * 1000000 / (avgPacketSizeBytes * 8)) * blackholeDuration);
    const trafficLostMbit = Math.round(trafficMbps * blackholeDuration);

    if (blackholeDuration > 0) {
      return {
        status: 'FATAL_PREEMPT_BLACKHOLE',
        blackholeSec: blackholeDuration,
        droppedPackets: droppedPackets,
        trafficLostMegabits: trafficLostMbit,
        title: `FATAL BLACKHOLE: ${blackholeDuration}s Traffic Drop on Reload`,
        summary: `Preempt delay (${preemptDelaySec}s) is shorter than core routing convergence (${igpConvergenceSec}s). Router becomes ACTIVE and claims Virtual IP before its uplinks have valid routes! Downstream client traffic is dropped!`,
        grade: 'FAIL',
        remediation: `Configure 'standby <group> preempt delay minimum ${Math.max(180, igpConvergenceSec + 60)}' to hold in Standby until routing tables synchronize.`
      };
    }

    return {
      status: 'PROTECTED_PREEMPT',
      blackholeSec: 0,
      droppedPackets: 0,
      trafficLostMegabits: 0,
      title: 'PROTECTED: Preempt Delay Adequately Calibrated',
      summary: `Preempt delay (${preemptDelaySec}s) exceeds core routing convergence time (${igpConvergenceSec}s). The router waits in Standby until routes are fully populated, then cleanly assumes Active state with zero packet loss.`,
      grade: 'PASS',
      remediation: 'Configuration complies with Zero-Trust gateway resiliency standards.'
    };
  }

  /**
   * Diagnoses Split-Brain Dual-Active Gateway Scenarios
   */
  function diagnoseDualActive(params) {
    const routerAVersion = params.routerAVersion || 1;
    const routerBVersion = params.routerBVersion || 1;
    const interSwitchTrunkUp = params.interSwitchTrunkUp !== false;
    const authKeysMatch = (params.authKeyA || 'cisco') === (params.authKeyB || 'cisco');
    const authModesMatch = (params.authModeA || 'NONE') === (params.authModeB || 'NONE');

    const issues = [];
    let isSplitBrain = false;

    if (!interSwitchTrunkUp) {
      isSplitBrain = true;
      issues.push('Inter-switch trunk or peer-link is DOWN. Routers cannot exchange Hellos across the VLAN.');
    }

    if (routerAVersion !== routerBVersion) {
      isSplitBrain = true;
      issues.push(`HSRP Version Mismatch: Router A is using HSRPv${routerAVersion} (UDP ${routerAVersion === 1 ? 1985 : 2026}) while Router B is using HSRPv${routerBVersion}. Neither router decodes the other's packets!`);
    }

    if (!authKeysMatch || !authModesMatch) {
      isSplitBrain = true;
      issues.push('Authentication Mismatch: Router A and Router B reject each other\'s Hello packets, causing both to transition to ACTIVE.');
    }

    if (isSplitBrain) {
      return {
        status: 'DUAL_ACTIVE_SPLIT_BRAIN',
        isSplitBrain: true,
        title: 'CRITICAL HAZARD: Dual-Active Split-Brain Detected',
        summary: 'Both Router A and Router B are currently ACTIVE for the same Virtual IP! Both are replying to ARP queries with the identical Virtual MAC, causing catastrophic CAM table flapping on downstream access switches and resetting TCP sessions.',
        issues: issues,
        remediation: 'Restore inter-switch trunk, unify HSRP version (recommend HSRPv2), and synchronize MD5 authentication keys.'
      };
    }

    return {
      status: 'HEALTHY_ACTIVE_STANDBY',
      isSplitBrain: false,
      title: 'OPTIMAL: Deterministic Active / Standby Pair',
      summary: 'Router A is ACTIVE and Router B is STANDBY. Hellos are continuously acknowledged with zero MAC flapping.',
      issues: [],
      remediation: 'Current gateway state is healthy.'
    };
  }

  /**
   * Generates a binary PCAP file containing the forged HSRP packet
   */
  function generatePcap(forgedPacket, srcIp = '10.100.0.1') {
    const hsrpBytes = forgedPacket.rawBytes;
    const version = forgedPacket.version;
    const isV1 = (version === 1);

    // Multicast Destination MAC
    // HSRPv1: 01:00:5E:00:00:02
    // HSRPv2: 01:00:5E:00:00:66 (0x66 = 102)
    const ethDst = isV1 ? [0x01, 0x00, 0x5e, 0x00, 0x00, 0x02] : [0x01, 0x00, 0x5e, 0x00, 0x00, 0x66];
    const ethSrc = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    const ethType = [0x08, 0x00]; // IPv4
    const ethHdr = [...ethDst, ...ethSrc, ...ethType];

    // IP Header (20 bytes)
    const ipTotalLen = 20 + 8 + hsrpBytes.length; // IP (20) + UDP (8) + HSRP
    const ipSrc = parseIpv4(srcIp);
    const ipDst = isV1 ? [224, 0, 0, 2] : [224, 0, 0, 102];
    const ipHdr = [
      0x45, 0xc0, // TOS: Internetwork Control (0xc0)
      (ipTotalLen >> 8) & 0xff, ipTotalLen & 0xff,
      0x23, 0x45, 0x00, 0x00,
      0x01, 0x11, // TTL: 1, Protocol: 17 (UDP)
      0x00, 0x00, // Checksum placeholder
      ...ipSrc,
      ...ipDst
    ];

    let ipSum = 0;
    for (let i = 0; i < 20; i += 2) {
      ipSum += (ipHdr[i] << 8) + ipHdr[i + 1];
    }
    while (ipSum >> 16) {
      ipSum = (ipSum & 0xffff) + (ipSum >> 16);
    }
    const ipChecksum = (~ipSum) & 0xffff;
    ipHdr[10] = (ipChecksum >> 8) & 0xff;
    ipHdr[11] = ipChecksum & 0xff;

    // UDP Header (8 bytes)
    const udpPort = isV1 ? 1985 : 2026;
    const udpLen = 8 + hsrpBytes.length;
    const udpHdr = [
      (udpPort >> 8) & 0xff, udpPort & 0xff,
      (udpPort >> 8) & 0xff, udpPort & 0xff,
      (udpLen >> 8) & 0xff, udpLen & 0xff,
      0x00, 0x00 // UDP Checksum optional
    ];

    const packetPayload = [...ethHdr, ...ipHdr, ...udpHdr, ...hsrpBytes];
    const packetLen = packetPayload.length;

    // PCAP Global Header (24 bytes)
    const pcapGlobalHeader = [
      0xd4, 0xc3, 0xb2, 0xa1, // Magic Number
      0x02, 0x00, 0x04, 0x00, // Version 2.4
      0x00, 0x00, 0x00, 0x00, // Timezone GMT
      0x00, 0x00, 0x00, 0x00, // Sigfigs
      0x00, 0x00, 0x04, 0x00, // Snaplen 262144
      0x01, 0x00, 0x00, 0x00  // LinkType Ethernet (1)
    ];

    // PCAP Record Header (16 bytes)
    const nowSec = Math.floor(Date.now() / 1000);
    const pcapRecordHeader = [
      nowSec & 0xff, (nowSec >> 8) & 0xff, (nowSec >> 16) & 0xff, (nowSec >> 24) & 0xff,
      0x00, 0x00, 0x00, 0x00,
      packetLen & 0xff, (packetLen >> 8) & 0xff, (packetLen >> 16) & 0xff, (packetLen >> 24) & 0xff,
      packetLen & 0xff, (packetLen >> 8) & 0xff, (packetLen >> 16) & 0xff, (packetLen >> 24) & 0xff
    ];

    return new Uint8Array([...pcapGlobalHeader, ...pcapRecordHeader, ...packetPayload]);
  }

  return {
    OPCODES,
    STATES,
    calculateVirtualMac,
    forgePacket,
    formatHexDump,
    simulatePreemptDelay,
    diagnoseDualActive,
    generatePcap,
    parseIpv4
  };
}));
