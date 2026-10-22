/**
 * HSRPForge Pro - Web Studio Controller & Preset Manager
 */

(function () {
  'use strict';

  const PRESETS = {
    'campus-core': {
      version: 2,
      group: 100,
      priority: 110,
      state: 16, // Active
      virtualIp: '10.100.0.1',
      authMode: 'MD5',
      authKey: 'CampusCore$HSRP2026',
      preemptEnabled: true,
      preemptDelaySec: 180,
      igpConvergenceSec: 60,
      trafficMbps: 1000,
      interSwitchTrunkUp: true,
      objectTracking: true,
      bfdEnabled: true,
      splitBrainProtection: true,
      mhsrpLoadSharing: true,
      coppActive: true,
      garpActive: true
    },
    'datacenter-mhsrp': {
      version: 2,
      group: 200,
      priority: 120,
      state: 16,
      virtualIp: '10.200.0.1',
      authMode: 'MD5',
      authKey: 'DcSpine$MHSRP2026',
      preemptEnabled: true,
      preemptDelaySec: 180,
      igpConvergenceSec: 45,
      trafficMbps: 5000,
      interSwitchTrunkUp: true,
      objectTracking: true,
      bfdEnabled: true,
      splitBrainProtection: true,
      mhsrpLoadSharing: true,
      coppActive: true,
      garpActive: true
    },
    'vulnerable-cleartext': {
      version: 1,
      group: 1,
      priority: 100,
      state: 16,
      virtualIp: '192.168.1.1',
      authMode: 'TEXT',
      authKey: 'cisco',
      preemptEnabled: true,
      preemptDelaySec: 0, // Triggers instant blackhole!
      igpConvergenceSec: 90,
      trafficMbps: 1000,
      interSwitchTrunkUp: false, // Triggers split brain!
      objectTracking: false,
      bfdEnabled: false,
      splitBrainProtection: false,
      mhsrpLoadSharing: false,
      coppActive: false,
      garpActive: true
    }
  };

  let currentConfig = Object.assign({}, PRESETS['campus-core']);
  let activeTab = 'cisco-ios-xe';
  let forgedPacketCache = null;

  // DOM Elements
  const selectVersion = document.getElementById('select-version');
  const inputGroup = document.getElementById('input-group');
  const inputPriority = document.getElementById('input-priority');
  const selectState = document.getElementById('select-state');
  const inputVirtualIp = document.getElementById('input-virtual-ip');
  const selectAuthMode = document.getElementById('select-auth-mode');
  const outputVmac = document.getElementById('output-vmac');
  const badgeVersion = document.getElementById('badge-version');

  const selectPreemptEnabled = document.getElementById('select-preempt-enabled');
  const inputPreemptDelay = document.getElementById('input-preempt-delay');
  const inputIgpConvergence = document.getElementById('input-igp-convergence');
  const inputTrafficRate = document.getElementById('input-traffic-rate');

  const preemptDiagBanner = document.getElementById('preempt-diag-banner');
  const preemptDiagTitle = document.getElementById('preempt-diag-title');
  const preemptDiagDesc = document.getElementById('preempt-diag-desc');
  const badgePreemptStatus = document.getElementById('badge-preempt-status');
  const calcBlackholeTime = document.getElementById('calc-blackhole-time');
  const calcDroppedPackets = document.getElementById('calc-dropped-packets');

  const selectTrunkStatus = document.getElementById('select-trunk-status');
  const selectObjectTracking = document.getElementById('select-object-tracking');
  const splitDiagBanner = document.getElementById('split-diag-banner');
  const splitDiagTitle = document.getElementById('split-diag-title');
  const splitDiagDesc = document.getElementById('split-diag-desc');

  const auditGradeCircle = document.getElementById('audit-grade-circle');
  const auditScoreText = document.getElementById('audit-score-text');
  const auditComplianceText = document.getElementById('audit-compliance-text');
  const auditScoreBar = document.getElementById('audit-score-bar');
  const auditStatusBadge = document.getElementById('audit-status-badge');
  const findingsContainer = document.getElementById('findings-container');

  const hexDissectorBox = document.getElementById('hex-dissector-box');
  const synthesizerOutputBox = document.getElementById('synthesizer-output-box');

  const btnCopyHex = document.getElementById('btn-copy-hex');
  const btnDownloadPcap = document.getElementById('btn-download-pcap');
  const btnCopyConfig = document.getElementById('btn-copy-config');
  const presetButtons = document.querySelectorAll('.btn-preset');
  const tabButtons = document.querySelectorAll('.tab-btn');

  function updateUiFromConfig() {
    selectVersion.value = currentConfig.version;
    inputGroup.value = currentConfig.group;
    inputPriority.value = currentConfig.priority;
    selectState.value = currentConfig.state;
    inputVirtualIp.value = currentConfig.virtualIp;
    selectAuthMode.value = currentConfig.authMode;

    selectPreemptEnabled.value = currentConfig.preemptEnabled ? 'true' : 'false';
    inputPreemptDelay.value = currentConfig.preemptDelaySec;
    inputIgpConvergence.value = currentConfig.igpConvergenceSec;
    inputTrafficRate.value = currentConfig.trafficMbps;

    selectTrunkStatus.value = currentConfig.interSwitchTrunkUp ? 'true' : 'false';
    selectObjectTracking.value = currentConfig.objectTracking ? 'true' : 'false';

    recomputeAll();
  }

  function readConfigFromUi() {
    currentConfig.version = parseInt(selectVersion.value, 10);
    currentConfig.group = parseInt(inputGroup.value, 10) || 0;
    currentConfig.priority = parseInt(inputPriority.value, 10) || 100;
    currentConfig.state = parseInt(selectState.value, 10);
    currentConfig.virtualIp = inputVirtualIp.value.trim() || '10.100.0.1';
    currentConfig.authMode = selectAuthMode.value;

    currentConfig.preemptEnabled = (selectPreemptEnabled.value === 'true');
    currentConfig.preemptDelaySec = parseInt(inputPreemptDelay.value, 10) || 0;
    currentConfig.igpConvergenceSec = parseInt(inputIgpConvergence.value, 10) || 60;
    currentConfig.trafficMbps = parseInt(inputTrafficRate.value, 10) || 1000;

    currentConfig.interSwitchTrunkUp = (selectTrunkStatus.value === 'true');
    currentConfig.objectTracking = (selectObjectTracking.value === 'true');

    recomputeAll();
  }

  function recomputeAll() {
    // 1. Virtual MAC & Packet Forge
    const vMac = HSRPProtocolEngine.calculateVirtualMac(currentConfig.version, currentConfig.group);
    outputVmac.value = `${vMac.formatted} (${vMac.colon}) - ${vMac.standard}`;
    badgeVersion.textContent = `HSRPv${currentConfig.version}`;

    forgedPacketCache = HSRPProtocolEngine.forgePacket({
      version: currentConfig.version,
      opCode: 0, // Hello
      state: currentConfig.state,
      priority: currentConfig.priority,
      group: currentConfig.group,
      helloSec: 3,
      holdSec: 10,
      virtualIp: currentConfig.virtualIp,
      authKey: currentConfig.authKey || 'cisco',
      authMode: currentConfig.authMode
    });

    hexDissectorBox.textContent = HSRPProtocolEngine.formatHexDump(forgedPacketCache.rawBytes);

    // 2. Preempt Delay Blackhole Simulation
    const preemptDiag = HSRPProtocolEngine.simulatePreemptDelay({
      preemptEnabled: currentConfig.preemptEnabled,
      preemptDelaySec: currentConfig.preemptDelaySec,
      igpConvergenceSec: currentConfig.igpConvergenceSec,
      trafficMbps: currentConfig.trafficMbps
    });

    preemptDiagTitle.textContent = preemptDiag.title;
    preemptDiagDesc.textContent = preemptDiag.summary;
    calcBlackholeTime.textContent = `${preemptDiag.blackholeSec} seconds`;
    calcDroppedPackets.textContent = `${preemptDiag.droppedPackets.toLocaleString()} packets (${preemptDiag.trafficLostMegabits} Mbit)`;

    if (preemptDiag.status === 'FATAL_PREEMPT_BLACKHOLE') {
      preemptDiagBanner.className = 'diag-banner diag-critical';
      badgePreemptStatus.textContent = 'FATAL BLACKHOLE';
      badgePreemptStatus.className = 'badge badge-amber';
    } else {
      preemptDiagBanner.className = 'diag-banner diag-protected';
      badgePreemptStatus.textContent = 'PROTECTED';
      badgePreemptStatus.className = 'badge badge-emerald';
    }

    // 3. Dual-Active Split-Brain Diagnosis
    const splitDiag = HSRPProtocolEngine.diagnoseDualActive({
      routerAVersion: currentConfig.version,
      routerBVersion: currentConfig.interSwitchTrunkUp ? currentConfig.version : (currentConfig.version === 1 ? 2 : 1),
      interSwitchTrunkUp: currentConfig.interSwitchTrunkUp,
      authKeyA: currentConfig.authKey,
      authKeyB: currentConfig.interSwitchTrunkUp ? currentConfig.authKey : 'mismatch',
      authModeA: currentConfig.authMode,
      authModeB: currentConfig.authMode
    });

    splitDiagTitle.textContent = splitDiag.title;
    splitDiagDesc.textContent = splitDiag.summary;
    splitDiagBanner.className = 'diag-banner ' + (splitDiag.isSplitBrain ? 'diag-critical' : 'diag-healthy');

    // 4. Run 10-Point Zero-Trust Audit
    const audit = HSRPSecurityAuditor.auditConfiguration({
      authMode: currentConfig.authMode,
      preemptEnabled: currentConfig.preemptEnabled,
      preemptDelaySec: currentConfig.preemptDelaySec,
      objectTracking: currentConfig.objectTracking,
      version: currentConfig.version,
      bfdEnabled: currentConfig.bfdEnabled,
      splitBrainProtection: currentConfig.splitBrainProtection,
      mhsrpLoadSharing: currentConfig.mhsrpLoadSharing,
      coppActive: currentConfig.coppActive,
      priority: currentConfig.priority,
      garpActive: currentConfig.garpActive
    });

    auditScoreText.textContent = `${audit.score} / 100 Points`;
    auditGradeCircle.textContent = audit.grade;
    auditGradeCircle.className = `grade-circle grade-${audit.grade.toLowerCase().replace('+', 'plus')}`;
    auditScoreBar.style.width = `${audit.score}%`;

    if (audit.passed) {
      auditScoreBar.style.background = 'var(--primary-emerald)';
      auditComplianceText.textContent = 'Production Zero-Trust';
      auditComplianceText.style.color = 'var(--primary-emerald)';
      auditStatusBadge.textContent = 'PASSING';
      auditStatusBadge.className = 'badge badge-emerald';
    } else {
      auditScoreBar.style.background = 'var(--primary-rose)';
      auditComplianceText.textContent = 'Non-Compliant / Audit Failure';
      auditComplianceText.style.color = 'var(--primary-rose)';
      auditStatusBadge.textContent = 'CRITICAL FAILS';
      auditStatusBadge.className = 'badge badge-amber';
    }

    // Render findings
    findingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const div = document.createElement('div');
      div.className = `finding-item ${f.level.toLowerCase()}`;
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: 700; margin-bottom: 0.2rem;">
          <span>[${f.level}] ${f.id} - ${f.title}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxPoints} pts</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.78rem;">${f.finding}</div>
      `;
      findingsContainer.appendChild(div);
    });

    // 5. Update Synthesizer
    renderSynthesizerConfig();
  }

  function renderSynthesizerConfig() {
    const synthParams = {
      group: currentConfig.group,
      virtualIp: currentConfig.virtualIp,
      priority: currentConfig.priority,
      authKey: currentConfig.authKey || 'Hsrp$ecureKey2026!',
      preemptDelaySec: currentConfig.preemptDelaySec || 180,
      vlan: currentConfig.group
    };

    let text = '';
    if (activeTab === 'cisco-ios-xe') {
      text = HSRPConfigSynthesizer.synthesizeCiscoIosXe(synthParams);
    } else if (activeTab === 'cisco-nxos') {
      text = HSRPConfigSynthesizer.synthesizeCiscoNxos(synthParams);
    } else if (activeTab === 'arista-eos') {
      text = HSRPConfigSynthesizer.synthesizeAristaEos(synthParams);
    } else if (activeTab === 'linux-keepalived') {
      text = HSRPConfigSynthesizer.synthesizeLinuxKeepalived(synthParams);
    } else if (activeTab === 'prometheus') {
      text = HSRPConfigSynthesizer.synthesizePrometheusAlerts(synthParams);
    }
    synthesizerOutputBox.textContent = text;
  }

  // Event Listeners
  [selectVersion, inputGroup, inputPriority, selectState, inputVirtualIp, selectAuthMode,
   selectPreemptEnabled, inputPreemptDelay, inputIgpConvergence, inputTrafficRate,
   selectTrunkStatus, selectObjectTracking].forEach(el => {
    el.addEventListener('change', readConfigFromUi);
    el.addEventListener('input', readConfigFromUi);
  });

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const presetKey = btn.getAttribute('data-preset');
      if (PRESETS[presetKey]) {
        currentConfig = Object.assign({}, PRESETS[presetKey]);
        updateUiFromConfig();
      }
    });
  });

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.getAttribute('data-tab');
      renderSynthesizerConfig();
    });
  });

  btnCopyHex.addEventListener('click', () => {
    navigator.clipboard.writeText(hexDissectorBox.textContent).then(() => {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(() => btnCopyHex.textContent = 'Copy Hex', 2000);
    });
  });

  btnCopyConfig.addEventListener('click', () => {
    navigator.clipboard.writeText(synthesizerOutputBox.textContent).then(() => {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(() => btnCopyConfig.textContent = 'Copy Config', 2000);
    });
  });

  btnDownloadPcap.addEventListener('click', () => {
    if (!forgedPacketCache) return;
    const pcapBytes = HSRPProtocolEngine.generatePcap(forgedPacketCache, '10.100.0.1');
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hsrp-v${currentConfig.version}-grp${currentConfig.group}-${Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Initial load
  updateUiFromConfig();
})();
