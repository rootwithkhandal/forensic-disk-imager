// --------------------------------------------------
// FORGELENS Disk Imager Frontend Controller
// Handles UI states, Tauri IPC, and log rendering
// --------------------------------------------------

// Destructure Tauri APIs from global window injection or fall back to browser simulation
let invoke, listen;

if (window.__TAURI__) {
  invoke = window.__TAURI__.core.invoke;
  listen = window.__TAURI__.event.listen;
} else {
  // Browser simulation mode fallback
  const mockListeners = {};
  
  listen = async (event, callback) => {
    if (!mockListeners[event]) mockListeners[event] = [];
    mockListeners[event].push(callback);
    return () => {
      mockListeners[event] = mockListeners[event].filter(cb => cb !== callback);
    };
  };

  const triggerMockEvent = (event, payload) => {
    if (mockListeners[event]) {
      mockListeners[event].forEach(cb => cb({ payload }));
    }
  };

  let mockInterval = null;

  invoke = async (cmd, args) => {
    console.log(`[MOCK IPC] Invoke command: ${cmd}`, args);
    
    if (cmd === 'get_admin_status') {
      return true;
    }
    
    if (cmd === 'scan_devices') {
      await new Promise(r => setTimeout(r, 500));
      return [
        { 
          name: 'PhysicalDrive0', 
          path: '\\\\.\\PhysicalDrive0', 
          size: 1000204886016, 
          model: 'Samsung SSD 980 PRO 1TB', 
          serial: 'S6BCNJ0R123456', 
          vendor: 'Samsung', 
          device_type: 'SSD', 
          is_mounted: false, 
          mount_points: [],
          partitions: [
            { name: 'Partition 1 (System)', size: 524288000, fs_type: 'FAT32' },
            { name: 'Partition 2 (OS)', size: 950000000000, fs_type: 'NTFS' },
            { name: 'Partition 3 (Recovery)', size: 49767086016, fs_type: 'NTFS (Hidden)' }
          ]
        },
        { 
          name: 'PhysicalDrive1', 
          path: '\\\\.\\PhysicalDrive1', 
          size: 32017047552, 
          model: 'Crucial USB Flash Drive', 
          serial: '070324888123', 
          vendor: 'Crucial', 
          device_type: 'USB', 
          is_mounted: false, 
          mount_points: [],
          partitions: [
            { name: 'Partition 1 (USB Storage)', size: 32015000000, fs_type: 'exFAT' }
          ]
        }
      ];
    }
    
    if (cmd === 'browse_folder') {
      return 'C:\\Forensics\\Evidence_Source';
    }
    
    if (cmd === 'browse_file') {
      return `C:\\Forensics\\Acquisitions\\case_evidence.${args.ext || 'dd'}`;
    }
    
    if (cmd === 'check_checkpoint') {
      return false;
    }
    
    if (cmd === 'cancel_acquisition') {
      if (mockInterval) {
        clearInterval(mockInterval);
        triggerMockEvent('acquisition-event', { type: 'Log', data: '[SYSTEM] Acquisition cancelled by user.' });
        state.activeJob = false;
        toggleUIJobActive(false);
      }
      return;
    }
    
    if (cmd === 'start_triage') {
      const destPath = args.destPath;
      triggerMockEvent('acquisition-event', { type: 'Log', data: `[SYSTEM] Starting simulated rapid system triage to ${destPath}` });
      let progress = 0;
      mockInterval = setInterval(() => {
        progress += 25;
        if (progress === 25) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Gathering volatile process list and network sockets...' });
        } else if (progress === 50) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Dumping Windows registry system and SAM hives...' });
        } else if (progress === 75) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Extracting Chrome browser history databases...' });
        } else if (progress >= 100) {
          clearInterval(mockInterval);
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Packaging forensic triage files into destination...' });
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[TRIAGE] Rapid forensic triage completed successfully!' });
          triggerMockEvent('acquisition-event', {
            type: 'Finished',
            data: {
              bytes_read: 4096,
              bad_sectors: 0,
              hashes: { 'SHA-256': 'triage-tethered-integrity-sha256' }
            }
          });
        }
      }, 1000);
      return;
    }

    if (cmd === 'mount_image') {
      await new Promise(r => setTimeout(r, 800));
      return true;
    }
    
    if (cmd === 'start_acquisition') {
      const config = args.configInput;
      let bytes_read = 0;
      const total_size = config.imaging_mode === 'Physical' ? 32017047552 : 54000000;
      const speed = 125000000; // 125 MB/s
      let bad_sectors = 0;
      
      triggerMockEvent('acquisition-event', { type: 'Log', data: `[ACQUISITION] Starting simulated physical imaging of ${config.source_path}` });
      
      mockInterval = setInterval(() => {
        bytes_read += speed * 0.25;
        if (Math.random() < 0.02) {
          bad_sectors += 1;
          triggerMockEvent('acquisition-event', { type: 'Log', data: `[WARNING] Bad sector encountered at offset ${bytes_read} bytes` });
        }
        
        if (bytes_read >= total_size) {
          bytes_read = total_size;
          clearInterval(mockInterval);
          triggerMockEvent('acquisition-event', { type: 'Progress', data: { bytes_read, total_size, speed_bps: speed, bad_sectors } });
          triggerMockEvent('acquisition-event', { 
            type: 'Finished', 
            data: { 
              bytes_read, 
              bad_sectors, 
              hashes: { 'MD5': '9e107d9d372bb6826bd81d3542a419d6', 'SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } 
            } 
          });
        } else {
          triggerMockEvent('acquisition-event', { type: 'Progress', data: { bytes_read, total_size, speed_bps: speed, bad_sectors } });
        }
      }, 250);
      return;
    }
    if (cmd === 'list_volumes') {
      await new Promise(r => setTimeout(r, 300));
      return [
        { letter: 'C:', label: 'Windows', fs_type: 'NTFS', total_size: 1000204886016, free_space: 450000000000 },
        { letter: 'D:', label: 'Data', fs_type: 'exFAT', total_size: 2000204886016, free_space: 1500000000000 }
      ];
    }
    
    if (cmd === 'start_live_acquisition') {
      const config = args.configInput;
      triggerMockEvent('acquisition-event', { type: 'Log', data: `[LIVE] Starting simulated live acquisition of volume ${config.volume} to ${config.dest_path}` });
      
      let progress = 0;
      mockInterval = setInterval(() => {
        progress += 20;
        if (progress === 20) {
          if (config.capture_ram) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Capturing physical memory (RAM)...' });
        } else if (progress === 40) {
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Creating VSS snapshot for consistent imaging...' });
        } else if (progress === 60) {
          if (config.capture_locked_files) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Copying OS-locked registry hives and MFT...' });
        } else if (progress === 80) {
          if (config.run_consistency_check) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Running filesystem consistency validation against VSS...' });
        } else if (progress >= 100) {
          clearInterval(mockInterval);
          if (config.auto_cleanup_vss) triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Cleaning up temporary VSS snapshot...' });
          triggerMockEvent('acquisition-event', { type: 'Log', data: '[LIVE] Live acquisition completed successfully! Reports generated.' });
          triggerMockEvent('acquisition-event', {
            type: 'Finished',
            data: {
              bytes_read: 0,
              bad_sectors: 0,
              hashes: {}
            }
          });
        }
      }, 1000);
      return;
    }
  };
}

// State management
let state = {
  imagingMode: 'Physical', // 'Physical' or 'Logical'
  devices: [],
  selectedDeviceIndex: null,
  activeJob: false,
  logCount: 0
};

// UI Elements Binding
const elements = {
  adminBadge: document.getElementById('admin-badge'),
  clockDisplay: document.getElementById('clock-display'),
  btnThemeToggle: document.getElementById('btn-theme-toggle'),
  btnRescan: document.getElementById('btn-rescan'),
  modePhysical: document.getElementById('mode-physical'),
  modeLogical: document.getElementById('mode-logical'),
  physicalContainer: document.getElementById('physical-container'),
  logicalContainer: document.getElementById('logical-container'),
  deviceList: document.getElementById('device-list'),
  
  logicalSourceInput: document.getElementById('logical-source-input'),
  btnBrowseSource: document.getElementById('btn-browse-source'),
  
  inputEvidenceId: document.getElementById('input-evidence-id'),
  inputCaseNumber: document.getElementById('input-case-number'),
  inputExaminer: document.getElementById('input-examiner'),
  inputNotes: document.getElementById('input-notes'),
  selectFormat: document.getElementById('select-format'),
  inputDestPath: document.getElementById('input-dest-path'),
  btnBrowseDest: document.getElementById('btn-browse-dest'),
  selectVerification: document.getElementById('select-verification'),
  selectBlocksize: document.getElementById('select-blocksize'),
  selectCompression: document.getElementById('select-compression'),
  selectSplit: document.getElementById('select-split'),
  customSplitGroup: document.getElementById('custom-split-group'),
  inputSplitSize: document.getElementById('input-split-size'),
  checkReadVerification: document.getElementById('check-read-verification'),
  inputKeywords: document.getElementById('input-keywords'),
  inputYaraPath: document.getElementById('input-yara-path'),
  btnBrowseYara: document.getElementById('btn-browse-yara'),
  checkSparse: document.getElementById('check-sparse'),
  checkDigitalSignature: document.getElementById('check-digital-signature'),
  
  hashMd5: document.getElementById('hash-md5'),
  hashSha1: document.getElementById('hash-sha1'),
  hashSha256: document.getElementById('hash-sha256'),
  hashSha512: document.getElementById('hash-sha512'),
  
  consoleLogs: document.getElementById('console-logs'),
  btnClearLog: document.getElementById('btn-clear-log'),
  btnExportLog: document.getElementById('btn-export-log'),
  
  monitorIdle: document.getElementById('monitor-idle'),
  monitorActive: document.getElementById('monitor-active'),
  idleStatusText: document.getElementById('idle-status-text'),
  btnStartAcquisition: document.getElementById('btn-start-acquisition'),
  btnResumeAcquisition: document.getElementById('btn-resume-acquisition'),
  btnCancelAcquisition: document.getElementById('btn-cancel-acquisition'),
  
  txtActiveJobDesc: document.getElementById('txt-active-job-desc'),
  txtStatSpeed: document.getElementById('txt-stat-speed'),
  txtStatEta: document.getElementById('txt-stat-eta'),
  txtStatBad: document.getElementById('txt-stat-bad'),
  txtStatPercent: document.getElementById('txt-stat-percent'),
  progressBarFill: document.getElementById('progress-bar-fill'),
  txtBytesProgress: document.getElementById('txt-bytes-progress'),

  // Triage Workbench
  triageDbPath: document.getElementById('triage-db-path'),
  btnBrowseTriageDb: document.getElementById('btn-browse-triage-db'),
  triageTableSelect: document.getElementById('triage-table-select'),
  btnLoadTriageTable: document.getElementById('btn-load-triage-table'),
  triageTableHead: document.getElementById('triage-table-head'),
  triageTableBody: document.getElementById('triage-table-body'),

  // Timeline
  timelineImagePath: document.getElementById('timeline-image-path'),
  btnBrowseTimelineImage: document.getElementById('btn-browse-timeline-image'),
  timelineDestPath: document.getElementById('timeline-dest-path'),
  btnBrowseTimelineDest: document.getElementById('btn-browse-timeline-dest'),
  btnStartTimeline: document.getElementById('btn-start-timeline'),

  // RAM Analysis
  ramImagePath: document.getElementById('ram-image-path'),
  btnBrowseRamImage: document.getElementById('btn-browse-ram-image'),
  ramVolPath: document.getElementById('ram-vol-path'),
  btnBrowseRamVol: document.getElementById('btn-browse-ram-vol'),
  ramProfileSelect: document.getElementById('ram-profile-select'),
  ramEnrichAbuseIp: document.getElementById('ram-enrich-abuseip'),
  ramEnrichVt: document.getElementById('ram-enrich-vt'),
  ramKeyAbuseIp: document.getElementById('ram-key-abuseip'),
  ramKeyVt: document.getElementById('ram-key-vt'),
  btnStartRamAnalysis: document.getElementById('btn-start-ram-analysis')
};

// Initialize Application
async function init() {
  logMessage('SYSTEM', 'Forgelens Disk Imager UI loaded.');
  
  // 0. Initialize Theme
  initTheme();
  
  // 1. Start Clock Updater
  startClock();
  
  // 2. Fetch Admin privileges
  try {
    const isAdmin = await invoke('get_admin_status');
    updateAdminBadge(isAdmin);
  } catch (e) {
    logMessage('ERROR', 'Failed to retrieve privileges: ' + e);
  }

  // 3. Register Global Event Listeners
  setupEventListeners();

  // 4. Initial Scan of block devices
  await doRescan();
}

function initTheme() {
  const savedTheme = localStorage.getItem('forgelens-theme');
  if (savedTheme === 'light') {
    document.documentElement.classList.add('light-theme');
    elements.btnThemeToggle.textContent = '☾';
    elements.btnThemeToggle.title = 'Switch to Dark Mode';
  } else {
    document.documentElement.classList.remove('light-theme');
    elements.btnThemeToggle.textContent = '☀';
    elements.btnThemeToggle.title = 'Switch to Light Mode';
  }
}

function toggleTheme() {
  const isLight = document.documentElement.classList.toggle('light-theme');
  if (isLight) {
    localStorage.setItem('forgelens-theme', 'light');
    elements.btnThemeToggle.textContent = '☾';
    elements.btnThemeToggle.title = 'Switch to Dark Mode';
  } else {
    localStorage.setItem('forgelens-theme', 'dark');
    elements.btnThemeToggle.textContent = '☀';
    elements.btnThemeToggle.title = 'Switch to Light Mode';
  }
}

// Live Clock in IST
function startClock() {
  function update() {
    const now = new Date();
    // Offset by +5:30 for IST
    const istTime = new Date(now.getTime() + (5.5 * 60 * 60 * 1000));
    const istStr = istTime.toISOString().replace('T', ' ').substring(0, 19) + ' IST';
    elements.clockDisplay.textContent = istStr;
  }
  setInterval(update, 1000);
  update();
}

function updateAdminBadge(isAdmin) {
  elements.adminBadge.className = 'badge';
  if (isAdmin) {
    elements.adminBadge.textContent = 'Admin Mode';
    elements.adminBadge.classList.add('badge-admin');
    logMessage('SYSTEM', 'Running with elevated administrator privileges.');
  } else {
    elements.adminBadge.textContent = 'Needs Administrator Privileges';
    elements.adminBadge.classList.add('badge-needs-admin');
    logMessage('SYSTEM', 'WARNING: Running in standard user mode. Raw disk imaging will not be possible.');
  }
}

// Event Listeners
function setupEventListeners() {
  // Theme toggle button
  elements.btnThemeToggle.addEventListener('click', toggleTheme);

  // Mode selection buttons
  elements.modePhysical.addEventListener('click', () => setImagingMode('Physical'));
  elements.modeLogical.addEventListener('click', () => setImagingMode('Logical'));

  // Rescan button
  elements.btnRescan.addEventListener('click', doRescan);

  // Browse source directory (Logical mode)
  elements.btnBrowseSource.addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_folder');
      if (folder) {
        elements.logicalSourceInput.value = folder;
        logMessage('SYSTEM', 'Selected source folder: ' + folder);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse folder: ' + e);
    }
  });

  // Browse destination path
  elements.btnBrowseDest.addEventListener('click', async () => {
    try {
      const format = elements.selectFormat.value;
      let ext = 'dd';
      if (format.includes('E01')) ext = 'e01';
      else if (format.includes('EX01')) ext = 'ex01';
      else if (format.includes('AFF')) ext = 'aff';
      else if (format.includes('SMART')) ext = 'smart';

      const file = await invoke('browse_file', { ext });
      if (file) {
        elements.inputDestPath.value = file;
        logMessage('SYSTEM', 'Set destination file path: ' + file);
        // Check for checkpoints
        checkCheckpointExists(file);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to save file dialog: ' + e);
    }
  });

  // YARA Rules folder browse
  elements.btnBrowseYara.addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_yara_folder');
      if (folder) {
        elements.inputYaraPath.value = folder;
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse for YARA folder: ' + e);
    }
  });

  // Output format change updates file extensions if already populated
  elements.selectFormat.addEventListener('change', () => {
    const path = elements.inputDestPath.value;
    if (path) {
      const format = elements.selectFormat.value;
      let ext = '.dd';
      if (format.includes('E01')) ext = '.e01';
      else if (format.includes('EX01')) ext = '.ex01';
      else if (format.includes('AFF')) ext = '.aff';
      else if (format.includes('SMART')) ext = '.smart';

      // Replace old extension
      let cleanPath = path;
      if (path.endsWith('.dd') || path.endsWith('.e01') || path.endsWith('.ex01') || path.endsWith('.aff') || path.endsWith('.smart')) {
        cleanPath = path.substring(0, path.lastIndexOf('.'));
      }
      const newPath = cleanPath + ext;
      elements.inputDestPath.value = newPath;
      checkCheckpointExists(newPath);
    }
  });

  // Toggle custom splitting size display
  elements.selectSplit.addEventListener('change', () => {
    if (elements.selectSplit.value === 'Custom') {
      elements.customSplitGroup.classList.remove('hidden');
    } else {
      elements.customSplitGroup.classList.add('hidden');
    }
  });

  // Clear log console
  elements.btnClearLog.addEventListener('click', () => {
    elements.consoleLogs.innerHTML = '';
  });

  // Export log console
  elements.btnExportLog.addEventListener('click', () => {
    const logs = Array.from(elements.consoleLogs.children).map(c => c.textContent).join('\n');
    if (!logs) {
      alert('The console log is empty.');
      return;
    }
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forgelens_console_log_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    logMessage('SYSTEM', 'Console log exported successfully.');
  });

  // Start Acquisition
  elements.btnStartAcquisition.addEventListener('click', (e) => {
    e.preventDefault();
    handleStartAcquisition(false);
  });

  // Resume Acquisition
  elements.btnResumeAcquisition.addEventListener('click', (e) => {
    e.preventDefault();
    handleStartAcquisition(true);
  });

  // Cancel Acquisition
  elements.btnCancelAcquisition.addEventListener('click', async () => {
    try {
      logMessage('SYSTEM', 'Cancelling active acquisition job...');
      await invoke('cancel_acquisition');
    } catch (e) {
      logMessage('ERROR', 'Event system setup failed: ' + e);
    }
  });

  // Tab Navigation Buttons
  document.getElementById('btn-tab-imaging').addEventListener('click', () => switchTab('imaging'));
  document.getElementById('btn-tab-triage').addEventListener('click', () => switchTab('triage'));
  document.getElementById('btn-tab-live').addEventListener('click', () => switchTab('live'));
  document.getElementById('btn-tab-timeline').addEventListener('click', () => switchTab('timeline'));
  document.getElementById('btn-tab-cases').addEventListener('click', () => { switchTab('cases'); loadCases(); });
  document.getElementById('btn-tab-ram').addEventListener('click', () => switchTab('ram'));

  document.getElementById('btn-refresh-cases').addEventListener('click', loadCases);

  // Triage Destination folder browse
  document.getElementById('btn-browse-triage-dest').addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_folder');
      if (folder) {
        document.getElementById('triage-dest-path').value = folder;
        logMessage('SYSTEM', 'Set triage destination directory: ' + folder);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse folder: ' + e);
    }
  });

  // Triage Workbench Handlers
  if (elements.btnBrowseTriageDb) {
    elements.btnBrowseTriageDb.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'db' });
        if (file) {
          elements.triageDbPath.value = file;
          logMessage('SYSTEM', 'Loaded Triage DB: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse for Triage DB: ' + e);
      }
    });
  }

  if (elements.btnLoadTriageTable) {
    elements.btnLoadTriageTable.addEventListener('click', async () => {
      const dbPath = elements.triageDbPath.value;
      if (!dbPath) {
        alert("Please select a triage.db file first.");
        return;
      }
      const table = elements.triageTableSelect.value;
      elements.triageTableBody.innerHTML = '<tr><td style="padding: 12px; color: var(--text-muted);">Querying database...</td></tr>';
      
      try {
        const resultJson = await invoke('query_triage_db', { dbPath, tableName: table });
        const data = JSON.parse(resultJson);
        renderTriageTable(data);
        logMessage('SYSTEM', `Loaded ${data.length} records from ${table}.`);
      } catch (e) {
        elements.triageTableBody.innerHTML = `<tr><td style="padding: 12px; color: #ff5555;">Error: ${e}</td></tr>`;
        logMessage('ERROR', 'Triage query failed: ' + e);
      }
    });
  }

  // Triage Start button click
  document.getElementById('btn-start-triage').addEventListener('click', async (e) => {
    e.preventDefault();
    const destPath = document.getElementById('triage-dest-path').value;
    if (!destPath) {
      alert('Please select a triage destination directory.');
      return;
    }
    const collect_registry = document.getElementById('triage-registry').checked;
    const collect_volatile = document.getElementById('triage-volatile').checked;
    const collect_browsers = document.getElementById('triage-browsers').checked;
    const collect_eventlogs = document.getElementById('triage-eventlogs').checked;

    try {
      state.activeJob = true;
      toggleUIJobActive(true);
      resetStats();
      logMessage('SYSTEM', 'Initiating rapid triage collection...');
      
      await invoke('start_triage', {
        destPath,
        collectRegistry: collect_registry,
        collectVolatile: collect_volatile,
        collectBrowsers: collect_browsers,
        collectEventlogs: collect_eventlogs
      });
      
      // Auto-load DB path for analysis workbench if it succeeds
      if (elements.triageDbPath) {
         elements.triageDbPath.value = destPath + "\\triage.db";
      }
    } catch (err) {
      state.activeJob = false;
      toggleUIJobActive(false);
      logMessage('ERROR', 'Failed to start triage: ' + err);
      alert('Failed to start triage: ' + err);
    }
  });

  // Triage Workbench Renderer
  function renderTriageTable(data) {
    if (!data || data.length === 0) {
      elements.triageTableHead.innerHTML = '<th>No Data</th>';
      elements.triageTableBody.innerHTML = '<tr><td style="padding: 12px; color: var(--text-muted);">No records found in this table.</td></tr>';
      return;
    }
    
    // Build Headers from first row keys
    const keys = Object.keys(data[0]);
    let theadHtml = '';
    keys.forEach(key => {
      theadHtml += `<th style="padding: 12px; font-weight: 600; text-transform: capitalize;">${key.replace(/_/g, ' ')}</th>`;
    });
    elements.triageTableHead.innerHTML = theadHtml;
    
    // Build Rows
    let tbodyHtml = '';
    data.forEach(row => {
      tbodyHtml += '<tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">';
      keys.forEach(key => {
        let val = row[key];
        if (val === null || val === undefined) val = '';
        // Truncate very long texts
        if (typeof val === 'string' && val.length > 200) val = val.substring(0, 200) + '...';
        tbodyHtml += `<td style="padding: 10px 12px; word-break: break-word;">${val}</td>`;
      });
      tbodyHtml += '</tr>';
    });
    elements.triageTableBody.innerHTML = tbodyHtml;
  }

  // Live Acquisition Buttons
  document.getElementById('btn-refresh-volumes').addEventListener('click', async () => {
    try {
      const select = document.getElementById('live-volume-select');
      select.innerHTML = '<option value="">Scanning...</option>';
      const vols = await invoke('list_volumes');
      select.innerHTML = vols.map(v => `<option value="${v.letter}">${v.letter} [${v.label}] - ${v.fs_type}</option>`).join('');
      if (vols.length === 0) select.innerHTML = '<option value="">No volumes found</option>';
      logMessage('SYSTEM', `Refreshed system volumes (${vols.length} found).`);
    } catch (e) {
      logMessage('ERROR', 'Failed to list volumes: ' + e);
    }
  });

  document.getElementById('btn-browse-live-dest').addEventListener('click', async () => {
    try {
      const folder = await invoke('browse_folder');
      if (folder) {
        document.getElementById('live-dest-path').value = folder;
        logMessage('SYSTEM', 'Set live acquisition destination directory: ' + folder);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse folder: ' + e);
    }
  });

  document.getElementById('btn-browse-ram-tool').addEventListener('click', async () => {
    try {
      const file = await invoke('browse_file', { ext: 'exe' });
      if (file) {
        document.getElementById('live-ram-tool').value = file;
        logMessage('SYSTEM', 'Set custom RAM acquisition tool: ' + file);
      }
    } catch (e) {
      logMessage('ERROR', 'Failed to browse file: ' + e);
    }
  });

  document.getElementById('btn-start-live').addEventListener('click', async (e) => {
    e.preventDefault();
    const volume = document.getElementById('live-volume-select').value;
    const destPath = document.getElementById('live-dest-path').value;
    
    if (!volume || !destPath) {
      alert('Please select both a system volume and a destination folder.');
      return;
    }

    const config = {
      volume,
      dest_path: destPath,
      evidence_id: document.getElementById('live-evidence-id').value,
      notes: document.getElementById('live-notes').value,
      case_number: document.getElementById('live-case-num').value,
      examiner: document.getElementById('live-examiner').value,
      capture_ram: document.getElementById('live-cb-ram').checked,
      capture_locked_files: document.getElementById('live-cb-locked').checked,
      run_consistency_check: document.getElementById('live-cb-consistency').checked,
      image_vss: document.getElementById('live-cb-image-vss').checked,
      auto_cleanup_vss: document.getElementById('live-cb-cleanup').checked,
      ram_tool_path: document.getElementById('live-ram-tool').value || null,
      hash_algorithms: ['SHA256']
    };

    try {
      state.activeJob = true;
      toggleUIJobActive(true);
      resetStats();
      logMessage('SYSTEM', 'Initiating live system acquisition pipeline...');
      await invoke('start_live_acquisition', { configInput: config });
    } catch (err) {
      state.activeJob = false;
      toggleUIJobActive(false);
      logMessage('ERROR', 'Failed to start live acquisition: ' + err);
      alert('Failed to start live acquisition: ' + err);
    }
  });

  // Timeline Handlers
  if (elements.btnBrowseTimelineImage) {
    elements.btnBrowseTimelineImage.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'dd' });
        if (file) {
          elements.timelineImagePath.value = file;
          logMessage('SYSTEM', 'Selected image for timeline: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse image: ' + e);
      }
    });
  }

  if (elements.btnBrowseTimelineDest) {
    elements.btnBrowseTimelineDest.addEventListener('click', async () => {
      try {
        const folder = await invoke('browse_folder');
        if (folder) {
          elements.timelineDestPath.value = folder;
          logMessage('SYSTEM', 'Selected timeline destination: ' + folder);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse folder: ' + e);
      }
    });
  }

  if (elements.btnStartTimeline) {
    elements.btnStartTimeline.addEventListener('click', async (e) => {
      e.preventDefault();
      const imagePath = elements.timelineImagePath.value;
      const destPath = elements.timelineDestPath.value;
      
      if (!imagePath || !destPath) {
        alert('Please select both an image file and a destination directory.');
        return;
      }
      
      try {
        logMessage('SYSTEM', 'Starting timeline generation... This may take a while.');
        elements.btnStartTimeline.disabled = true;
        elements.btnStartTimeline.textContent = 'Generating...';
        
        const result = await invoke('generate_image_timeline', {
          imagePath: imagePath,
          outputDir: destPath
        });
        
        logMessage('SYSTEM', result);
        alert(result);
      } catch (err) {
        logMessage('ERROR', 'Failed to generate timeline: ' + err);
        alert('Failed to generate timeline: ' + err);
      } finally {
        elements.btnStartTimeline.disabled = false;
        elements.btnStartTimeline.textContent = '▶ Generate Timeline';
      }
    });
  }

  // RAM Analysis Handlers
  if (elements.btnBrowseRamImage) {
    elements.btnBrowseRamImage.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'raw' });
        if (file) {
          elements.ramImagePath.value = file;
          logMessage('SYSTEM', 'Selected memory dump for analysis: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse memory dump: ' + e);
      }
    });
  }

  if (elements.btnBrowseRamVol) {
    elements.btnBrowseRamVol.addEventListener('click', async () => {
      try {
        const file = await invoke('browse_file', { ext: 'exe' });
        if (file) {
          elements.ramVolPath.value = file;
          logMessage('SYSTEM', 'Selected Volatility 3 executable: ' + file);
        }
      } catch (e) {
        logMessage('ERROR', 'Failed to browse Volatility executable: ' + e);
      }
    });
  }

  if (elements.btnStartRamAnalysis) {
    elements.btnStartRamAnalysis.addEventListener('click', async (e) => {
      e.preventDefault();
      const imagePath = elements.ramImagePath.value;
      const volPath = elements.ramVolPath.value;
      
      if (!imagePath || !volPath) {
        alert('Please select both a memory dump file and the Volatility 3 executable/script path.');
        return;
      }
      
      const config = {
        image_path: imagePath,
        vol_path: volPath,
        profile: elements.ramProfileSelect.value,
        enrich_vt: elements.ramEnrichVt ? elements.ramEnrichVt.checked : false,
        enrich_mb: false,
        enrich_abuseip: elements.ramEnrichAbuseIp ? elements.ramEnrichAbuseIp.checked : false,
        vt_key: elements.ramKeyVt ? elements.ramKeyVt.value : '',
        mb_key: '',
        abuseip_key: elements.ramKeyAbuseIp ? elements.ramKeyAbuseIp.value : ''
      };
      
      try {
        logMessage('VOLATILITY', `Starting Volatility 3 analysis [Profile: ${config.profile}]...`);
        elements.btnStartRamAnalysis.disabled = true;
        elements.btnStartRamAnalysis.textContent = 'Running Analysis...';
        
        await invoke('start_volatility_analysis', { config });
      } catch (err) {
        logMessage('ERROR', 'Failed to start Volatility analysis: ' + err);
        alert('Failed to start Volatility analysis: ' + err);
        elements.btnStartRamAnalysis.disabled = false;
        elements.btnStartRamAnalysis.textContent = '▶ Start Volatility Analysis';
      }
    });
  }

  // Listen to Tauri Backend events
  listen('acquisition-event', (event) => {
    handleBackendEvent(event.payload);
  });

  listen('volatility-event', (event) => {
    const { type, data } = event.payload;
    if (type === 'Log') {
      logMessage('VOLATILITY', data);
    } else if (type === 'Error') {
      logMessage('ERROR', '[VOLATILITY ERROR] ' + data);
      alert('Volatility Analysis Error:\n' + data);
      if (elements.btnStartRamAnalysis) {
        elements.btnStartRamAnalysis.disabled = false;
        elements.btnStartRamAnalysis.textContent = '▶ Start Volatility Analysis';
      }
    } else if (type === 'Finished') {
      logMessage('SYSTEM', '=== VOLATILITY ANALYSIS COMPLETED ===');
      alert('Volatility Analysis Completed!');
      if (elements.btnStartRamAnalysis) {
        elements.btnStartRamAnalysis.disabled = false;
        elements.btnStartRamAnalysis.textContent = '▶ Start Volatility Analysis';
      }
    }
  });
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.add('hidden'));
  document.querySelectorAll('.tab-content').forEach(panel => panel.classList.add('hidden'));
  
  if (tabName === 'imaging') {
    document.getElementById('btn-tab-imaging').classList.add('active');
    document.getElementById('tab-imaging-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.remove('hidden');
  } else if (tabName === 'triage') {
    document.getElementById('btn-tab-triage').classList.add('active');
    document.getElementById('tab-triage-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'live') {
    document.getElementById('btn-tab-live').classList.add('active');
    document.getElementById('tab-live-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
    // Auto-refresh volumes if empty
    const volSelect = document.getElementById('live-volume-select');
    if (volSelect && volSelect.options.length <= 1) {
      document.getElementById('btn-refresh-volumes').click();
    }
  } else if (tabName === 'timeline') {
    document.getElementById('btn-tab-timeline').classList.add('active');
    document.getElementById('tab-timeline-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'cases') {
    document.getElementById('btn-tab-cases').classList.add('active');
    document.getElementById('tab-cases-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  } else if (tabName === 'ram') {
    document.getElementById('btn-tab-ram').classList.add('active');
    document.getElementById('tab-ram-content').classList.remove('hidden');
    document.getElementById('sidebar-panel').classList.add('hidden');
  }
}

function setImagingMode(mode) {
  if (state.activeJob) return;
  
  state.imagingMode = mode;
  if (mode === 'Physical') {
    elements.modePhysical.classList.add('active');
    elements.modeLogical.classList.remove('active');
    elements.physicalContainer.classList.remove('hidden');
    elements.logicalContainer.classList.add('hidden');
    logMessage('SYSTEM', 'Switched to Physical Sector-by-Sector imaging mode.');
  } else {
    elements.modePhysical.classList.remove('active');
    elements.modeLogical.classList.add('active');
    elements.physicalContainer.classList.add('hidden');
    elements.logicalContainer.classList.remove('hidden');
    logMessage('SYSTEM', 'Switched to Logical File/Directory imaging mode.');
  }
}

// Check checkpoint
async function checkCheckpointExists(destPath) {
  try {
    const exists = await invoke('check_checkpoint', { destPath });
    if (exists) {
      elements.btnResumeAcquisition.classList.remove('hidden');
      logMessage('SYSTEM', 'Detected partial checkpoint. You can resume this acquisition job.');
    } else {
      elements.btnResumeAcquisition.classList.add('hidden');
    }
  } catch (e) {
    console.error(e);
  }
}

// Device Scanner
async function doRescan() {
  if (state.activeJob) return;

  elements.deviceList.innerHTML = '<div class="info-message">Scanning system block devices...</div>';
  logMessage('SYSTEM', 'Scanning block devices...');
  
  try {
    const devs = await invoke('scan_devices');
    state.devices = devs;
    elements.deviceList.innerHTML = '';
    
    if (devs.length === 0) {
      elements.deviceList.innerHTML = '<div class="info-message">No physical devices detected. Run in Elevated Mode.</div>';
      return;
    }
    
    devs.forEach((dev, idx) => {
      const card = document.createElement('div');
      card.className = 'device-card';
      if (state.selectedDeviceIndex === idx) {
        card.classList.add('selected');
      }
      
      let partitionsHtml = '';
      if (dev.partitions && dev.partitions.length > 0) {
        partitionsHtml = `
          <div class="partition-list">
            ${dev.partitions.map(part => `
              <div class="partition-item">
                <span class="partition-icon">↳ 📂</span>
                <span class="partition-name">${part.name}</span>
                <span class="partition-type">[${part.fs_type}]</span>
                <span class="partition-size">${formatBytes(part.size)}</span>
              </div>
            `).join('')}
          </div>
        `;
      }

      card.innerHTML = `
        <div class="device-icon-row">
          <div class="device-icon">💾</div>
          <div class="device-info">
            <div class="device-meta-row">
              <span class="device-path">${dev.path} <span class="chip chip-blue">${dev.device_type}</span></span>
              <span class="device-size">${formatBytes(dev.size)}</span>
            </div>
            <div class="device-model">${dev.vendor} ${dev.model} ${dev.serial ? '(S/N: ' + dev.serial + ')' : ''}</div>
            <div class="device-health-row">⚡ Health: <span class="chip chip-green">${dev.smart_health || 'Healthy (100% Life)'}</span></div>
          </div>
        </div>
        ${partitionsHtml}
      `;
      
      card.addEventListener('click', () => {
        if (state.activeJob) return;
        state.selectedDeviceIndex = idx;
        
        // Remove selection from others
        document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        
        logMessage('SYSTEM', `Selected device: ${dev.path} (${formatBytes(dev.size)})`);
        
        // Populate default destination path
        if (!elements.inputDestPath.value) {
          const cleanName = dev.name.replace(/\\\\.\\/g, '').replace(/[\/\\?%*:|"<>\s]/g, '_');
          elements.inputDestPath.value = `C:\\${cleanName}.dd`;
          checkCheckpointExists(`C:\\${cleanName}.dd`);
        }
      });
      
      elements.deviceList.appendChild(card);
    });

    logMessage('SYSTEM', `Discovered ${devs.length} device(s).`);
  } catch (err) {
    elements.deviceList.innerHTML = `<div class="info-message error-text">Failed to scan devices: ${err}</div>`;
    logMessage('ERROR', 'Scan failed: ' + err);
  }
}

// Trigger Acquisition
async function handleStartAcquisition(isResume) {
  if (state.activeJob) return;

  // Validate form inputs
  if (!elements.inputEvidenceId.value || !elements.inputCaseNumber.value || !elements.inputExaminer.value) {
    alert('Please fill out all required configuration fields (Evidence ID, Case Number, Examiner Name).');
    return;
  }

  let sourcePath = '';
  if (state.imagingMode === 'Physical') {
    if (state.selectedDeviceIndex === null) {
      alert('Please select a source physical block device.');
      return;
    }
    sourcePath = state.devices[state.selectedDeviceIndex].path;
  } else {
    sourcePath = elements.logicalSourceInput.value;
    if (!sourcePath) {
      alert('Please select a source logical directory.');
      return;
    }
  }

  const destPath = elements.inputDestPath.value;
  if (!destPath) {
    alert('Please specify a destination path.');
    return;
  }

  // Collect active hashes
  const hash_algorithms = [];
  if (elements.hashMd5.checked) hash_algorithms.push('MD5');
  if (elements.hashSha1.checked) hash_algorithms.push('SHA1');
  if (elements.hashSha256.checked) hash_algorithms.push('SHA256');
  if (elements.hashSha512.checked) hash_algorithms.push('SHA512');

  if (hash_algorithms.length === 0) {
    alert('Please enable at least one cryptographic hash algorithm.');
    return;
  }

  // Calculate splitting size in MB
  let split_size_mb = null;
  const splitVal = elements.selectSplit.value;
  if (splitVal === 'Custom') {
    const parsed = parseInt(elements.inputSplitSize.value, 10);
    if (isNaN(parsed) || parsed <= 0) {
      alert('Please enter a valid custom split size in MB.');
      return;
    }
    split_size_mb = parsed;
  } else if (splitVal !== 'None') {
    split_size_mb = parseInt(splitVal, 10);
  }

  const read_verification = elements.checkReadVerification.checked;

  const config = {
    imaging_mode: state.imagingMode,
    source_path: sourcePath,
    dest_path: destPath,
    evidence_id: elements.inputEvidenceId.value,
    notes: elements.inputNotes.value,
    case_number: elements.inputCaseNumber.value,
    examiner: elements.inputExaminer.value,
    format_mode: elements.selectFormat.value,
    hash_verification: elements.selectVerification.value,
    block_size_kb: parseInt(elements.selectBlocksize.value, 10),
    hash_algorithms,
    compression: elements.selectCompression.value,
    resume_mode: isResume,
    split_size_mb,
    read_verification,
    keywords: elements.inputKeywords.value ? elements.inputKeywords.value.split(',').map(s => s.trim()).filter(s => s.length > 0) : [],
    yara_rules_path: elements.inputYaraPath.value || null,
    sparse: elements.checkSparse.checked,
    digital_signature: elements.checkDigitalSignature.checked
  };

  try {
    state.activeJob = true;
    toggleUIJobActive(true);
    
    // Clear display progress stats
    resetStats();
    
    logMessage('SYSTEM', 'Initiating acquisition job...');
    await invoke('start_acquisition', { configInput: config });
  } catch (e) {
    state.activeJob = false;
    toggleUIJobActive(false);
    logMessage('ERROR', 'Failed to start acquisition: ' + e);
    alert('Failed to start: ' + e);
  }
}

// Toggle layout state when job starts/cancels
function toggleUIJobActive(active) {
  if (active) {
    elements.monitorIdle.classList.add('hidden');
    elements.monitorActive.classList.remove('hidden');
    // Disable configuration forms
    toggleFormInputs(true);
    elements.btnRescan.disabled = true;
  } else {
    elements.monitorIdle.classList.remove('hidden');
    elements.monitorActive.classList.add('hidden');
    // Enable configuration forms
    toggleFormInputs(false);
    elements.btnRescan.disabled = false;
    // Check destination file again for resume state
    checkCheckpointExists(elements.inputDestPath.value);
  }
}

function toggleFormInputs(disabled) {
  const inputs = [
    elements.inputEvidenceId, elements.inputCaseNumber, elements.inputExaminer, elements.inputNotes,
    elements.selectFormat, elements.selectVerification, elements.selectBlocksize, elements.selectCompression,
    elements.selectSplit, elements.inputSplitSize, elements.checkReadVerification,
    elements.hashMd5, elements.hashSha1, elements.hashSha256, elements.hashSha512,
    elements.btnBrowseSource, elements.btnBrowseDest,
    elements.inputKeywords, elements.checkSparse, elements.checkDigitalSignature,
    elements.inputYaraPath, elements.btnBrowseYara,
    document.getElementById('btn-browse-triage-dest'),
    document.getElementById('btn-start-triage'),
    document.getElementById('btn-browse-mount-src'),
    document.getElementById('btn-browse-mount-point'),
    document.getElementById('btn-verify-image'),
    document.getElementById('btn-mount-image')
  ];
  inputs.forEach(input => {
    if (input) input.disabled = disabled;
  });
}

function resetStats() {
  elements.txtStatSpeed.textContent = '0.00 MB/s';
  elements.txtStatEta.textContent = '0s';
  elements.txtStatBad.textContent = '0';
  elements.txtStatPercent.textContent = '0.0%';
  elements.progressBarFill.style.width = '0%';
  elements.txtBytesProgress.textContent = '0 B / 0 B';
}

// Handle Tauri emitted progress events
function handleBackendEvent(event) {
  const { type, data } = event;

  if (type === 'Log') {
    logMessage('ACQUISITION', data);
  } else if (type === 'Progress') {
    const { bytes_read, total_size, speed_bps, bad_sectors } = data;
    
    // Percentage
    const pct = total_size > 0 ? (bytes_read / total_size * 100) : 0;
    elements.txtStatPercent.textContent = pct.toFixed(1) + '%';
    elements.progressBarFill.style.width = pct.toFixed(1) + '%';
    
    // Speed
    const speedMb = speed_bps / 1000000;
    elements.txtStatSpeed.textContent = speedMb.toFixed(2) + ' MB/s';
    
    // ETA
    const remainingBytes = total_size - bytes_read;
    const etaSecs = speed_bps > 0 ? Math.ceil(remainingBytes / speed_bps) : 0;
    elements.txtStatEta.textContent = formatDuration(etaSecs);
    
    // Bad Sectors
    elements.txtStatBad.textContent = bad_sectors.toString();
    if (bad_sectors > 0) {
      elements.txtStatBad.className = 'stat-val text-red';
    } else {
      elements.txtStatBad.className = 'stat-val text-teal';
    }

    // Bytes label
    elements.txtBytesProgress.textContent = `${formatBytes(bytes_read)} / ${formatBytes(total_size)}`;
  } else if (type === 'Finished') {
    const { bytes_read, bad_sectors, hashes } = data;
    logMessage('SYSTEM', '=== ACQUISITION COMPLETED SUCCESSFULLY ===');
    logMessage('SYSTEM', `Total Imaged Size: ${formatBytes(bytes_read)}`);
    logMessage('SYSTEM', `Bad Sectors Discovered: ${bad_sectors}`);
    
    for (const algo in hashes) {
      logMessage('ACQUISITION', `${algo}: ${hashes[algo]}`);
    }
    
    alert('Acquisition Job Completed and Verified!');
    state.activeJob = false;
    toggleUIJobActive(false);
  } else if (type === 'KeywordHit') {
    logMessage('WARNING', `[KEYWORD HIT] Found '${data.keyword}' at offset ${data.offset}`);
  } else if (type === 'YaraHit') {
    const tags = data.tags.length > 0 ? ` [${data.tags.join(', ')}]` : '';
    logMessage('WARNING', `[YARA HIT] Rule '${data.rule_name}'${tags} matched at offset ${data.offset}`);
  } else if (type === 'Error') {
    logMessage('ERROR', 'Critical backend error: ' + data);
    alert('Forensic Acquisition Error:\n' + data);
    state.activeJob = false;
    toggleUIJobActive(false);
  }
}

// Log view utility
function logMessage(level, text) {
  const entry = document.createElement('div');
  entry.className = `log-entry log-${level.toLowerCase()}`;
  
  const timestamp = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
  entry.textContent = `[${timestamp} IST] [${level}] ${text}`;
  
  elements.consoleLogs.appendChild(entry);
  
  // Auto scroll to bottom
  elements.consoleLogs.scrollTop = elements.consoleLogs.scrollHeight;
}

// Helper formatting utilities
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1000;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(secs) {
  if (secs === 0) return '0s';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  
  let str = '';
  if (h > 0) str += `${h}h `;
  if (m > 0 || h > 0) str += `${m}m `;
  str += `${s}s`;
  return str;
}

// Boot UI
document.addEventListener('DOMContentLoaded', init);

// Case Management Functions
async function loadCases() {
  const container = document.getElementById('cases-list');
  container.innerHTML = '<div class="info-message">Loading cases...</div>';
  try {
    const cases = await invoke('get_cases');
    if (cases.length === 0) {
      container.innerHTML = '<div class="info-message">No cases found in the database.</div>';
      return;
    }
    
    let html = '<table style="width: 100%; border-collapse: collapse; color: var(--text-main);">';
    html += '<tr style="border-bottom: 1px solid var(--color-border);"><th style="text-align: left; padding: 8px;">Case Number</th><th style="text-align: left; padding: 8px;">Examiner</th><th style="text-align: left; padding: 8px;">Created At</th><th style="text-align: right; padding: 8px;">Actions</th></tr>';
    
    for (const c of cases) {
      html += `<tr style="border-bottom: 1px solid var(--color-bg);">
        <td style="padding: 8px; font-family: 'JetBrains Mono', monospace;">${c.case_number}</td>
        <td style="padding: 8px;">${c.examiner_name}</td>
        <td style="padding: 8px;">${c.created_at}</td>
        <td style="padding: 8px; text-align: right;">
          <button class="btn btn-secondary btn-sm" onclick="exportCaseReport(${c.id}, '${c.case_number}')">Export Report</button>
        </td>
      </tr>`;
    }
    html += '</table>';
    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="info-message" style="color: red;">Failed to load cases: ${e}</div>`;
  }
}

async function exportCaseReport(caseId, caseNumber) {
  try {
    const file = await invoke('browse_file', { ext: 'html' });
    if (file) {
      logMessage('SYSTEM', `Exporting report for case ${caseNumber} to ${file}...`);
      await invoke('export_case_report', { caseId: caseId, exportPath: file });
      logMessage('SYSTEM', `Report for case ${caseNumber} exported successfully.`);
    }
  } catch (e) {
    logMessage('ERROR', `Failed to export report for case ${caseNumber}: ` + e);
    alert('Failed to export report: ' + e);
  }
}
