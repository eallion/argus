/**
 * Argus Dashboard Client Application
 */

// Application State
const state = {
  hasAdmin: false,
  isAuthenticated: false,
  username: '',
  totpEnabled: false,
  turnstileEnabled: false,
  turnstileSiteKey: '',
  turnstilePassed: false,
  turnstileToken: '',
  temp2FAToken: '',
  icp: '',
  mps: '',
  domains: [],
  settings: null,
  activeFilter: 'all',
  searchQuery: '',
  domainGroupFilter: '',
  viewMode: 'groups', // 'groups' (一级首页：仅显示主域名) | 'subdomains' (二级页面：某主域名的子域名) | 'all' (显示全部监控目标)
  currentApex: '', // 二级子域名页面对应的主域名
  currentPage: 1, // 当前页码 (从 1 开始)
  pageSize: 20, // 每页条数 (10, 20, 50, 100)
  editingChannels: [],
  editingChannelIndex: -1,
  formMultiHostNodes: [],
  dnsProvidersMeta: [],
  savedDNSProviders: [],
  dnsSyncConfigs: [],
  notifications: [],
  unreadNotificationsCount: 0,
  pendingAggregatedCount: 0,
};

// DOM Elements
const elements = {
  setupView: document.getElementById('setup-view'),
  loginView: document.getElementById('login-view'),
  dashboardView: document.getElementById('dashboard-view'),
  setupForm: document.getElementById('setup-form'),
  loginForm: document.getElementById('login-form'),
  login2FAForm: document.getElementById('login-2fa-form'),
  passwordForm: document.getElementById('password-form'),
  domainForm: document.getElementById('domain-form'),
  settingsForm: document.getElementById('settings-form'),
  domainsTableHead: document.getElementById('domains-table-head'),
  domainsTableBody: document.getElementById('domains-table-body'),
  searchInput: document.getElementById('search-input'),
  domainGroupSelect: document.getElementById('domain-group-select'),
  viewModeTabs: document.querySelectorAll('.view-mode-tab'),
  breadcrumbBar: document.getElementById('breadcrumb-bar'),
  btnBackToGroups: document.getElementById('btn-back-to-groups'),
  crumbLinkRoot: document.getElementById('crumb-link-root'),
  crumbCurrentDomain: document.getElementById('crumb-current-domain'),
  breadcrumbDomainMeta: document.getElementById('breadcrumb-domain-meta'),
  tablePagination: document.getElementById('table-pagination'),
  paginationInfo: document.getElementById('pagination-info'),
  btnPagePrev: document.getElementById('btn-page-prev'),
  btnPageNext: document.getElementById('btn-page-next'),
  paginationPages: document.getElementById('pagination-pages'),
  pageSizeSelect: document.getElementById('page-size-select'),
  filterTabs: document.querySelectorAll('.filter-tab'),
  btnCheckAll: document.getElementById('btn-check-all'),
  btnAddModal: document.getElementById('btn-add-modal'),
  btnBatchModal: document.getElementById('btn-batch-modal'),
  btnNotificationsCenter: document.getElementById('btn-notifications-center'),
  modalNotificationsCenter: document.getElementById('modal-notifications-center'),
  notificationUnreadBadge: document.getElementById('notification-unread-badge'),
  centerUnreadPill: document.getElementById('center-unread-pill'),
  btnRefreshNotifications: document.getElementById('btn-refresh-notifications'),
  chkUnreadOnly: document.getElementById('chk-unread-only'),
  btnMarkAllRead: document.getElementById('btn-mark-all-read'),
  btnClearNotifications: document.getElementById('btn-clear-notifications'),
  notificationListContainer: document.getElementById('notification-list-container'),
  notificationEmptyState: document.getElementById('notification-empty-state'),
  settingNotificationMode: document.getElementById('setting-notification-mode'),
  settingNotificationBatchInterval: document.getElementById('setting-notification-batch-interval'),
  batchIntervalGroup: document.getElementById('batch-interval-group'),
  batchActionsBar: document.getElementById('batch-actions-bar'),
  btnFlushBatch: document.getElementById('btn-flush-batch'),
  batchPendingPill: document.getElementById('batch-pending-pill'),
  batchPendingCount: document.getElementById('batch-pending-count'),
  // DNS API Sync Elements
  dnsSyncForm: document.getElementById('dns-api-sync-form'),
  dnsProviderSelect: document.getElementById('dns-sync-provider-select'),
  dnsOptgroupSaved: document.getElementById('dns-optgroup-saved'),
  dnsSyncDomain: document.getElementById('dns-sync-domain'),
  dnsCustomCredsBox: document.getElementById('dns-sync-custom-creds'),
  dnsAuthKeyInput: document.getElementById('dns-sync-auth-key'),
  dnsAuthSecretInput: document.getElementById('dns-sync-auth-secret'),
  dnsZoneIdInput: document.getElementById('dns-sync-zone-id'),
  dnsSaveCredsCheck: document.getElementById('dns-sync-save-creds'),
  dnsBlacklistText: document.getElementById('dns-sync-blacklist'),
  dnsRdapModeSelect: document.getElementById('dns-sync-rdap-mode'),
  dnsDefaultPortInput: document.getElementById('dns-sync-default-port'),
  dnsAutoTaskCheck: document.getElementById('dns-sync-auto-task'),
  btnDnsPreview: document.getElementById('btn-dns-preview'),
  btnDnsExecuteSync: document.getElementById('btn-dns-execute-sync'),
  dnsPreviewContainer: document.getElementById('dns-preview-container'),
  previewTotalCount: document.getElementById('preview-total-count'),
  previewAllowedCount: document.getElementById('preview-allowed-count'),
  previewBlockedCount: document.getElementById('preview-blocked-count'),
  dnsPreviewAllowedList: document.getElementById('dns-preview-allowed-list'),
  dnsPreviewBlockedBox: document.getElementById('dns-preview-blocked-box'),
  dnsPreviewBlockedList: document.getElementById('dns-preview-blocked-list'),
  dnsProvidersList: document.getElementById('dns-providers-list'),
  dnsSyncConfigsList: document.getElementById('dns-sync-configs-list'),
  btnAddDNSProvider: document.getElementById('btn-add-dns-provider'),
  dnsProviderForm: document.getElementById('dns-provider-form'),
  batchImportForm: document.getElementById('batch-import-form'),
  batchImportText: document.getElementById('batch-import-text'),
  btnBatchClear: document.getElementById('btn-batch-clear'),
  btnExportJson: document.getElementById('btn-export-json'),
  btnExportTxt: document.getElementById('btn-export-txt'),
  backupRestoreForm: document.getElementById('backup-restore-form'),
  backupFileInput: document.getElementById('backup-file-input'),
  btnSettingsModal: document.getElementById('btn-settings-modal'),
  btnPasswordModal: document.getElementById('btn-password-modal'),
  btnLogout: document.getElementById('btn-logout'),
  btnPasskeyLogin: document.getElementById('btn-passkey-login'),
  btnCancel2FA: document.getElementById('btn-cancel-2fa'),
  btnTestNotification: document.getElementById('btn-test-notification'),
  turnstileBox: document.getElementById('turnstile-box'),
  turnstileContainer: document.getElementById('turnstile-container'),
  turnstilePassedTag: document.getElementById('turnstile-passed-tag'),
  appriseEnabledCheck: document.getElementById('cfg-apprise-enabled'),
  appriseDetails: document.getElementById('apprise-details'),
  appriseWrapper: document.getElementById('apprise-wrapper'),
  appriseUnavailableBanner: document.getElementById('apprise-unavailable-banner'),
  appriseStatusBadge: document.getElementById('apprise-status-badge'),
  // KPIs
  kpiTotal: document.getElementById('kpi-total-domains'),
  kpiHealthy: document.getElementById('kpi-ssl-healthy'),
  kpiWarning: document.getElementById('kpi-warning-count'),
  kpiPolicy: document.getElementById('kpi-policy'),
  kpiCards: document.querySelectorAll('.kpi-card[data-filter]'),
  kpiCardPolicy: document.getElementById('kpi-card-policy'),
  countAll: document.getElementById('count-all'),
  countWarning: document.getElementById('count-warning'),
  countHealthy: document.getElementById('count-healthy'),
  toastContainer: document.getElementById('toast-container'),
};

// Toast notification helper
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  elements.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// Modal handling
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove('hidden');
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.add('hidden');
}

// 全局通用确认对话框 (替代浏览器原生 window.confirm)
function confirmModal(message, optionsOrCallback) {
  let onConfirm = null;
  let title = '操作确认';
  let okText = '确定';
  let cancelText = '取消';
  let okClass = 'btn-danger';
  let isDanger = true;

  if (typeof optionsOrCallback === 'function') {
    onConfirm = optionsOrCallback;
  } else if (optionsOrCallback && typeof optionsOrCallback === 'object') {
    onConfirm = optionsOrCallback.onConfirm;
    if (optionsOrCallback.title) title = optionsOrCallback.title;
    if (optionsOrCallback.okText) okText = optionsOrCallback.okText;
    if (optionsOrCallback.cancelText) cancelText = optionsOrCallback.cancelText;
    if (optionsOrCallback.okClass) okClass = optionsOrCallback.okClass;
    if (optionsOrCallback.isDanger !== undefined) isDanger = optionsOrCallback.isDanger;
  }

  const modalEl = document.getElementById('modal-confirm');
  const titleEl = document.getElementById('modal-confirm-title');
  const msgEl = document.getElementById('modal-confirm-message');
  const inputWrap = document.getElementById('modal-confirm-input-wrap');
  const okBtn = document.getElementById('modal-confirm-btn-ok');
  const cancelBtn = document.getElementById('modal-confirm-btn-cancel');
  const iconBox = document.getElementById('modal-confirm-icon-box');

  if (!modalEl || !msgEl || !okBtn) {
    if (onConfirm) onConfirm();
    return;
  }

  if (titleEl) titleEl.textContent = title;
  msgEl.textContent = message;
  if (inputWrap) inputWrap.classList.add('hidden');
  if (cancelBtn) {
    cancelBtn.textContent = cancelText;
    cancelBtn.classList.remove('hidden');
  }

  if (iconBox) {
    if (isDanger) {
      iconBox.style.background = 'rgba(244, 63, 94, 0.12)';
      iconBox.style.color = 'var(--color-rose)';
    } else {
      iconBox.style.background = 'rgba(59, 130, 246, 0.12)';
      iconBox.style.color = 'var(--color-blue)';
    }
  }

  okBtn.textContent = okText;
  okBtn.className = `btn ${okClass}`;

  const newOkBtn = okBtn.cloneNode(true);
  okBtn.parentNode.replaceChild(newOkBtn, okBtn);

  newOkBtn.onclick = async () => {
    closeModal('modal-confirm');
    if (onConfirm) {
      try {
        await onConfirm();
      } catch (err) {
        console.error('confirmModal callback error:', err);
      }
    }
  };

  openModal('modal-confirm');
}

// 全局通用输入对话框 (替代浏览器原生 window.prompt)
function promptModal(title, message, optionsOrCallback) {
  let onConfirm = null;
  let placeholder = '请输入内容';
  let inputType = 'text';
  let defaultValue = '';

  if (typeof optionsOrCallback === 'function') {
    onConfirm = optionsOrCallback;
  } else if (optionsOrCallback && typeof optionsOrCallback === 'object') {
    onConfirm = optionsOrCallback.onConfirm;
    if (optionsOrCallback.placeholder) placeholder = optionsOrCallback.placeholder;
    if (optionsOrCallback.inputType) inputType = optionsOrCallback.inputType;
    if (optionsOrCallback.defaultValue) defaultValue = optionsOrCallback.defaultValue;
  }

  const modalEl = document.getElementById('modal-confirm');
  const titleEl = document.getElementById('modal-confirm-title');
  const msgEl = document.getElementById('modal-confirm-message');
  const inputWrap = document.getElementById('modal-confirm-input-wrap');
  const inputEl = document.getElementById('modal-confirm-input');
  const okBtn = document.getElementById('modal-confirm-btn-ok');
  const cancelBtn = document.getElementById('modal-confirm-btn-cancel');

  if (!modalEl || !inputEl || !okBtn) return;

  if (titleEl) titleEl.textContent = title || '安全校验';
  if (msgEl) msgEl.textContent = message || '';
  if (cancelBtn) cancelBtn.classList.remove('hidden');

  if (inputWrap) inputWrap.classList.remove('hidden');
  inputEl.type = inputType;
  inputEl.placeholder = placeholder;
  inputEl.value = defaultValue;

  okBtn.textContent = '确定';
  okBtn.className = 'btn btn-primary';

  const newOkBtn = okBtn.cloneNode(true);
  okBtn.parentNode.replaceChild(newOkBtn, okBtn);

  const handleSubmit = async () => {
    const val = inputEl.value;
    closeModal('modal-confirm');
    if (onConfirm) {
      try {
        await onConfirm(val);
      } catch (err) {
        console.error('promptModal callback error:', err);
      }
    }
  };

  newOkBtn.onclick = handleSubmit;

  inputEl.onkeydown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSubmit();
    }
  };

  openModal('modal-confirm');
  setTimeout(() => inputEl.focus(), 100);
}

// 全局接管原生浏览器弹窗，杜绝弹出系统级对话框
window.alert = function(msg) {
  showToast(String(msg), 'info');
};
window.confirm = function(msg) {
  console.warn('Native confirm called, use confirmModal instead:', msg);
  return false;
};
window.prompt = function(msg) {
  console.warn('Native prompt called, use promptModal instead:', msg);
  return null;
};

// Universal modal close listeners
document.addEventListener('click', (e) => {
  const targetId = e.target.getAttribute('data-close-modal');
  if (targetId) {
    closeModal(targetId);
  }
});

function updateSettingsFooter(tabId) {
  const btn = document.getElementById('btn-test-notification');
  if (btn) {
    if (tabId === 'tab-notifications') {
      btn.classList.remove('hidden');
    } else {
      btn.classList.add('hidden');
    }
  }
}

// Settings Tab switcher
document.querySelectorAll('.settings-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.settings-panel').forEach(p => p.classList.add('hidden'));

    tab.classList.add('active');
    const targetPanel = document.getElementById(tab.dataset.tab);
    if (targetPanel) {
      targetPanel.classList.remove('hidden');
    }
    updateSettingsFooter(tab.dataset.tab);
  });
});

// Backup Modal Tab switcher
document.querySelectorAll('.backup-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.backup-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.backup-panel').forEach(p => p.classList.add('hidden'));

    tab.classList.add('active');
    const targetPanel = document.getElementById(tab.dataset.tab);
    if (targetPanel) {
      targetPanel.classList.remove('hidden');
    }
  });
});

// Apprise config toggle
elements.appriseEnabledCheck.addEventListener('change', (e) => {
  if (e.target.checked) {
    elements.appriseDetails.classList.remove('hidden');
  } else {
    elements.appriseDetails.classList.add('hidden');
  }
});

// Turnstile config toggle in settings
document.getElementById('cfg-turnstile-enabled').addEventListener('change', (e) => {
  const fields = document.getElementById('turnstile-settings-fields');
  if (e.target.checked) {
    fields.classList.remove('hidden');
  } else {
    fields.classList.add('hidden');
  }
});

// Apex/Root domain detector (真正的根域名，不含子域名及 www 前缀，用于触发 RDAP)
function isApexDomain(input) {
  if (!input) return false;
  let host = input.trim().toLowerCase().replace(/^(https?:\/\/)/, '').split('/')[0].split(':')[0];
  if (!host || /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host === 'localhost') {
    return false;
  }
  // www 视为子域名，默认不作为根域名查询到期时间
  if (host.startsWith('www.')) {
    return false;
  }
  const parts = host.split('.');
  if (parts.length < 2) return false;

  const compoundTLDs = [
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'co.uk', 'org.uk', 'me.uk', 'ac.uk',
    'com.hk', 'org.hk', 'edu.hk',
    'com.tw', 'org.tw', 'idv.tw',
    'co.jp', 'ne.jp', 'or.jp',
    'com.au', 'net.au', 'org.au'
  ];

  const lastTwo = parts.slice(-2).join('.');
  if (compoundTLDs.includes(lastTwo)) {
    return parts.length === 3;
  }
  return parts.length === 2;
}

// 根域名或 www 域名检测（用于新添/导入时默认置顶）
function isRootOrWWW(input) {
  if (!input) return false;
  let host = input.trim().toLowerCase().replace(/^(https?:\/\/)/, '').split('/')[0].split(':')[0];
  if (host.startsWith('www.')) {
    return isApexDomain(host.slice(4));
  }
  return isApexDomain(host);
}

// 提取主域名/根域名（如 sub.example.com -> example.com，用于域名聚合筛选）
function getApexDomain(input) {
  if (!input) return '';
  let host = input.trim().toLowerCase().replace(/^(https?:\/\/)/, '').split('/')[0].split(':')[0];
  if (!host || /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host === 'localhost') {
    return host;
  }
  if (host.startsWith('www.')) {
    host = host.slice(4);
  }
  const parts = host.split('.');
  if (parts.length <= 2) return host;

  const compoundTLDs = [
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'co.uk', 'org.uk', 'me.uk', 'ac.uk',
    'com.hk', 'org.hk', 'edu.hk',
    'com.tw', 'org.tw', 'idv.tw',
    'co.jp', 'ne.jp', 'or.jp',
    'com.au', 'net.au', 'org.au'
  ];
  const lastTwo = parts.slice(-2).join('.');
  if (compoundTLDs.includes(lastTwo)) {
    if (parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return host;
  }
  return parts.slice(-2).join('.');
}

// 计算监控目标排序置顶权重: 置顶目标 (is_pinned === true) Rank 1 > 普通目标 Rank 0 (可自由取消置顶)
function getDomainRank(d) {
  if (!d) return 0;
  return d.is_pinned ? 1 : 0;
}

// 输入域名时智能预填：根域名默认勾选检查过期，根域与 www 默认勾选置顶（可自由取消）
document.getElementById('form-domain-host').addEventListener('input', (e) => {
  const val = e.target.value;
  // 1. 只有真正的根域名默认勾选 RDAP 域名过期检测（www 默认不查询）
  document.getElementById('form-domain-check-reg').checked = isApexDomain(val);

  // 2. 根域名和 www 域名在新添加时默认自动勾选置顶（已有目标或手动修改不受影响）
  const id = document.getElementById('form-domain-id').value;
  if (!id) {
    document.getElementById('form-domain-is-pinned').checked = isRootOrWWW(val);
  }
});

// Toggle SSL check options
document.getElementById('form-domain-check-ssl').addEventListener('change', (e) => {
  const portGroup = document.getElementById('form-group-port');
  const multiGroup = document.getElementById('form-group-multi-host');
  const multiBox = document.getElementById('form-domain-multi-host-box');
  const regCheck = document.getElementById('form-domain-check-reg');
  if (e.target.checked) {
    if (portGroup) portGroup.classList.remove('hidden');
    if (multiGroup) multiGroup.classList.remove('hidden');
    const isMulti = document.getElementById('form-domain-multi-host').checked;
    if (isMulti && multiBox) multiBox.classList.remove('hidden');
  } else {
    if (portGroup) portGroup.classList.add('hidden');
    if (multiGroup) multiGroup.classList.add('hidden');
    if (multiBox) multiBox.classList.add('hidden');
    // 取消勾选 SSL 检查时，若域名过期检查未开启，自动勾选域名过期检查
    if (regCheck && !regCheck.checked) {
      regCheck.checked = true;
    }
  }
});

// Toggle multi-host nodes input box
document.getElementById('form-domain-multi-host').addEventListener('change', (e) => {
  if (e.target.checked) {
    document.getElementById('form-domain-multi-host-box').classList.remove('hidden');
    renderFormMultiHostNodes();
  } else {
    document.getElementById('form-domain-multi-host-box').classList.add('hidden');
  }
});

// 多主机节点动态列表管理
function renderFormMultiHostNodes() {
  const container = document.getElementById('multi-host-nodes-container');
  const hiddenInput = document.getElementById('form-domain-hosts-list');
  if (!container) return;

  if (!state.formMultiHostNodes || state.formMultiHostNodes.length === 0) {
    container.innerHTML = '<div class="node-empty-hint">暂无探测节点，请在上方选择类型并输入解析值后点击“添加”</div>';
    if (hiddenInput) hiddenInput.value = '';
    return;
  }

  container.innerHTML = state.formMultiHostNodes.map((n, idx) => `
    <div class="node-row" data-index="${idx}">
      <div class="node-row-left">
        <span class="node-type-tag tag-${escapeHtml(n.type)}">${escapeHtml(n.type)}</span>
        <span class="node-value font-mono" title="${escapeHtml(n.value)}">${escapeHtml(n.value)}</span>
        ${n.alias ? `<span class="node-alias text-muted">(${escapeHtml(n.alias)})</span>` : ''}
      </div>
      <button type="button" class="btn btn-ghost btn-xs text-rose btn-remove-host-node" data-index="${idx}" title="删除该节点">
        <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
        </svg>
      </button>
    </div>
  `).join('');

  if (hiddenInput) {
    hiddenInput.value = JSON.stringify(state.formMultiHostNodes);
  }

  container.querySelectorAll('.btn-remove-host-node').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.index, 10);
      state.formMultiHostNodes.splice(idx, 1);
      renderFormMultiHostNodes();
    });
  });
}

function addHostNodeFromInput() {
  const typeEl = document.getElementById('node-input-type');
  const valEl = document.getElementById('node-input-value');
  const aliasEl = document.getElementById('node-input-alias');

  const type = typeEl ? typeEl.value : 'A';
  const value = valEl ? valEl.value.trim() : '';
  const alias = aliasEl ? aliasEl.value.trim() : '';

  if (!value) {
    showToast('请输入解析值（IP 或主机名）', 'error');
    if (valEl) valEl.focus();
    return;
  }

  // 基础格式校验
  if (type === 'A') {
    const ipPart = value.split(':')[0];
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ipPart)) {
      showToast('A 记录解析值应为有效的 IPv4 地址（如 1.1.1.1）', 'error');
      if (valEl) valEl.focus();
      return;
    }
  } else if (type === 'CNAME') {
    if (!value.includes('.') || value.includes(' ')) {
      showToast('CNAME 记录解析值应为有效的主机域名（如 cdn.example.com）', 'error');
      if (valEl) valEl.focus();
      return;
    }
  }

  if (!state.formMultiHostNodes) state.formMultiHostNodes = [];
  const exists = state.formMultiHostNodes.some(n => n.value.toLowerCase() === value.toLowerCase() && n.type === type);
  if (exists) {
    showToast('该解析类型的节点已存在，无需重复添加', 'error');
    return;
  }

  state.formMultiHostNodes.push({ type, value, alias });
  renderFormMultiHostNodes();

  if (valEl) {
    valEl.value = '';
    valEl.focus();
  }
  if (aliasEl) aliasEl.value = '';
}

const btnAddHostNode = document.getElementById('btn-add-host-node');
if (btnAddHostNode) {
  btnAddHostNode.addEventListener('click', addHostNodeFromInput);
}
const valNodeInput = document.getElementById('node-input-value');
if (valNodeInput) {
  valNodeInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addHostNodeFromInput();
    }
  });
}
const aliasNodeInput = document.getElementById('node-input-alias');
if (aliasNodeInput) {
  aliasNodeInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addHostNodeFromInput();
    }
  });
}

// API Client
async function api(path, options = {}) {
  const isFormData = options.body instanceof FormData;
  const defaultHeaders = isFormData ? {} : { 'Content-Type': 'application/json' };
  options.headers = { ...defaultHeaders, ...(options.headers || {}) };

  try {
    const res = await fetch(path, options);
    if (res.status === 401 && !path.startsWith('/api/auth/status') && !path.startsWith('/api/auth/login')) {
      showToast('登录已过期，请重新登录', 'error');
      switchView('login');
      return null;
    }

    const contentType = (res.headers.get('content-type') || '').toLowerCase();
    let data = null;
    let rawText = '';

    if (contentType.includes('application/json')) {
      try {
        data = await res.json();
      } catch (e) {
        rawText = await res.text().catch(() => '');
      }
    } else {
      rawText = await res.text().catch(() => '');
    }

    if (!res.ok) {
      let errMsg = `请求失败 (HTTP ${res.status})`;
      if (data && data.error) {
        errMsg = data.error;
      } else if (rawText) {
        const titleMatch = rawText.match(/<title[^>]*>([^<]+)<\/title>/i);
        if (titleMatch && titleMatch[1]) {
          errMsg = `服务器响应异常 (HTTP ${res.status}): ${titleMatch[1].trim()}`;
        } else {
          const stripped = rawText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
          if (stripped.length > 0 && stripped.length < 150) {
            errMsg = `服务异常 (HTTP ${res.status}): ${stripped}`;
          } else {
            errMsg = `服务网关响应异常 (HTTP ${res.status})`;
          }
        }
      }
      const err = new Error(errMsg);
      err.status = res.status;
      err.data = data;
      throw err;
    }

    return data !== null ? data : {};
  } catch (err) {
    showToast(err.message, 'error');
    throw err;
  }
}

// View switcher
function switchView(viewName) {
  elements.setupView.classList.add('hidden');
  elements.loginView.classList.add('hidden');
  elements.dashboardView.classList.add('hidden');

  if (viewName === 'setup') {
    elements.setupView.classList.remove('hidden');
  } else if (viewName === 'login') {
    elements.loginView.classList.remove('hidden');
    elements.loginForm.classList.remove('hidden');
    elements.login2FAForm.classList.add('hidden');
  } else if (viewName === 'dashboard') {
    elements.dashboardView.classList.remove('hidden');
  }
}

// Turnstile Widget Loader
let turnstileWidgetId = null;
function initTurnstile() {
  if (!state.turnstileEnabled || !state.turnstileSiteKey) {
    elements.turnstileBox.classList.add('hidden');
    return;
  }

  elements.turnstileBox.classList.remove('hidden');

  if (state.turnstilePassed) {
    elements.turnstileContainer.classList.add('hidden');
    elements.turnstilePassedTag.classList.remove('hidden');
    return;
  }

  elements.turnstileContainer.classList.remove('hidden');
  elements.turnstilePassedTag.classList.add('hidden');

  const renderWidget = () => {
    if (window.turnstile && elements.turnstileContainer) {
      elements.turnstileContainer.innerHTML = '';
      turnstileWidgetId = window.turnstile.render('#turnstile-container', {
        sitekey: state.turnstileSiteKey,
        theme: 'dark',
        callback: function (token) {
          state.turnstileToken = token;
        },
      });
    }
  };

  if (!window.turnstile) {
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true;
    script.defer = true;
    script.onload = renderWidget;
    document.head.appendChild(script);
  } else {
    renderWidget();
  }
}

// Init Auth Check
async function checkAuth() {
  try {
    const res = await api('/api/auth/status');
    state.hasAdmin = res.has_admin;
    state.isAuthenticated = res.is_authenticated;
    state.username = res.username;
    state.totpEnabled = res.totp_enabled;
    state.turnstileEnabled = res.turnstile_enabled;
    state.turnstileSiteKey = res.turnstile_site_key;
    state.turnstilePassed = res.turnstile_passed;
    state.icp = res.icp || '';
    state.mps = res.mps || '';

    if (!localStorage.getItem('argus_theme') && res.default_theme && res.default_theme !== 'auto') {
      if (window.applyTheme) window.applyTheme(res.default_theme);
    }

    renderAuthFooter();

    if (!state.hasAdmin) {
      switchView('setup');
    } else if (!state.isAuthenticated) {
      switchView('login');
      initTurnstile();
    } else {
      switchView('dashboard');
      await loadDashboardData();
    }
  } catch (err) {
    console.error('Failed to check auth status', err);
  }
}

// Render ICP & MPS Footer on Auth (Unauthenticated) Pages
function renderAuthFooter() {
  const footers = document.querySelectorAll('.auth-footer');
  if (!footers.length) return;

  const items = [];
  if (state.icp) {
    items.push(`
      <a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener noreferrer">
        ${escapeHtml(state.icp)}
      </a>
    `);
  }
  if (state.mps) {
    const digits = state.mps.replace(/\D/g, '');
    const mpsUrl = digits ? `http://www.beian.gov.cn/portal/registerSystemInfo?recordcode=${digits}` : 'http://www.beian.gov.cn/';
    items.push(`
      <a href="${mpsUrl}" target="_blank" rel="noopener noreferrer">
        <svg class="mps-badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
        <span>${escapeHtml(state.mps)}</span>
      </a>
    `);
  }

  footers.forEach(footer => {
    if (items.length > 0) {
      footer.innerHTML = items.join('');
      footer.classList.remove('hidden');
    } else {
      footer.innerHTML = '';
      footer.classList.add('hidden');
    }
  });
}

// Setup Form Submission
elements.setupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('setup-username').value.trim();
  const password = document.getElementById('setup-password').value;
  const confirm = document.getElementById('setup-confirm-password').value;

  if (password !== confirm) {
    showToast('两次输入的密码不一致', 'error');
    return;
  }

  try {
    await api('/api/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    showToast('管理员初始化成功', 'success');
    await checkAuth();
  } catch (err) {
    // Handled in api()
  }
});

// Login Form Submission with Turnstile & 2FA handling
elements.loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;

  try {
    const res = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password,
        turnstile_token: state.turnstileToken,
      }),
    });

    if (res.need_2fa) {
      state.temp2FAToken = res.temp_token;
      elements.loginForm.classList.add('hidden');
      elements.login2FAForm.classList.remove('hidden');
      document.getElementById('login-2fa-code').value = '';
      document.getElementById('login-2fa-code').focus();
      showToast('请输入 2FA 动态口令', 'info');
      return;
    }

    showToast('登录成功', 'success');
    await checkAuth();
  } catch (err) {
    // If turnstile was already verified on server, retain passed status so user doesn't repeat captcha
    if (err.data && err.data.turnstile_passed) {
      state.turnstilePassed = true;
      elements.turnstileContainer.classList.add('hidden');
      elements.turnstilePassedTag.classList.remove('hidden');
    }
  }
});

// 2FA Verification Submit
elements.login2FAForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = document.getElementById('login-2fa-code').value.trim();

  try {
    await api('/api/auth/2fa/verify', {
      method: 'POST',
      body: JSON.stringify({
        temp_token: state.temp2FAToken,
        code,
      }),
    });
    showToast('2FA 验证成功，已登录', 'success');
    await checkAuth();
  } catch (err) {
    // Handled in api()
  }
});

elements.btnCancel2FA.addEventListener('click', () => {
  elements.login2FAForm.classList.add('hidden');
  elements.loginForm.classList.remove('hidden');
});

// Passkey Login Ceremony
elements.btnPasskeyLogin.addEventListener('click', async () => {
  try {
    const options = await api('/api/auth/passkey/login/start', { method: 'POST' });
    
    // Convert base64url strings to ArrayBuffer
    options.publicKey.challenge = bufferDecode(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {
      options.publicKey.allowCredentials.forEach(cred => {
        cred.id = bufferDecode(cred.id);
      });
    }

    const assertion = await navigator.credentials.get({
      publicKey: options.publicKey,
    });

    const res = await api('/api/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify({
        id: assertion.id,
        rawId: bufferEncode(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: bufferEncode(assertion.response.authenticatorData),
          clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
          signature: bufferEncode(assertion.response.signature),
          userHandle: assertion.response.userHandle ? bufferEncode(assertion.response.userHandle) : null,
        },
      }),
    });

    showToast('Passkey 快捷登录成功', 'success');
    await checkAuth();
  } catch (err) {
    console.error('Passkey login error', err);
    if (err.name !== 'NotAllowedError') {
      showToast(err.message || 'Passkey 登录失败', 'error');
    }
  }
});

// Logout
elements.btnLogout.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
    showToast('已安全退出', 'info');
    switchView('login');
    checkAuth();
  } catch (err) {
    switchView('login');
  }
});

// Change Password
elements.btnPasswordModal.addEventListener('click', () => {
  elements.passwordForm.reset();
  closeModal('modal-settings');
  openModal('modal-password');
});

elements.passwordForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const old_password = document.getElementById('pwd-old').value;
  const new_password = document.getElementById('pwd-new').value;
  const confirm = document.getElementById('pwd-confirm').value;

  if (new_password !== confirm) {
    showToast('两次输入的新密码不一致', 'error');
    return;
  }

  try {
    await api('/api/auth/password', {
      method: 'PUT',
      body: JSON.stringify({ old_password, new_password }),
    });
    showToast('密码已成功修改', 'success');
    closeModal('modal-password');
  } catch (err) {
    // Handled in api()
  }
});

// Load Dashboard Data
async function loadDashboardData() {
  await Promise.all([loadDomains(), loadSettings(), loadPasskeys(), loadDNSData(), fetchUnreadNotificationCount()]);
}

// Load Domains
async function loadDomains() {
  try {
    const domains = await api('/api/domains');
    state.domains = domains || [];
    updateDomainGroupOptions();
    renderDashboard();
  } catch (err) {
    console.error('Failed to load domains', err);
  }
}

// 动态构建主域名筛选选项列表
function updateDomainGroupOptions() {
  if (!elements.domainGroupSelect) return;
  const groups = new Map();
  state.domains.forEach(d => {
    const apex = getApexDomain(d.host);
    if (apex) {
      groups.set(apex, (groups.get(apex) || 0) + 1);
    }
  });

  const sortedGroups = Array.from(groups.entries()).sort((a, b) => {
    if (b[1] !== a[1]) return b[1] - a[1];
    return a[0].localeCompare(b[0]);
  });

  const currentVal = state.domainGroupFilter;
  let html = `<option value="">全部主域名 (${state.domains.length})</option>`;
  sortedGroups.forEach(([domain, count]) => {
    html += `<option value="${escapeHtml(domain)}">${escapeHtml(domain)} (${count})</option>`;
  });
  elements.domainGroupSelect.innerHTML = html;
  if (currentVal && groups.has(currentVal)) {
    elements.domainGroupSelect.value = currentVal;
  } else {
    state.domainGroupFilter = '';
  }
}

// Load Settings
async function loadSettings() {
  try {
    const settings = await api('/api/settings');
    state.settings = settings;
    if (settings.icp !== undefined) state.icp = settings.icp;
    if (settings.mps !== undefined) state.mps = settings.mps;
    const verBadge = document.getElementById('about-app-version');
    if (verBadge && settings.version) {
      verBadge.textContent = settings.version.startsWith('v') ? settings.version : `v${settings.version}`;
    }
    renderAuthFooter();
    updatePolicyKPI();
    renderAppriseStatus();
    renderSecuritySettings();
  } catch (err) {
    console.error('Failed to load settings', err);
  }
}

function updatePolicyKPI() {
  if (state.settings) {
    elements.kpiPolicy.textContent = `阶梯: ${state.settings.alert_thresholds || '30, 15, 7, 3'} 天`;
  }
}

function renderAppriseStatus() {
  if (!state.settings) return;

  if (state.settings.apprise_available) {
    elements.appriseWrapper.classList.remove('disabled-feature');
    elements.appriseUnavailableBanner.classList.add('hidden');
    elements.appriseEnabledCheck.disabled = false;
    elements.appriseStatusBadge.textContent = 'Apprise 服务就绪 (可配置)';
    elements.appriseStatusBadge.className = 'badge badge-purple';
  } else {
    // Dimmed and disabled when not deployed in compose.yml
    elements.appriseWrapper.classList.add('disabled-feature');
    elements.appriseUnavailableBanner.classList.remove('hidden');
    elements.appriseEnabledCheck.disabled = true;
    elements.appriseEnabledCheck.checked = false;
    elements.appriseDetails.classList.add('hidden');
    elements.appriseStatusBadge.textContent = 'compose.yml 未启用（不可设置）';
    elements.appriseStatusBadge.className = 'badge badge-gray';
  }
}

function renderSecuritySettings() {
  if (!state.settings) return;

  // Turnstile
  document.getElementById('cfg-turnstile-enabled').checked = state.settings.turnstile_enabled;
  document.getElementById('cfg-turnstile-sitekey').value = state.settings.turnstile_site_key || '';
  document.getElementById('cfg-turnstile-secret').value = state.settings.turnstile_secret_key || '';
  if (state.settings.turnstile_enabled) {
    document.getElementById('turnstile-settings-fields').classList.remove('hidden');
  } else {
    document.getElementById('turnstile-settings-fields').classList.add('hidden');
  }

  // 2FA status
  const totpBox = document.getElementById('totp-action-box');
  if (state.totpEnabled) {
    totpBox.innerHTML = `
      <span class="security-status-pill status-enabled">
        <span class="status-pulse-dot"></span>
        已开启保护
      </span>
      <button type="button" id="btn-disable-2fa" class="btn btn-secondary btn-sm text-rose">关闭 2FA</button>
    `;
    document.getElementById('btn-disable-2fa').addEventListener('click', handleDisable2FA);
  } else {
    totpBox.innerHTML = `
      <button type="button" id="btn-enable-2fa-modal" class="btn btn-secondary btn-sm">配置 2FA</button>
    `;
    document.getElementById('btn-enable-2fa-modal').addEventListener('click', handleOpen2FASetup);
  }
}

// 2FA Setup Flow
let pendingTOTPSecret = '';
async function handleOpen2FASetup() {
  try {
    const res = await api('/api/auth/2fa/setup', { method: 'POST' });
    pendingTOTPSecret = res.secret;
    document.getElementById('totp-secret-text').textContent = res.secret;
    document.getElementById('totp-verify-code').value = '';
    openModal('modal-totp-setup');
  } catch (err) {
    // Handled in api()
  }
}

document.getElementById('btn-copy-secret').addEventListener('click', () => {
  navigator.clipboard.writeText(pendingTOTPSecret);
  showToast('密钥已复制到剪贴板', 'info');
});

document.getElementById('totp-verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = document.getElementById('totp-verify-code').value.trim();

  try {
    await api('/api/auth/2fa/enable', {
      method: 'POST',
      body: JSON.stringify({ secret: pendingTOTPSecret, code }),
    });
    showToast('2FA 两步验证已成功开启', 'success');
    closeModal('modal-totp-setup');
    state.totpEnabled = true;
    renderSecuritySettings();
  } catch (err) {
    // Handled in api()
  }
});

async function handleDisable2FA() {
  promptModal('停用两步验证 (2FA)', '为了系统安全，请输入当前管理员密码以确认停用 2FA：', {
    inputType: 'password',
    placeholder: '请输入当前管理员密码',
    onConfirm: async (password) => {
      if (!password) {
        showToast('密码不能为空', 'warning');
        return;
      }
      try {
        await api('/api/auth/2fa/disable', {
          method: 'POST',
          body: JSON.stringify({ password }),
        });
        showToast('2FA 两步验证已成功停用', 'info');
        state.totpEnabled = false;
        renderSecuritySettings();
      } catch (err) {
        // Handled in api()
      }
    },
  });
}

// Passkey Management
async function loadPasskeys() {
  try {
    const list = await api('/api/auth/passkey/list');
    renderPasskeyList(list || []);
  } catch (err) {
    console.error('Failed to load passkeys', err);
  }
}

function renderPasskeyList(records) {
  const container = document.getElementById('passkey-list');
  if (!records || records.length === 0) {
    container.innerHTML = '<div class="passkey-empty">暂未绑定 Passkey 凭证</div>';
    return;
  }

  container.innerHTML = records.map(p => `
    <div class="passkey-item">
      <div>
        <strong>${escapeHtml(p.name)}</strong>
        <div class="cert-meta">创建时间: ${formatDate(p.created_at)}</div>
      </div>
      <button type="button" class="btn btn-ghost btn-sm text-rose btn-delete-passkey" data-id="${p.id}" title="删除该 Passkey">
        <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
        </svg>
      </button>
    </div>
  `).join('');

  container.querySelectorAll('.btn-delete-passkey').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.id;
      confirmModal('确定要删除此 Passkey 凭据吗？删除后将无法使用该密钥进行免密登录。', async () => {
        try {
          await api(`/api/auth/passkey/${id}`, { method: 'DELETE' });
          showToast('Passkey 凭证已删除', 'info');
          await loadPasskeys();
        } catch (err) {
          // Handled in api()
        }
      });
    });
  });
}

document.getElementById('btn-add-passkey').addEventListener('click', async () => {
  try {
    const options = await api('/api/auth/passkey/register/start', { method: 'POST' });

    options.publicKey.challenge = bufferDecode(options.publicKey.challenge);
    options.publicKey.user.id = bufferDecode(options.publicKey.user.id);
    if (options.publicKey.excludeCredentials) {
      options.publicKey.excludeCredentials.forEach(cred => {
        cred.id = bufferDecode(cred.id);
      });
    }

    const credential = await navigator.credentials.create({
      publicKey: options.publicKey,
    });

    await api('/api/auth/passkey/register/finish', {
      method: 'POST',
      body: JSON.stringify({
        id: credential.id,
        rawId: bufferEncode(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufferEncode(credential.response.attestationObject),
          clientDataJSON: bufferEncode(credential.response.clientDataJSON),
        },
      }),
    });

    showToast('Passkey 凭证添加成功', 'success');
    await loadPasskeys();
  } catch (err) {
    console.error('Passkey registration error', err);
    if (err.name !== 'NotAllowedError') {
      showToast(err.message || 'Passkey 注册失败', 'error');
    }
  }
});

// Target status determination helpers (30, 15, 7, 3 tiers)
function isTargetWarning(d) {
  // SSL 警告判定: 开启了 SSL 检查，且状态属于过期、极危、警告、注意、关注(<=30天)、或者检测失败
  const isSSLWarning = (d.check_ssl !== false) && (
    d.ssl_status === 'expired' ||
    d.ssl_status === 'critical' ||
    d.ssl_status === 'warning' ||
    d.ssl_status === 'notice' ||
    d.ssl_status === 'info' ||
    d.ssl_status === 'error' ||
    (typeof d.ssl_days_left === 'number' && d.ssl_days_left <= 30 && d.ssl_status !== 'pending')
  );

  // 域名到期警告判定: 开启了域名检查，且状态属于过期、极危、警告、注意、关注(<=30天)、或者查询失败
  const isDomainWarning = !!d.check_domain && (
    d.domain_status === 'expired' ||
    d.domain_status === 'critical' ||
    d.domain_status === 'warning' ||
    d.domain_status === 'notice' ||
    d.domain_status === 'info' ||
    d.domain_status === 'error' ||
    (typeof d.domain_days_left === 'number' && d.domain_days_left <= 30 && d.domain_status !== 'pending')
  );

  return isSSLWarning || isDomainWarning;
}

function isTargetHealthy(d) {
  if (isTargetWarning(d)) return false;
  const hasCheck = (d.check_ssl !== false) || !!d.check_domain;
  if (!hasCheck) return false;

  const sslOk = (d.check_ssl === false) || d.ssl_status === 'healthy' || (typeof d.ssl_days_left === 'number' && d.ssl_days_left > 30);
  const domOk = !d.check_domain || d.domain_status === 'healthy' || (typeof d.domain_days_left === 'number' && d.domain_days_left > 30);
  return sslOk && domOk;
}

// 同步更新顶部 KPI 卡片与下方 filter tabs 的 active 选中高亮状态
function updateFilterActiveUI(activeFilter) {
  const current = activeFilter || 'all';

  // 下方 filter tabs
  if (elements.filterTabs) {
    elements.filterTabs.forEach(tab => {
      if (tab.dataset.filter === current) {
        tab.classList.add('active');
      } else {
        tab.classList.remove('active');
      }
    });
  }

  // 顶部 KPI 统计卡片
  if (elements.kpiCards) {
    elements.kpiCards.forEach(card => {
      if (card.dataset.filter === current) {
        card.classList.add('active');
        card.setAttribute('aria-pressed', 'true');
      } else {
        card.classList.remove('active');
        card.setAttribute('aria-pressed', 'false');
      }
    });
  }
}

// 统一筛选切换入口
function setActiveFilter(filterName) {
  // 如果再次点击已经激活的非 all 筛选项（如 warning / healthy），则反选取消筛选恢复为 all
  if (state.activeFilter === filterName && filterName !== 'all') {
    state.activeFilter = 'all';
    state.viewMode = 'groups';
    state.currentApex = null;
  } else {
    state.activeFilter = filterName || 'all';
    if (state.activeFilter === 'warning') {
      // 筛选“需注意/告警”时，自动平铺展开为全部监控目标模式
      state.viewMode = 'all';
      state.currentApex = null;
    } else if (state.activeFilter === 'all' && state.viewMode === 'all') {
      // 切换为全部时，恢复为主域名模式
      state.viewMode = 'groups';
      state.currentApex = null;
    }
  }

  state.currentPage = 1;
  updateNavAndBreadcrumb();
  updateTableHead();
  updateFilterActiveUI(state.activeFilter);
  renderDashboard();
}

// 主域名星标置顶 (仿 Cloudflare 新版星标) 本地存储与同步
const PINNED_APEX_KEY = 'argus_pinned_apex_domains';

function getPinnedApexDomains() {
  try {
    const raw = localStorage.getItem(PINNED_APEX_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function isApexPinned(apex, targets = []) {
  const pinnedList = getPinnedApexDomains();
  if (pinnedList.includes(apex.toLowerCase())) return true;
  return targets.some(t => t.is_pinned);
}

async function togglePinApex(apex, targets = []) {
  let pinnedList = getPinnedApexDomains();
  const apexLower = apex.toLowerCase();
  const currentlyPinned = pinnedList.includes(apexLower) || targets.some(t => t.is_pinned);

  if (currentlyPinned) {
    pinnedList = pinnedList.filter(item => item !== apexLower);
    for (const t of targets) {
      if (t.is_pinned) {
        t.is_pinned = false;
        try {
          await api(`/api/domains/${t.id}/pin`, {
            method: 'POST',
            body: JSON.stringify({ is_pinned: false })
          });
        } catch (e) {}
      }
    }
    showToast(`已取消 ${apex} 的置顶`, 'info');
  } else {
    pinnedList.push(apexLower);
    const targetToPin = targets.find(t => t.host.toLowerCase() === apexLower) || targets[0];
    if (targetToPin && !targetToPin.is_pinned) {
      targetToPin.is_pinned = true;
      try {
        await api(`/api/domains/${targetToPin.id}/pin`, {
          method: 'POST',
          body: JSON.stringify({ is_pinned: true })
        });
      } catch (e) {}
    }
    showToast(`已将 ${apex} 置顶`, 'success');
  }
  localStorage.setItem(PINNED_APEX_KEY, JSON.stringify([...new Set(pinnedList)]));
}

// 主域名分组数据构建函数
function buildDomainGroups(domains) {
  const groupsMap = new Map();
  const pinnedApexList = getPinnedApexDomains();

  domains.forEach(d => {
    const apex = (getApexDomain(d.host) || d.host).toLowerCase();
    if (!groupsMap.has(apex)) {
      groupsMap.set(apex, {
        apex: apex,
        targets: [],
        hasPinned: false,
        isPinned: false,
        hasWarning: false,
        hasHealthy: false,
        latestCheckedAt: null,
      });
    }
    const group = groupsMap.get(apex);
    group.targets.push(d);
    if (d.is_pinned) group.hasPinned = true;
    if (isTargetWarning(d)) group.hasWarning = true;
    if (isTargetHealthy(d)) group.hasHealthy = true;
    if (d.last_checked_at) {
      if (!group.latestCheckedAt || new Date(d.last_checked_at) > new Date(group.latestCheckedAt)) {
        group.latestCheckedAt = d.last_checked_at;
      }
    }
  });

  const groupList = [];
  groupsMap.forEach(group => {
    group.isPinned = pinnedApexList.includes(group.apex) || group.hasPinned;

    // 寻找代表该主域名的注册到期检测目标：优先匹配 host === apex 且开启 check_domain 的目标
    const apexTarget = group.targets.find(t => t.host.toLowerCase() === group.apex && t.check_domain);
    const anyDomainCheckTarget = group.targets.find(t => t.check_domain);
    group.domainTarget = apexTarget || anyDomainCheckTarget || null;

    // 统计 SSL 监控概况
    let sslHealthy = 0;
    let sslWarning = 0;
    let minSslDaysLeft = Infinity;

    group.targets.forEach(t => {
      if (t.check_ssl !== false) {
        if (t.ssl_status === 'healthy') {
          sslHealthy++;
        } else if (isTargetWarning(t)) {
          sslWarning++;
        }
        if (typeof t.ssl_days_left === 'number' && t.ssl_days_left >= 0 && t.ssl_days_left < minSslDaysLeft) {
          minSslDaysLeft = t.ssl_days_left;
        }
      }
    });

    group.sslHealthy = sslHealthy;
    group.sslWarning = sslWarning;
    group.minSslDaysLeft = minSslDaysLeft === Infinity ? null : minSslDaysLeft;

    // 如果域名注册到期告警，也将整个分组标记为 warning
    if (group.domainTarget && isTargetWarning(group.domainTarget)) {
      group.hasWarning = true;
    }

    groupList.push(group);
  });

  return groupList;
}

// 统一渲染域名注册到期 (RDAP/WHOIS) 状态徽章与到期时间
function renderDomainExpiryBadge(dom) {
  const tipIcon = `<svg class="badge-tip-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

  if (!dom || !dom.check_domain) {
    return {
      badge: `<span class="status-badge badge-skipped cursor-help" data-tooltip="未开启此主域名的注册到期监控">未监控${tipIcon}</span>`,
      meta: ''
    };
  }

  const domErr = dom.domain_error ? escapeHtml(dom.domain_error) : '';
  const domErrTip = domErr ? `查询失败原因: ${domErr}` : '';
  const expiryDateTip = dom.domain_expires_at ? `到期: ${formatDate(dom.domain_expires_at)}` : '';
  const combinedTip = domErrTip ? `${domErrTip}${expiryDateTip ? ' · ' + expiryDateTip : ''}` : expiryDateTip;

  let badge = '';

  if (dom.domain_status === 'expired' || dom.domain_days_left < 0) {
    badge = `<span class="status-badge badge-critical${combinedTip ? ' cursor-help' : ''}"${combinedTip ? ` data-tooltip="${combinedTip}"` : ' data-tooltip="已超过注册期限"'}>域名已过期${domErr ? tipIcon : ''}</span>`;
  } else if (dom.domain_days_left <= 3) {
    badge = `<span class="status-badge badge-critical${combinedTip ? ' cursor-help' : ''}"${combinedTip ? ` data-tooltip="${combinedTip}"` : ''}>极危 · 剩余 ${dom.domain_days_left} 天${domErr ? tipIcon : ''}</span>`;
  } else if (dom.domain_days_left <= 7) {
    badge = `<span class="status-badge badge-warning${combinedTip ? ' cursor-help' : ''}"${combinedTip ? ` data-tooltip="${combinedTip}"` : ''}>橙色警告 · 剩余 ${dom.domain_days_left} 天${domErr ? tipIcon : ''}</span>`;
  } else if (dom.domain_days_left <= 15) {
    badge = `<span class="status-badge badge-notice${combinedTip ? ' cursor-help' : ''}"${combinedTip ? ` data-tooltip="${combinedTip}"` : ''}>注意 · 剩余 ${dom.domain_days_left} 天${domErr ? tipIcon : ''}</span>`;
  } else if (dom.domain_days_left <= 30) {
    badge = `<span class="status-badge badge-info${combinedTip ? ' cursor-help' : ''}"${combinedTip ? ` data-tooltip="${combinedTip}"` : ''}>关注 · 剩余 ${dom.domain_days_left} 天${domErr ? tipIcon : ''}</span>`;
  } else if (dom.domain_status === 'error') {
    badge = `<span class="status-badge badge-critical cursor-help" data-tooltip="${domErrTip || 'RDAP 查询失败'}">查询失败${tipIcon}</span>`;
  } else if (dom.domain_status === 'healthy') {
    badge = `<span class="status-badge badge-healthy${combinedTip ? ' cursor-help' : ''}"${combinedTip ? ` data-tooltip="${combinedTip}"` : ''}>正常 · 剩余 ${dom.domain_days_left} 天</span>`;
  } else {
    badge = `<span class="status-badge badge-pending">等待巡检</span>`;
  }

  return { badge, meta: '' };
}

// 动态切换表头
function updateTableHead() {
  if (!elements.domainsTableHead) return;

  if (state.viewMode === 'groups') {
    elements.domainsTableHead.innerHTML = `
      <tr>
        <th>主域名 (Apex Domain)</th>
        <th>域名注册到期 (RDAP)</th>
        <th>子域名监控概况</th>
        <th>最近巡检时间</th>
        <th class="text-right">操作</th>
      </tr>
    `;
  } else if (state.viewMode === 'subdomains') {
    // 二级页面列表中彻底不再显示域名到期时间
    elements.domainsTableHead.innerHTML = `
      <tr>
        <th>监控目标 (子域名 / 根域名)</th>
        <th>SSL 证书有效期</th>
        <th>最近巡检时间</th>
        <th class="text-right">操作</th>
      </tr>
    `;
  } else {
    // 全部监控目标平铺集合模式 (例如点击“告警”筛选时)
    elements.domainsTableHead.innerHTML = `
      <tr>
        <th>监控目标 (Host)</th>
        <th>SSL 证书有效期</th>
        <th>最近巡检时间</th>
        <th class="text-right">操作</th>
      </tr>
    `;
  }
}

// 更新二级页面面包屑与工具栏胶囊激活状态
function updateNavAndBreadcrumb() {
  // 1. 视图胶囊
  if (elements.viewModeTabs) {
    elements.viewModeTabs.forEach(tab => {
      const mode = tab.dataset.view;
      if (state.viewMode === mode) {
        tab.classList.add('active');
      } else {
        tab.classList.remove('active');
      }
    });
  }

  // 2. 二级页面面包屑
  if (!elements.breadcrumbBar) return;

  if (state.viewMode === 'subdomains' && state.currentApex) {
    elements.breadcrumbBar.classList.remove('hidden');
    if (elements.crumbCurrentDomain) {
      elements.crumbCurrentDomain.textContent = state.currentApex;
    }

    if (elements.breadcrumbDomainMeta) {
      const groups = buildDomainGroups(state.domains);
      const curGroup = groups.find(g => g.apex === state.currentApex);
      const expiry = renderDomainExpiryBadge(curGroup ? curGroup.domainTarget : null);
      elements.breadcrumbDomainMeta.innerHTML = `
        <span class="text-xs text-muted">主域名到期：</span>
        ${expiry.badge}
        ${expiry.meta ? `<span class="text-xs text-muted font-mono" style="margin-left: 0.35rem;">${expiry.meta.replace(/<\/?div[^>]*>/g, '')}</span>` : ''}
      `;
    }
  } else {
    elements.breadcrumbBar.classList.add('hidden');
  }
}

// 渲染通用分页控件
function renderPagination(totalCount) {
  if (!elements.tablePagination) return;

  if (totalCount <= 0) {
    elements.tablePagination.classList.add('hidden');
    return;
  }

  elements.tablePagination.classList.remove('hidden');

  const totalPages = Math.max(1, Math.ceil(totalCount / state.pageSize));
  if (state.currentPage > totalPages) {
    state.currentPage = totalPages;
  }
  if (state.currentPage < 1) {
    state.currentPage = 1;
  }

  if (elements.paginationInfo) {
    elements.paginationInfo.textContent = `共 ${totalCount} 条记录 · 第 ${state.currentPage} / ${totalPages} 页`;
  }

  if (elements.btnPagePrev) {
    elements.btnPagePrev.disabled = state.currentPage <= 1;
  }
  if (elements.btnPageNext) {
    elements.btnPageNext.disabled = state.currentPage >= totalPages;
  }

  if (elements.paginationPages) {
    let pagesHtml = '';
    const maxButtons = 5;

    let startPage = Math.max(1, state.currentPage - Math.floor(maxButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxButtons - 1);

    if (endPage - startPage + 1 < maxButtons) {
      startPage = Math.max(1, endPage - maxButtons + 1);
    }

    if (startPage > 1) {
      pagesHtml += `<button type="button" class="page-num" data-page="1">1</button>`;
      if (startPage > 2) {
        pagesHtml += `<span class="page-ellipsis">...</span>`;
      }
    }

    for (let p = startPage; p <= endPage; p++) {
      pagesHtml += `<button type="button" class="page-num${p === state.currentPage ? ' active' : ''}" data-page="${p}">${p}</button>`;
    }

    if (endPage < totalPages) {
      if (endPage < totalPages - 1) {
        pagesHtml += `<span class="page-ellipsis">...</span>`;
      }
      pagesHtml += `<button type="button" class="page-num" data-page="${totalPages}">${totalPages}</button>`;
    }

    elements.paginationPages.innerHTML = pagesHtml;

    elements.paginationPages.querySelectorAll('.page-num').forEach(btn => {
      btn.addEventListener('click', () => {
        const page = parseInt(btn.dataset.page, 10);
        if (page && page !== state.currentPage) {
          state.currentPage = page;
          renderDashboard();
        }
      });
    });
  }

  if (elements.pageSizeSelect) {
    elements.pageSizeSelect.value = String(state.pageSize);
  }
}

// 主界面渲染入口
function renderDashboard() {
  let healthyCount = 0;
  let warningCount = 0;

  state.domains.forEach(d => {
    if (isTargetWarning(d)) {
      warningCount++;
    } else if (isTargetHealthy(d)) {
      healthyCount++;
    }
  });

  elements.kpiTotal.textContent = state.domains.length;
  elements.kpiHealthy.textContent = healthyCount;
  elements.kpiWarning.textContent = warningCount;
  elements.countAll.textContent = state.domains.length;
  elements.countWarning.textContent = warningCount;
  elements.countHealthy.textContent = healthyCount;

  // 同步卡片与 Tab 选中状态
  updateFilterActiveUI(state.activeFilter);

  // 动态更新表头与导航/面包屑
  updateTableHead();
  updateNavAndBreadcrumb();

  const query = state.searchQuery.toLowerCase().trim();

  // 根据当前视图模式分发渲染
  if (state.viewMode === 'groups') {
    // 一级首页：只显示主域名
    const allGroups = buildDomainGroups(state.domains);

    // 筛选与搜索
    const filteredGroups = allGroups.filter(g => {
      if (query) {
        const matchApex = g.apex.includes(query);
        const matchTargets = g.targets.some(t => t.host.toLowerCase().includes(query));
        if (!matchApex && !matchTargets) return false;
      }
      if (state.activeFilter === 'warning') {
        return g.hasWarning;
      }
      if (state.activeFilter === 'healthy') {
        return !g.hasWarning && g.hasHealthy;
      }
      return true;
    });

    // 排序：星标置顶项排在最前，其次有告警，其余按主域名首字母升序
    filteredGroups.sort((a, b) => {
      if (a.isPinned && !b.isPinned) return -1;
      if (!a.isPinned && b.isPinned) return 1;
      if (a.hasWarning && !b.hasWarning) return -1;
      if (!a.hasWarning && b.hasWarning) return 1;
      return a.apex.localeCompare(b.apex);
    });

    // 分页切片
    const totalCount = filteredGroups.length;
    const startIndex = (state.currentPage - 1) * state.pageSize;
    const pageGroups = filteredGroups.slice(startIndex, startIndex + state.pageSize);

    renderGroupTable(pageGroups);
    renderPagination(totalCount);

  } else if (state.viewMode === 'subdomains') {
    // 二级页面：显示当前主域名下的子域名的监控信息（可包括根域名），列表中不再显示域名到期时间
    const currentApex = (state.currentApex || '').toLowerCase();
    const groupTargets = state.domains.filter(d => (getApexDomain(d.host) || d.host).toLowerCase() === currentApex);

    const filtered = groupTargets.filter(d => {
      const hostLower = d.host.toLowerCase();
      if (query && !hostLower.includes(query)) {
        return false;
      }
      if (state.activeFilter === 'warning') {
        return isTargetWarning(d);
      }
      if (state.activeFilter === 'healthy') {
        return isTargetHealthy(d);
      }
      return true;
    });

    // 排序：置顶优先，根域名优先，其余按 ID 升序
    filtered.sort((a, b) => {
      const rankDiff = getDomainRank(b) - getDomainRank(a);
      if (rankDiff !== 0) return rankDiff;
      const isARoot = a.host.toLowerCase() === currentApex ? 1 : 0;
      const isBRoot = b.host.toLowerCase() === currentApex ? 1 : 0;
      if (isBRoot !== isARoot) return isBRoot - isARoot;
      return a.id - b.id;
    });

    const totalCount = filtered.length;
    const startIndex = (state.currentPage - 1) * state.pageSize;
    const pageDomains = filtered.slice(startIndex, startIndex + state.pageSize);

    renderSubdomainTable(pageDomains);
    renderPagination(totalCount);

  } else {
    // 全部监控目标集合平铺模式 (all)
    const filtered = state.domains.filter(d => {
      const hostLower = d.host.toLowerCase();
      if (query && !hostLower.includes(query)) {
        return false;
      }
      if (state.activeFilter === 'warning') {
        return isTargetWarning(d);
      }
      if (state.activeFilter === 'healthy') {
        return isTargetHealthy(d);
      }
      return true;
    });

    filtered.sort((a, b) => {
      const rankDiff = getDomainRank(b) - getDomainRank(a);
      if (rankDiff !== 0) return rankDiff;
      return a.id - b.id;
    });

    const totalCount = filtered.length;
    const startIndex = (state.currentPage - 1) * state.pageSize;
    const pageDomains = filtered.slice(startIndex, startIndex + state.pageSize);

    renderAllTable(pageDomains);
    renderPagination(totalCount);
  }
}

// 渲染一级首页主域名表格
function renderGroupTable(groups) {
  if (groups.length === 0) {
    elements.domainsTableBody.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">
          <p>暂无符合条件的主域名</p>
        </td>
      </tr>
    `;
    return;
  }

  elements.domainsTableBody.innerHTML = groups.map(g => {
    // 1. 域名到期时间移至一级首页的域名中展示
    const expiry = renderDomainExpiryBadge(g.domainTarget);

    // 2. SSL 监控概况简报 (第一项为监控目标总数，移除最短证书剩余)
    const stats = [];
    stats.push(`<span class="status-badge badge-subdomain-count badge-apex-jump" data-apex="${escapeHtml(g.apex)}" title="该主域名下包含的监控目标总数 · 点击查看子域名列表">${g.targets.length} 个监控目标</span>`);
    if (g.sslHealthy > 0) {
      stats.push(`<span class="status-badge badge-healthy">${g.sslHealthy} 正常</span>`);
    }
    if (g.sslWarning > 0) {
      stats.push(`<span class="status-badge badge-warning">${g.sslWarning} 需注意</span>`);
    }
    if (g.sslHealthy === 0 && g.sslWarning === 0) {
      stats.push(`<span class="status-badge badge-pending">等待巡检</span>`);
    }
    const sslSummaryHtml = `<div class="group-ssl-summary">${stats.join(' ')}</div>`;

    // 3. 最近巡检时间
    const lastChecked = g.latestCheckedAt ? formatTimeAgo(g.latestCheckedAt) : '尚未检测';
    const lastCheckedFull = g.latestCheckedAt ? `最后检测: ${new Date(g.latestCheckedAt).toLocaleString('zh-CN', { hour12: false })}` : '尚未检测';

    // 4. 检查此主域名是否通过 DNS API 添加 (若已被禁用则展示为普通配置API按钮)
    const syncConf = (state.dnsSyncConfigs || []).find(c => (c.domain || '').toLowerCase() === g.apex.toLowerCase());
    let apiActionHtml = '';
    if (syncConf && !syncConf.is_disabled) {
      const pName = syncConf.provider_name || syncConf.provider_type || 'API';
      apiActionHtml = `
        <button type="button" class="btn btn-purple btn-sm btn-edit-domain-api" data-apex="${escapeHtml(g.apex)}" title="编辑该域名的 API 同步规则与凭据 (服务商: ${escapeHtml(pName)})">
          <span>${escapeHtml(pName)} API</span>
        </button>
      `;
    } else {
      apiActionHtml = `
        <button type="button" class="btn btn-purple btn-sm btn-config-api" data-apex="${escapeHtml(g.apex)}" title="为该主域名配置 DNS API 动态同步模式">
          <span>配置 API</span>
        </button>
      `;
    }

    const starBtnHtml = `
      <button type="button" class="btn-star-apex ${g.isPinned ? 'pinned' : ''}" data-apex="${escapeHtml(g.apex)}" title="${g.isPinned ? '已置顶（点击取消置顶）' : '置顶此主域名'}">
        <svg class="star-icon" viewBox="0 0 24 24" ${g.isPinned ? 'fill="currentColor"' : 'fill="none" stroke="currentColor" stroke-width="2"'}>
          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
        </svg>
      </button>
    `;

    return `
      <tr class="apex-row" data-apex="${escapeHtml(g.apex)}">
        <td>
          <div class="apex-cell-title">
            ${starBtnHtml}
            <a href="javascript:void(0)" class="host-name apex-domain-name" data-apex="${escapeHtml(g.apex)}" title="点击进入二级页面查看子域名列表">
              <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--color-primary, #6366f1); flex-shrink: 0;">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="2" y1="12" x2="22" y2="12"></line>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
              </svg>
              <span>${escapeHtml(g.apex)}</span>
            </a>
          </div>
        </td>
        <td>
          ${expiry.badge}
        </td>
        <td>
          ${sslSummaryHtml}
        </td>
        <td class="time-cell" data-tooltip="${lastCheckedFull}">${lastChecked}</td>
        <td class="text-right">
          <div class="action-buttons">
            ${apiActionHtml}
            <button class="btn btn-primary btn-sm btn-view-subdomains" data-apex="${escapeHtml(g.apex)}" title="查看该主域名下的所有子域名监控">
              <span>查看</span>
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="9 18 15 12 9 6"></polyline>
              </svg>
            </button>
            <button class="btn btn-secondary btn-sm btn-check-group" data-apex="${escapeHtml(g.apex)}" title="一键重检该主域名下全部子域名">
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M23 4v6h-6"></path>
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
              <span>刷新</span>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  attachGroupEvents();
}

// 渲染二级页面子域名列表（注意：列表中不再显示域名到期时间！）
function renderSubdomainTable(domains) {
  if (domains.length === 0) {
    elements.domainsTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="empty-state">
          <p>当前主域名下暂无符合条件的子域名监控目标</p>
        </td>
      </tr>
    `;
    return;
  }

  const tipIcon = `<svg class="badge-tip-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

  elements.domainsTableBody.innerHTML = domains.map(dom => {
    // SSL 证书徽章
    let sslBadge = '';
    const sslErr = dom.ssl_error ? escapeHtml(dom.ssl_error) : '';
    const sslErrTip = sslErr ? `失败原因: ${sslErr}` : '';

    if (dom.check_ssl === false) {
      sslBadge = `<span class="status-badge badge-skipped cursor-help" data-tooltip="未开启 SSL 证书监控">不监控${tipIcon}</span>`;
    } else if (dom.ssl_status === 'expired' || dom.ssl_days_left < 0) {
      sslBadge = `<span class="status-badge badge-critical${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>证书已过期${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 3) {
      sslBadge = `<span class="status-badge badge-critical${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>极危 · 仅剩 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 7) {
      sslBadge = `<span class="status-badge badge-warning${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>橙色警告 · 剩余 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 15) {
      sslBadge = `<span class="status-badge badge-notice${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>注意 · 剩余 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 30) {
      sslBadge = `<span class="status-badge badge-info${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>关注 · 剩余 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_status === 'error') {
      sslBadge = `<span class="status-badge badge-critical cursor-help" data-tooltip="${sslErrTip || '证书检测失败'}">检测失败${tipIcon}</span>`;
    } else if (dom.ssl_status === 'healthy') {
      sslBadge = `<span class="status-badge badge-healthy">正常 · 剩余 ${dom.ssl_days_left} 天</span>`;
    } else {
      sslBadge = `<span class="status-badge badge-pending">等待巡检</span>`;
    }

    // 多主机节点明细
    let multiHostDetailsHtml = '';
    if (dom.check_ssl !== false && dom.multi_host && dom.ssl_details) {
      try {
        const nodes = JSON.parse(dom.ssl_details);
        if (nodes && nodes.length > 0) {
          multiHostDetailsHtml = `
            <details class="multihost-collapsible">
              <summary class="multihost-summary text-purple">分区节点明细 (${nodes.length} 个节点) ▾</summary>
              <div class="multihost-details-box">
                <table class="multihost-table">
                  <thead>
                    <tr>
                      <th>节点地址 / 备注</th>
                      <th>状态</th>
                      <th>到期时间</th>
                      <th>颁发者</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${nodes.map(n => {
                      let nBadge = '';
                      const nErr = n.error ? escapeHtml(n.error) : '';
                      const nErrTip = nErr ? `失败原因: ${nErr}` : '';

                      if (n.status === 'expired' || n.days_left < 0) nBadge = `<span class="status-badge badge-critical${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>已过期${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 3) nBadge = `<span class="status-badge badge-critical${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 7) nBadge = `<span class="status-badge badge-warning${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 15) nBadge = `<span class="status-badge badge-notice${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 30) nBadge = `<span class="status-badge badge-info${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.status === 'error') nBadge = `<span class="status-badge badge-critical cursor-help" data-tooltip="${nErrTip || '检测失败'}">失败${tipIcon}</span>`;
                      else nBadge = `<span class="status-badge badge-healthy">${n.days_left} 天</span>`;

                      const nTypeBadge = n.type ? `<span class="node-type-tag tag-${escapeHtml(n.type)}">${escapeHtml(n.type)}</span> ` : '';
                      const nTitle = n.alias ? `${nTypeBadge}<strong>${escapeHtml(n.node)}</strong> <span class="text-muted">(${escapeHtml(n.alias)})</span>` : `${nTypeBadge}<strong>${escapeHtml(n.node)}</strong>`;
                      const nExp = n.expires_at ? formatDate(n.expires_at) : '-';
                      return `
                        <tr>
                          <td>${nTitle}</td>
                          <td>${nBadge}</td>
                          <td>${nExp}</td>
                          <td class="text-muted">${escapeHtml(n.issuer || '-')}</td>
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              </div>
            </details>
          `;
        }
      } catch (e) {}
    }

    const lastChecked = dom.last_checked_at ? formatTimeAgo(dom.last_checked_at) : '尚未检测';
    const lastCheckedFull = dom.last_checked_at ? `最后检测: ${new Date(dom.last_checked_at).toLocaleString('zh-CN', { hour12: false })}` : '尚未检测';
    const targetUrl = `https://${dom.host}${dom.port && dom.port !== '443' ? ':' + dom.port : ''}`;
    const multiHostBadge = (dom.check_ssl !== false && dom.multi_host) ? `<span class="status-badge badge-purple" data-tooltip="多主机模式（已配置指定探测节点）">多主机</span>` : '';

    let pinBtn = '';
    if (dom.is_pinned) {
      pinBtn = `
        <button type="button" class="btn-pin-toggle active" data-id="${dom.id}" data-action="toggle-pin" title="已置顶（点击取消置顶）">
          <svg class="pin-icon" viewBox="0 0 24 24" fill="currentColor">
            <path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6l1 1 1-1v-6H18v-2l-2-2z"/>
          </svg>
        </button>
      `;
    } else {
      pinBtn = `
        <button type="button" class="btn-pin-toggle" data-id="${dom.id}" data-action="toggle-pin" title="点击置顶此监控目标">
          <svg class="pin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6l1 1 1-1v-6H18v-2l-2-2z"/>
          </svg>
        </button>
      `;
    }

    const muteBadge = dom.notify_disabled ? `<span class="mute-tag" data-tooltip="已关闭异常告警推送"><svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13.73 21a2 2 0 0 1-3.46 0"/><path d="M18.63 13A17.89 17.89 0 0 1 18 8"/><path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"/><line x1="1" y1="1" x2="23" y2="23"/></svg>免打扰</span>` : '';

    // 注意：二级页面的表格中只有 4 列，不再显示域名到期时间！
    return `
      <tr data-id="${dom.id}">
        <td>
          <div class="host-cell">
            ${pinBtn}
            <a href="${targetUrl}" target="_blank" rel="noopener noreferrer" class="host-name" data-tooltip="${escapeHtml(dom.host)}">${escapeHtml(dom.host)}</a>
            ${dom.port && dom.port !== '443' ? `<span class="port-tag">:${dom.port}</span>` : ''}
            ${multiHostBadge}
            ${muteBadge}
          </div>
        </td>
        <td>
          <div style="display: flex; align-items: center; gap: 0.5rem; white-space: nowrap !important;">
            ${sslBadge}
            ${(dom.check_ssl !== false && dom.ssl_issuer) ? `<span class="cert-issuer-inline" title="证书颁发者: ${escapeHtml(dom.ssl_issuer)} · 到期: ${dom.ssl_expires_at ? formatDate(dom.ssl_expires_at) : ''}">${escapeHtml(dom.ssl_issuer)}</span>` : ''}
          </div>
          ${multiHostDetailsHtml}
        </td>
        <td class="time-cell" data-tooltip="${lastCheckedFull}">${lastChecked}</td>
        <td class="text-right">
          <div class="action-buttons">
            <button class="btn btn-secondary btn-sm btn-action-check" data-id="${dom.id}" title="即刻单次重检">
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M23 4v6h-6"></path>
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
              <span>刷新</span>
            </button>
            <button class="btn btn-secondary btn-sm btn-action-edit" data-id="${dom.id}" title="编辑目标">
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 20h9"></path>
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
              </svg>
              <span>编辑</span>
            </button>
            <button class="btn btn-danger btn-sm btn-action-delete" data-id="${dom.id}" title="删除目标">
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
              <span>删除</span>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  attachActionEvents();
}

// 渲染全部监控目标平铺集合表格
function renderAllTable(domains) {
  if (domains.length === 0) {
    elements.domainsTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="empty-state">
          <p>暂无符合条件的监控目标</p>
        </td>
      </tr>
    `;
    return;
  }

  const tipIcon = `<svg class="badge-tip-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

  elements.domainsTableBody.innerHTML = domains.map(dom => {
    // SSL Badge
    let sslBadge = '';
    const sslErr = dom.ssl_error ? escapeHtml(dom.ssl_error) : '';
    const sslErrTip = sslErr ? `失败原因: ${sslErr}` : '';

    if (dom.check_ssl === false) {
      sslBadge = `<span class="status-badge badge-skipped cursor-help" data-tooltip="未开启 SSL 证书监控">不监控${tipIcon}</span>`;
    } else if (dom.ssl_status === 'expired' || dom.ssl_days_left < 0) {
      sslBadge = `<span class="status-badge badge-critical${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>证书已过期${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 3) {
      sslBadge = `<span class="status-badge badge-critical${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>极危 · 仅剩 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 7) {
      sslBadge = `<span class="status-badge badge-warning${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>橙色警告 · 剩余 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 15) {
      sslBadge = `<span class="status-badge badge-notice${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>注意 · 剩余 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_days_left <= 30) {
      sslBadge = `<span class="status-badge badge-info${sslErr ? ' cursor-help' : ''}"${sslErrTip ? ` data-tooltip="${sslErrTip}"` : ''}>关注 · 剩余 ${dom.ssl_days_left} 天${sslErr ? tipIcon : ''}</span>`;
    } else if (dom.ssl_status === 'error') {
      sslBadge = `<span class="status-badge badge-critical cursor-help" data-tooltip="${sslErrTip || '证书检测失败'}">检测失败${tipIcon}</span>`;
    } else if (dom.ssl_status === 'healthy') {
      sslBadge = `<span class="status-badge badge-healthy">正常 · 剩余 ${dom.ssl_days_left} 天</span>`;
    } else {
      sslBadge = `<span class="status-badge badge-pending">等待巡检</span>`;
    }

    const lastChecked = dom.last_checked_at ? formatTimeAgo(dom.last_checked_at) : '尚未检测';
    const lastCheckedFull = dom.last_checked_at ? `最后检测: ${new Date(dom.last_checked_at).toLocaleString('zh-CN', { hour12: false })}` : '尚未检测';
    const targetUrl = `https://${dom.host}${dom.port && dom.port !== '443' ? ':' + dom.port : ''}`;
    const multiHostBadge = (dom.check_ssl !== false && dom.multi_host) ? `<span class="status-badge badge-purple" data-tooltip="多主机模式（已配置指定探测节点）">多主机</span>` : '';

    let multiHostDetailsHtml = '';
    if (dom.check_ssl !== false && dom.multi_host && dom.ssl_details) {
      try {
        const nodes = JSON.parse(dom.ssl_details);
        if (nodes && nodes.length > 0) {
          multiHostDetailsHtml = `
            <details class="multihost-collapsible">
              <summary class="multihost-summary text-purple">分区节点明细 (${nodes.length} 个节点) ▾</summary>
              <div class="multihost-details-box">
                <table class="multihost-table">
                  <thead>
                    <tr>
                      <th>节点地址 / 备注</th>
                      <th>状态</th>
                      <th>到期时间</th>
                      <th>颁发者</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${nodes.map(n => {
                      let nBadge = '';
                      const nErr = n.error ? escapeHtml(n.error) : '';
                      const nErrTip = nErr ? `失败原因: ${nErr}` : '';

                      if (n.status === 'expired' || n.days_left < 0) nBadge = `<span class="status-badge badge-critical${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>已过期${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 3) nBadge = `<span class="status-badge badge-critical${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 7) nBadge = `<span class="status-badge badge-warning${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 15) nBadge = `<span class="status-badge badge-notice${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.days_left <= 30) nBadge = `<span class="status-badge badge-info${nErr ? ' cursor-help' : ''}"${nErrTip ? ` data-tooltip="${nErrTip}"` : ''}>${n.days_left} 天${nErr ? tipIcon : ''}</span>`;
                      else if (n.status === 'error') nBadge = `<span class="status-badge badge-critical cursor-help" data-tooltip="${nErrTip || '检测失败'}">失败${tipIcon}</span>`;
                      else nBadge = `<span class="status-badge badge-healthy">${n.days_left} 天</span>`;

                      const nTypeBadge = n.type ? `<span class="node-type-tag tag-${escapeHtml(n.type)}">${escapeHtml(n.type)}</span> ` : '';
                      const nTitle = n.alias ? `${nTypeBadge}<strong>${escapeHtml(n.node)}</strong> <span class="text-muted">(${escapeHtml(n.alias)})</span>` : `${nTypeBadge}<strong>${escapeHtml(n.node)}</strong>`;
                      const nExp = n.expires_at ? formatDate(n.expires_at) : '-';
                      return `
                        <tr>
                          <td>${nTitle}</td>
                          <td>${nBadge}</td>
                          <td>${nExp}</td>
                          <td class="text-muted">${escapeHtml(n.issuer || '-')}</td>
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              </div>
            </details>
          `;
        }
      } catch (e) {}
    }

    let pinBtn = '';
    if (dom.is_pinned) {
      pinBtn = `
        <button type="button" class="btn-pin-toggle active" data-id="${dom.id}" data-action="toggle-pin" title="已置顶（点击取消置顶）">
          <svg class="pin-icon" viewBox="0 0 24 24" fill="currentColor">
            <path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6l1 1 1-1v-6H18v-2l-2-2z"/>
          </svg>
        </button>
      `;
    } else {
      pinBtn = `
        <button type="button" class="btn-pin-toggle" data-id="${dom.id}" data-action="toggle-pin" title="点击置顶此监控目标">
          <svg class="pin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6l1 1 1-1v-6H18v-2l-2-2z"/>
          </svg>
        </button>
      `;
    }

    const muteBadge = dom.notify_disabled ? `<span class="mute-tag" data-tooltip="已关闭异常告警推送"><svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13.73 21a2 2 0 0 1-3.46 0"/><path d="M18.63 13A17.89 17.89 0 0 1 18 8"/><path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"/><line x1="1" y1="1" x2="23" y2="23"/></svg>免打扰</span>` : '';

    const domApex = (getApexDomain(dom.host) || dom.host).toLowerCase();
    const apexBadge = (dom.host.toLowerCase() !== domApex)
      ? `<span class="badge badge-purple badge-apex-jump" data-apex="${escapeHtml(domApex)}" title="点击跳入主域名 ${escapeHtml(domApex)} 并显示其全部目标">${escapeHtml(domApex)}</span>`
      : '';

    return `
      <tr data-id="${dom.id}">
        <td>
          <div class="host-cell">
            ${pinBtn}
            <a href="${targetUrl}" target="_blank" rel="noopener noreferrer" class="host-name" data-tooltip="${escapeHtml(dom.host)}">${escapeHtml(dom.host)}</a>
            ${dom.port && dom.port !== '443' ? `<span class="port-tag">:${dom.port}</span>` : ''}
            ${apexBadge}
            ${multiHostBadge}
            ${muteBadge}
          </div>
        </td>
        <td>
          <div style="display: flex; align-items: center; gap: 0.5rem; white-space: nowrap !important;">
            ${sslBadge}
            ${(dom.check_ssl !== false && dom.ssl_issuer) ? `<span class="cert-issuer-inline" title="证书颁发者: ${escapeHtml(dom.ssl_issuer)} · 到期: ${dom.ssl_expires_at ? formatDate(dom.ssl_expires_at) : ''}">${escapeHtml(dom.ssl_issuer)}</span>` : ''}
          </div>
          ${multiHostDetailsHtml}
        </td>
        <td class="time-cell" data-tooltip="${lastCheckedFull}">${lastChecked}</td>
        <td class="text-right">
          <div class="action-buttons">
            <button class="btn btn-secondary btn-sm btn-action-check" data-id="${dom.id}" title="即刻单次重检">
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M23 4v6h-6"></path>
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
              <span>刷新</span>
            </button>
            <button class="btn btn-secondary btn-sm btn-action-edit" data-id="${dom.id}" title="编辑目标">
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 20h9"></path>
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
              </svg>
              <span>编辑</span>
            </button>
            <button class="btn btn-danger btn-sm btn-action-delete" data-id="${dom.id}" title="删除目标">
              <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
              <span>删除</span>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  attachActionEvents();
}

// 主域名聚合列表的事件监听（点击进入二级子域名视图、批量刷新）
function attachGroupEvents() {
  function navigateToSubdomains(apex) {
    state.viewMode = 'subdomains';
    state.currentApex = apex;
    state.activeFilter = 'all'; // 取消告警等筛选条件，展示全部子域名监控
    state.currentPage = 1;
    updateFilterActiveUI('all');
    renderDashboard();
  }

  document.querySelectorAll('.apex-domain-name, .badge-subdomain-count, .btn-view-subdomains').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const apex = el.dataset.apex;
      if (apex) {
        navigateToSubdomains(apex);
      }
    });
  });

  // 星标置顶按钮事件
  document.querySelectorAll('.btn-star-apex').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const apex = btn.dataset.apex;
      if (!apex) return;
      const groups = buildDomainGroups(state.domains);
      const group = groups.find(g => g.apex === apex);
      const targets = group ? group.targets : [];
      await togglePinApex(apex, targets);
      renderDashboard();
    });
  });

  // 编辑 API / 配置 API 按钮事件
  document.querySelectorAll('.btn-edit-domain-api, .btn-config-api').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const apex = btn.dataset.apex;
      if (apex && typeof window.handleEditDomainAPI === 'function') {
        window.handleEditDomainAPI(apex);
      }
    });
  });

  document.querySelectorAll('.apex-row').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('button') || e.target.closest('a')) return;
      const apex = row.dataset.apex;
      if (apex) {
        navigateToSubdomains(apex);
      }
    });
  });

  document.querySelectorAll('.btn-check-group').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const apex = btn.dataset.apex;
      if (!apex) return;
      btn.classList.add('spinning');
      try {
        const groups = buildDomainGroups(state.domains);
        const group = groups.find(g => g.apex === apex);
        if (group && group.targets.length > 0) {
          showToast(`正在刷新 ${apex} 下的 ${group.targets.length} 个监控目标...`, 'info');
          for (const t of group.targets) {
            try {
              await api(`/api/domains/${t.id}/check`, { method: 'POST' });
            } catch (err) {}
          }
          await loadDomains();
          showToast(`已刷新 ${apex} 下全部目标`, 'success');
        }
      } catch (err) {
      } finally {
        btn.classList.remove('spinning');
      }
    });
  });
}


function attachActionEvents() {
  // 快速切换置顶状态
  document.querySelectorAll('.btn-pin-toggle').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.id, 10);
      try {
        const res = await api(`/api/domains/${id}/pin`, { method: 'POST' });
        const dom = state.domains.find(d => d.id === id);
        if (dom) {
          dom.is_pinned = res.is_pinned;
          showToast(res.is_pinned ? `已手动置顶 ${dom.host}` : `已取消置顶 ${dom.host}`, 'info');
          renderDashboard();
        }
      } catch (err) {
        // Handled in api()
      }
    });
  });

  document.querySelectorAll('.btn-action-check').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id;
      btn.classList.add('spinning');
      try {
        const updated = await api(`/api/domains/${id}/check`, { method: 'POST' });
        showToast(`已刷新 ${updated.host} 检测结果`, 'success');
        await loadDomains();
      } catch (err) {
        // Handled in api()
      } finally {
        btn.classList.remove('spinning');
      }
    });
  });

  document.querySelectorAll('.btn-action-edit').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.id, 10);
      const dom = state.domains.find(d => d.id === id);
      if (!dom) return;

      document.getElementById('modal-domain-title').textContent = '编辑目标';
      document.getElementById('form-domain-id').value = dom.id;
      document.getElementById('form-domain-host').value = dom.host;
      document.getElementById('form-domain-port').value = dom.port || '443';
      document.getElementById('form-domain-is-pinned').checked = !!dom.is_pinned;
      document.getElementById('form-domain-notify-disabled').checked = !!dom.notify_disabled;
      const checkSSL = dom.check_ssl !== false;
      document.getElementById('form-domain-check-ssl').checked = checkSSL;
      document.getElementById('form-domain-check-reg').checked = dom.check_domain;
      document.getElementById('form-domain-multi-host').checked = !!dom.multi_host;

      const portGroup = document.getElementById('form-group-port');
      const multiGroup = document.getElementById('form-group-multi-host');
      if (checkSSL) {
        if (portGroup) portGroup.classList.remove('hidden');
        if (multiGroup) multiGroup.classList.remove('hidden');
      } else {
        if (portGroup) portGroup.classList.add('hidden');
        if (multiGroup) multiGroup.classList.add('hidden');
      }
      
      // 反序列化解析多主机节点
      state.formMultiHostNodes = [];
      if (dom.hosts_list) {
        try {
          const parsed = JSON.parse(dom.hosts_list);
          if (Array.isArray(parsed)) {
            state.formMultiHostNodes = parsed.map(p => ({
              type: (p.type || 'A').toUpperCase(),
              value: p.value || p.address || '',
              alias: p.alias || '',
            })).filter(p => !!p.value);
          }
        } catch (e) {
          const lines = dom.hosts_list.split('\n');
          for (let line of lines) {
            line = line.trim();
            if (!line) continue;
            let alias = '';
            if (line.includes('#')) {
              const parts = line.split('#');
              line = parts[0].trim();
              alias = parts[1].trim();
            } else if (line.includes('//')) {
              const parts = line.split('//');
              line = parts[0].trim();
              alias = parts[1].trim();
            }
            let type = 'A';
            const parts = line.split(/\s+/);
            if (parts.length >= 2 && ['A', 'AAAA', 'CNAME'].includes(parts[0].toUpperCase())) {
              type = parts[0].toUpperCase();
              line = parts[1].trim();
            }
            if (line) {
              state.formMultiHostNodes.push({ type, value: line, alias });
            }
          }
        }
      }
      renderFormMultiHostNodes();

      if (dom.multi_host) {
        document.getElementById('form-domain-multi-host-box').classList.remove('hidden');
      } else {
        document.getElementById('form-domain-multi-host-box').classList.add('hidden');
      }
      openModal('modal-domain');
    });
  });

  document.querySelectorAll('.btn-action-delete').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.id, 10);
      const dom = state.domains.find(d => d.id === id);
      if (!dom) return;

      confirmModal(`确定要移除监控目标 ${dom.host} 吗？移除后将停止该目标的证书与状态巡检。`, async () => {
        try {
          await api(`/api/domains/${id}`, { method: 'DELETE' });
          showToast(`已成功移除 ${dom.host}`, 'info');
          await loadDomains();
        } catch (err) {
          // Handled in api()
        }
      });
    });
  });

  // 主域名跳转胶囊：点击跳入该主域名并取消筛选显示全部
  document.querySelectorAll('.badge-apex-jump').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const apex = el.dataset.apex;
      if (apex) {
        state.viewMode = 'subdomains';
        state.currentApex = apex;
        state.activeFilter = 'all'; // 取消筛选，显示全部
        state.currentPage = 1;
        updateFilterActiveUI('all');
        renderDashboard();
      }
    });
  });
}

// Search & Filter
elements.searchInput.addEventListener('input', (e) => {
  state.searchQuery = e.target.value;
  state.currentPage = 1;
  renderDashboard();
});

// 视图模式胶囊切换：主域名模式 / 全部监控目标
if (elements.viewModeTabs) {
  elements.viewModeTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const mode = tab.dataset.view;
      if (mode) {
        state.viewMode = mode;
        state.currentApex = '';
        state.activeFilter = 'all'; // 切换视图模式时取消告警筛选，展示全部内容
        state.currentPage = 1;
        updateFilterActiveUI('all');
        renderDashboard();
      }
    });
  });
}

// 二级页面返回主域名列表 (面包屑返回按钮 & 根路径文字)
function backToGroupsView() {
  state.viewMode = 'groups';
  state.currentApex = '';
  state.activeFilter = 'all'; // 返回主域名列表时取消告警筛选，展示全部主域名
  state.currentPage = 1;
  updateFilterActiveUI('all');
  renderDashboard();
}

if (elements.btnBackToGroups) {
  elements.btnBackToGroups.addEventListener('click', backToGroupsView);
}

if (elements.crumbLinkRoot) {
  elements.crumbLinkRoot.addEventListener('click', backToGroupsView);
}

// 分页控件事件：上一页 / 下一页
if (elements.btnPagePrev) {
  elements.btnPagePrev.addEventListener('click', () => {
    if (state.currentPage > 1) {
      state.currentPage--;
      renderDashboard();
    }
  });
}

if (elements.btnPageNext) {
  elements.btnPageNext.addEventListener('click', () => {
    state.currentPage++;
    renderDashboard();
  });
}

// 每页条数下拉选择 (10, 20, 50, 100)
if (elements.pageSizeSelect) {
  elements.pageSizeSelect.addEventListener('change', (e) => {
    state.pageSize = parseInt(e.target.value, 10) || 20;
    state.currentPage = 1;
    renderDashboard();
  });
}

if (elements.domainGroupSelect) {
  elements.domainGroupSelect.addEventListener('change', (e) => {
    state.domainGroupFilter = e.target.value;
    state.currentPage = 1;
    renderDashboard();
  });
}

// 筛选栏 Tab 点击
if (elements.filterTabs) {
  elements.filterTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      setActiveFilter(tab.dataset.filter);
    });
  });
}

// 顶部 KPI 统计卡片点击筛选 (双向联动)
if (elements.kpiCards) {
  elements.kpiCards.forEach(card => {
    const filter = card.dataset.filter;
    card.addEventListener('click', () => {
      setActiveFilter(filter);
    });
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        setActiveFilter(filter);
      }
    });
  });
}

// 顶部“临期与告警阶梯”卡片点击联动筛选告警目标
if (elements.kpiCardPolicy) {
  elements.kpiCardPolicy.addEventListener('click', () => {
    setActiveFilter('warning');
  });
  elements.kpiCardPolicy.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setActiveFilter('warning');
    }
  });
}

// Add Modal Open (Default unchecked for RDAP)
elements.btnAddModal.addEventListener('click', () => {
  document.getElementById('modal-domain-title').textContent = '添加目标';
  elements.domainForm.reset();
  document.getElementById('form-domain-id').value = '';
  document.getElementById('form-domain-port').value = '443';
  document.getElementById('form-domain-is-pinned').checked = false;
  document.getElementById('form-domain-notify-disabled').checked = false;
  document.getElementById('form-domain-check-ssl').checked = true;
  document.getElementById('form-domain-check-reg').checked = false; // 默认不勾选 RDAP
  document.getElementById('form-domain-multi-host').checked = false;
  const portGroup = document.getElementById('form-group-port');
  const multiGroup = document.getElementById('form-group-multi-host');
  if (portGroup) portGroup.classList.remove('hidden');
  if (multiGroup) multiGroup.classList.remove('hidden');
  state.formMultiHostNodes = [];
  renderFormMultiHostNodes();
  document.getElementById('form-domain-multi-host-box').classList.add('hidden');
  openModal('modal-domain');
});

// Add/Edit Domain Form Submit
elements.domainForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = document.getElementById('form-domain-id').value;
  const host = document.getElementById('form-domain-host').value.trim();
  const port = document.getElementById('form-domain-port').value.trim() || '443';
  const is_pinned = document.getElementById('form-domain-is-pinned').checked;
  const notify_disabled = document.getElementById('form-domain-notify-disabled').checked;
  const check_ssl = document.getElementById('form-domain-check-ssl').checked;
  const check_domain = document.getElementById('form-domain-check-reg').checked;
  const multi_host = document.getElementById('form-domain-multi-host').checked;

  if (!check_ssl && !check_domain) {
    showToast('请至少开启 SSL 证书检查或域名过期检查其中一项', 'warning');
    return;
  }

  let hosts_list = '';
  if (check_ssl && multi_host) {
    if (!state.formMultiHostNodes || state.formMultiHostNodes.length === 0) {
      showToast('已启用多主机模式，请至少添加一个探测节点', 'error');
      return;
    }
    hosts_list = JSON.stringify(state.formMultiHostNodes);
  }

  const payload = { host, port, check_ssl, check_domain, multi_host: check_ssl && multi_host, hosts_list, is_pinned, notify_disabled };

  try {
    if (id) {
      await api(`/api/domains/${id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      });
      showToast(`已更新目标 ${host}`, 'success');
    } else {
      await api('/api/domains', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      showToast(`已添加目标 ${host}，正在执行首次检测`, 'success');
    }
    closeModal('modal-domain');
    await loadDomains();
  } catch (err) {
    // Handled in api()
  }
});

// Trigger Check All
elements.btnCheckAll.addEventListener('click', async () => {
  elements.btnCheckAll.querySelector('svg').classList.add('spinning');
  try {
    await api('/api/check-all', { method: 'POST' });
    showToast('已触发后台全量巡检，请稍候...', 'info');
    setTimeout(loadDomains, 3000);
    setTimeout(loadDomains, 7000);
  } catch (err) {
    // Handled in api()
  } finally {
    setTimeout(() => {
      elements.btnCheckAll.querySelector('svg').classList.remove('spinning');
    }, 1500);
  }
});

// Open Batch & Backup Modal
if (elements.btnBatchModal) {
  elements.btnBatchModal.addEventListener('click', () => {
    loadDNSData();
    switchBackupModalTab('tab-dns-api-import');
    openModal('modal-batch-backup');
  });
}

// 模态框选项卡切换辅助函数
function switchBackupModalTab(tabId) {
  document.querySelectorAll('.backup-tab').forEach(t => {
    if (t.dataset.tab === tabId) {
      t.classList.add('active');
    } else {
      t.classList.remove('active');
    }
  });
  document.querySelectorAll('.backup-panel').forEach(p => {
    if (p.id === tabId) {
      p.classList.remove('hidden');
      p.classList.add('active');
    } else {
      p.classList.add('hidden');
      p.classList.remove('active');
    }
  });
}

// “添加目标”底部按钮切换
const linkSwitchBatch = document.getElementById('link-switch-to-batch');
if (linkSwitchBatch) {
  linkSwitchBatch.addEventListener('click', () => {
    closeModal('modal-domain');
    openModal('modal-batch-backup');
    switchBackupModalTab('tab-batch-import');
  });
}

const linkSwitchAPI = document.getElementById('link-switch-to-api-import');
if (linkSwitchAPI) {
  linkSwitchAPI.addEventListener('click', () => {
    closeModal('modal-domain');
    loadDNSData();
    openModal('modal-batch-backup');
    switchBackupModalTab('tab-dns-api-import');
  });
}

// “设置 - API 凭据”头部按钮切换为 API 导入
const btnSwitchAPISettings = document.getElementById('btn-switch-to-api-import-settings');
if (btnSwitchAPISettings) {
  btnSwitchAPISettings.addEventListener('click', () => {
    closeModal('modal-settings');
    loadDNSData();
    openModal('modal-batch-backup');
    switchBackupModalTab('tab-dns-api-import');
  });
}

// Clear batch text
if (elements.btnBatchClear) {
  elements.btnBatchClear.addEventListener('click', () => {
    elements.batchImportText.value = '';
    if (dnsParseStatus) {
      dnsParseStatus.classList.add('hidden');
    }
    elements.batchImportText.focus();
  });
}

// DNS Export File Upload & Dropzone Handling
const dnsDropzone = document.getElementById('dns-dropzone');
const dnsFileInput = document.getElementById('batch-dns-file');
const btnTriggerDnsFile = document.getElementById('btn-trigger-dns-file');
const dnsParseStatus = document.getElementById('dns-parse-status');
const dnsStatusBadge = document.getElementById('dns-status-badge');
const dnsStatusText = document.getElementById('dns-status-text');

if (dnsDropzone && dnsFileInput) {
  // Rely on native <label for="batch-dns-file"> click behavior to open file chooser.
  // Handle drag and drop:

  dnsDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dnsDropzone.classList.add('drag-over');
  });

  ['dragleave', 'dragend'].forEach(type => {
    dnsDropzone.addEventListener(type, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dnsDropzone.classList.remove('drag-over');
    });
  });

  dnsDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dnsDropzone.classList.remove('drag-over');
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleDnsFileUpload(e.dataTransfer.files[0]);
    }
  });

  dnsFileInput.addEventListener('change', () => {
    if (dnsFileInput.files && dnsFileInput.files.length > 0) {
      handleDnsFileUpload(dnsFileInput.files[0]);
      dnsFileInput.value = '';
    }
  });
}

async function handleDnsFileUpload(file) {
  if (!file) return;

  if (dnsParseStatus) {
    dnsParseStatus.classList.remove('hidden');
    dnsStatusBadge.className = 'badge badge-gray';
    dnsStatusBadge.textContent = '解析中...';
    dnsStatusText.textContent = `正在解析 ${file.name} ...`;
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await api('/api/domains/parse-file', {
      method: 'POST',
      body: formData,
    });

    if (dnsParseStatus) {
      dnsStatusBadge.className = 'badge badge-green';
      dnsStatusBadge.textContent = '解析成功';
      dnsStatusText.textContent = `${res.format} · 提取到 ${res.domain_count} 个 Web 域名 (已自动过滤 ${res.filtered_records} 条非 Web 记录)`;
    }

    if (elements.batchImportText && res.domains && res.domains.length > 0) {
      const existing = elements.batchImportText.value.trim();
      const newDomainsText = res.domains.join('\n');
      if (existing) {
        elements.batchImportText.value = existing + '\n' + newDomainsText;
      } else {
        elements.batchImportText.value = newDomainsText;
      }
    }

    showToast(res.message || `成功提取 ${res.domain_count} 个有效域名`, 'success');
  } catch (err) {
    if (dnsParseStatus) {
      dnsStatusBadge.className = 'badge badge-rose';
      dnsStatusBadge.textContent = '解析失败';
      dnsStatusText.textContent = err.message || '文件解析遇到错误';
    }
  }
}

// Batch Import Submit
if (elements.batchImportForm) {
  elements.batchImportForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const content = elements.batchImportText.value.trim();
    if (!content) {
      showToast('请输入要导入的域名列表', 'error');
      return;
    }
    const mode = document.getElementById('batch-rdap-mode').value;
    const default_port = document.getElementById('batch-default-port').value.trim() || '443';

    const btn = document.getElementById('btn-batch-submit');
    btn.disabled = true;
    btn.textContent = '正在导入...';

    try {
      const res = await api('/api/domains/batch-import', {
        method: 'POST',
        body: JSON.stringify({ content, mode, default_port }),
      });
      showToast(res.message || '批量导入成功', 'success');
      closeModal('modal-batch-backup');
      elements.batchImportText.value = '';
      await loadDomains();
      setTimeout(loadDomains, 3000);
      setTimeout(loadDomains, 6000);
    } catch (err) {
      // Handled in api()
    } finally {
      btn.disabled = false;
      btn.textContent = '开始批量导入';
    }
  });
}

// Export Backup (JSON)
if (elements.btnExportJson) {
  elements.btnExportJson.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/backup/export?format=json');
      if (!res.ok) throw new Error('导出备份失败');
      const blob = await res.blob();
      const disposition = res.headers.get('Content-Disposition') || '';
      let filename = 'argus-backup.json';
      const match = disposition.match(/filename="?([^";]+)"?/);
      if (match && match[1]) filename = match[1];

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast('系统备份文件已成功导出', 'success');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });
}

// Export Plain TXT
if (elements.btnExportTxt) {
  elements.btnExportTxt.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/backup/export?format=txt');
      if (!res.ok) throw new Error('导出纯文本列表失败');
      const blob = await res.blob();
      const disposition = res.headers.get('Content-Disposition') || '';
      let filename = 'argus-domains.txt';
      const match = disposition.match(/filename="?([^";]+)"?/);
      if (match && match[1]) filename = match[1];

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast('域名列表文本已成功导出', 'success');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });
}

// Backup Restore Submit
if (elements.backupRestoreForm) {
  elements.backupRestoreForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = elements.backupFileInput.files[0];
    if (!file) {
      showToast('请选择有效的备份 JSON 文件', 'error');
      return;
    }

    const restoreDomains = document.getElementById('restore-chk-domains').checked;
    const restoreSettings = document.getElementById('restore-chk-settings').checked;
    if (!restoreDomains && !restoreSettings) {
      showToast('请至少勾选一项要恢复的内容（域名或配置）', 'error');
      return;
    }

    const reader = new FileReader();
    reader.onload = async (event) => {
      const btn = document.getElementById('btn-restore-submit');
      if (btn) {
        btn.disabled = true;
        btn.textContent = '正在恢复...';
      }
      try {
        const data = JSON.parse(event.target.result);
        const res = await api('/api/backup/import', {
          method: 'POST',
          body: JSON.stringify({
            restore_domains: restoreDomains,
            restore_settings: restoreSettings,
            data,
          }),
        });

        showToast(res.message || '备份恢复完成', 'success');
        closeModal('modal-batch-backup');
        elements.backupFileInput.value = '';
        await Promise.all([loadDomains(), loadSettings()]);
        setTimeout(loadDomains, 3000);
      } catch (err) {
        showToast(err.message || '备份解析失败，请检查文件格式', 'error');
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = '执行数据恢复';
        }
      }
    };
    reader.readAsText(file);
  });
}

// Shoutrrr URL parser
function parseShoutrrrUrl(rawUrl) {
  if (!rawUrl) return null;
  const str = rawUrl.trim();
  try {
    if (str.startsWith('telegram://')) {
      const atIdx = str.indexOf('@');
      const token = atIdx > 11 ? str.slice(11, atIdx) : '';
      let desc = 'Telegram 机器人';
      try {
        const u = new URL(str);
        const ch = u.searchParams.get('channels') || u.searchParams.get('chats') || '';
        const tokenPreview = token.length > 8 ? `${token.slice(0, 4)}...${token.slice(-4)}` : token;
        desc = `Chat ID: ${ch || '默认'} · Token: ${tokenPreview}`;
      } catch {
        desc = str;
      }
      return {
        type: 'Telegram',
        badge: 'badge-blue',
        desc: desc,
        raw: str,
      };
    }
    if (str.startsWith('bark://')) {
      const atIdx = str.indexOf('@');
      const key = atIdx > 7 ? str.slice(7, atIdx) : '';
      const hostPart = atIdx > -1 ? str.slice(atIdx + 1).replace(/\/.*$/, '') : 'api.day.app';
      const keyPreview = key.length > 8 ? `${key.slice(0, 4)}...${key.slice(-4)}` : key;
      return {
        type: 'Bark (iOS)',
        badge: 'badge-blue',
        desc: `服务器: ${hostPart} · 设备: ${keyPreview}`,
        raw: str,
      };
    }
    if (str.startsWith('discord://')) {
      const atIdx = str.indexOf('@');
      const whId = atIdx > -1 ? str.slice(atIdx + 1).replace(/\/.*$/, '') : '';
      return {
        type: 'Discord',
        badge: 'badge-purple',
        desc: `Webhook ID: ${whId}`,
        raw: str,
      };
    }
    if (str.startsWith('slack://')) {
      return {
        type: 'Slack',
        badge: 'badge-amber',
        desc: 'Slack Incoming Webhook',
        raw: str,
      };
    }
    if (str.startsWith('smtp://') || str.startsWith('smtps://')) {
      let desc = 'SMTP 邮件';
      try {
        const u = new URL(str.replace('smtps://', 'http://').replace('smtp://', 'http://'));
        const to = u.searchParams.get('to') || u.searchParams.get('toAddresses') || '';
        const sub = u.searchParams.get('subject') || '';
        desc = `收件人: ${decodeURIComponent(to)} (${u.host})`;
        if (sub) {
          desc += ` · 主题: ${decodeURIComponent(sub)}`;
        }
      } catch {
        desc = str;
      }
      return {
        type: '邮件 (SMTP)',
        badge: 'badge-green',
        desc: desc,
        raw: str,
      };
    }
    if (str.startsWith('ntfy://')) {
      const parts = str.replace('ntfy://', '').split('/');
      const host = parts[0] || 'ntfy.sh';
      const topic = parts.slice(1).join('/') || '';
      return {
        type: 'Ntfy',
        badge: 'badge-blue',
        desc: `Topic: ${topic} (${host})`,
        raw: str,
      };
    }
    if (str.startsWith('gotify://') || str.startsWith('gotifys://')) {
      const isTLS = str.startsWith('gotifys://');
      const clean = str.replace(/^gotifys?:\/\//, '');
      const parts = clean.split('/');
      const host = parts[0] || '';
      const token = parts.slice(1).join('/') || '';
      const tokenPreview = token.length > 8 ? `${token.slice(0, 4)}...${token.slice(-4)}` : token;
      return {
        type: 'Gotify',
        badge: 'badge-blue',
        desc: `服务器: ${host} (${isTLS ? 'HTTPS' : 'HTTP'}) · Token: ${tokenPreview}`,
        raw: str,
      };
    }
    if (str.startsWith('generic+')) {
      const realUrl = str.replace('generic+', '');
      return {
        type: '通用 Webhook',
        badge: 'badge-purple',
        desc: realUrl,
        raw: str,
      };
    }
  } catch (e) {
    console.error('Error parsing shoutrrr URL', e);
  }
  return {
    type: '自定义 Shoutrrr',
    badge: 'badge-gray',
    desc: str,
    raw: str,
  };
}

// Reset notification channel form
function resetChannelForm() {
  state.editingChannelIndex = -1;
  const btnAddText = document.getElementById('btn-add-channel-text');
  if (btnAddText) {
    btnAddText.textContent = '添加到通知列表';
  }
  const btnCancel = document.getElementById('btn-cancel-edit-channel');
  if (btnCancel) {
    btnCancel.classList.add('hidden');
  }
  document.querySelectorAll('.channel-card.is-editing').forEach(c => c.classList.remove('is-editing'));
}

// Load channel configuration into form for editing
function loadChannelToForm(index) {
  const channels = state.editingChannels || [];
  const rawUrl = channels[index];
  if (!rawUrl) return;

  state.editingChannelIndex = index;
  renderConfiguredChannels();

  const btnAddText = document.getElementById('btn-add-channel-text');
  if (btnAddText) {
    btnAddText.textContent = '保存渠道修改';
  }
  const btnCancel = document.getElementById('btn-cancel-edit-channel');
  if (btnCancel) {
    btnCancel.classList.remove('hidden');
  }

  const selectType = document.getElementById('select-channel-type');
  const str = rawUrl.trim();

  const switchType = (val) => {
    if (selectType) {
      selectType.value = val;
      selectType.dispatchEvent(new Event('change'));
    }
  };

  try {
    if (str.startsWith('telegram://')) {
      switchType('telegram');
      const atIdx = str.indexOf('@');
      const token = atIdx > 11 ? str.slice(11, atIdx) : '';
      const u = new URL(str);
      const ch = u.searchParams.get('channels') || u.searchParams.get('chats') || '';
      document.getElementById('ch-tg-token').value = token;
      document.getElementById('ch-tg-chatid').value = ch;
      return;
    }
    if (str.startsWith('bark://')) {
      switchType('bark');
      const atIdx = str.indexOf('@');
      const key = atIdx > 7 ? str.slice(7, atIdx) : '';
      const hostPart = atIdx > -1 ? str.slice(atIdx + 1).replace(/\/.*$/, '') : 'api.day.app';
      document.getElementById('ch-bark-key').value = key;
      document.getElementById('ch-bark-host').value = hostPart;
      return;
    }
    if (str.startsWith('discord://')) {
      switchType('discord');
      const atIdx = str.indexOf('@');
      const whId = atIdx > -1 ? str.slice(atIdx + 1).replace(/\/.*$/, '') : '';
      const token = atIdx > 10 ? str.slice(10, atIdx) : '';
      document.getElementById('ch-discord-url').value = `https://discord.com/api/webhooks/${whId}/${token}`;
      return;
    }
    if (str.startsWith('slack://')) {
      switchType('slack');
      const parts = str.replace('slack://', '').split('/');
      if (parts.length >= 3) {
        document.getElementById('ch-slack-url').value = `https://hooks.slack.com/services/${parts[0]}/${parts[1]}/${parts[2]}`;
      } else {
        document.getElementById('ch-slack-url').value = str;
      }
      return;
    }
    if (str.startsWith('smtp://') || str.startsWith('smtps://')) {
      switchType('smtp');
      const dummyUrl = new URL(str.replace('smtps://', 'http://').replace('smtp://', 'http://'));
      document.getElementById('ch-smtp-host').value = dummyUrl.hostname || '';
      document.getElementById('ch-smtp-port').value = dummyUrl.port || '587';
      document.getElementById('ch-smtp-user').value = decodeURIComponent(dummyUrl.username || '');
      document.getElementById('ch-smtp-pass').value = decodeURIComponent(dummyUrl.password || '');
      document.getElementById('ch-smtp-from').value = decodeURIComponent(dummyUrl.searchParams.get('from') || dummyUrl.searchParams.get('fromAddress') || '');
      document.getElementById('ch-smtp-to').value = decodeURIComponent(dummyUrl.searchParams.get('to') || dummyUrl.searchParams.get('toAddresses') || '');
      document.getElementById('ch-smtp-subject').value = decodeURIComponent(dummyUrl.searchParams.get('subject') || '');
      return;
    }
    if (str.startsWith('ntfy://')) {
      switchType('ntfy');
      const parts = str.replace('ntfy://', '').split('/');
      document.getElementById('ch-ntfy-host').value = parts[0] || 'ntfy.sh';
      document.getElementById('ch-ntfy-topic').value = parts.slice(1).join('/') || '';
      return;
    }
    if (str.startsWith('gotify://') || str.startsWith('gotifys://')) {
      switchType('gotify');
      const isTLS = str.startsWith('gotifys://');
      const clean = str.replace(/^gotifys?:\/\//, '');
      const parts = clean.split('/');
      const host = parts[0] || '';
      const token = parts.slice(1).join('/') || '';
      document.getElementById('ch-gotify-host').value = host;
      document.getElementById('ch-gotify-token').value = token;
      const tlsCheckbox = document.getElementById('ch-gotify-tls');
      if (tlsCheckbox) tlsCheckbox.checked = isTLS;
      return;
    }
    if (str.startsWith('generic+')) {
      switchType('webhook');
      document.getElementById('ch-webhook-url').value = str.replace('generic+', '');
      return;
    }
  } catch (err) {
    console.warn('Error auto parsing channel URL for editing', err);
  }

  // fallback to custom
  switchType('custom');
  document.getElementById('ch-custom-url').value = str;
}

// Render configured channels list
function renderConfiguredChannels() {
  const container = document.getElementById('configured-channels-list');
  if (!container) return;

  const channels = state.editingChannels || [];
  if (channels.length === 0) {
    container.innerHTML = '<div class="channel-empty-tip">暂未配置任何通知渠道，请在下方选择渠道添加。</div>';
    return;
  }

  container.innerHTML = channels.map((rawUrl, index) => {
    const info = parseShoutrrrUrl(rawUrl);
    const isEditing = state.editingChannelIndex === index;
    return `
      <div class="channel-card ${isEditing ? 'is-editing' : ''}" id="channel-card-${index}">
        <div class="channel-card-left">
          <span class="badge ${info.badge}">${info.type}</span>
          <div class="channel-card-info">
            <span class="channel-card-desc" title="${escapeHtml(info.raw)}">${escapeHtml(info.desc)}</span>
          </div>
        </div>
        <div class="channel-card-actions">
          <button type="button" class="btn btn-secondary btn-xs btn-test-channel" data-index="${index}" title="单独测试此通知渠道">
            <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="5 3 19 12 5 21 5 3"></polygon>
            </svg>
            <span>测试</span>
          </button>
          <button type="button" class="btn btn-secondary btn-xs btn-edit-channel" data-index="${index}" title="编辑修改此渠道配置">
            <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
            </svg>
            <span>修改</span>
          </button>
          <button type="button" class="btn btn-ghost btn-xs btn-remove-channel text-rose" data-index="${index}" title="删除此渠道">
            <svg class="icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
            <span>删除</span>
          </button>
        </div>
      </div>
    `;
  }).join('');

  // 1. Separate single channel test
  container.querySelectorAll('.btn-test-channel').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = parseInt(btn.dataset.index, 10);
      const rawUrl = channels[idx];
      if (!rawUrl) return;

      const origHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span>测试中...</span>';
      try {
        const res = await api('/api/test-notification', {
          method: 'POST',
          body: JSON.stringify({ url: rawUrl }),
        });
        showToast(res.message || '该渠道测试通知已发送成功', 'success');
      } catch (err) {
        showToast(err.message || '该渠道测试通知发送失败', 'error');
      } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
      }
    });
  });

  // 2. Edit channel
  container.querySelectorAll('.btn-edit-channel').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.index, 10);
      loadChannelToForm(idx);
    });
  });

  // 3. Remove channel
  container.querySelectorAll('.btn-remove-channel').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.index, 10);
      if (!isNaN(idx) && idx >= 0 && idx < state.editingChannels.length) {
        if (state.editingChannelIndex === idx) {
          resetChannelForm();
        } else if (state.editingChannelIndex > idx) {
          state.editingChannelIndex--;
        }
        state.editingChannels.splice(idx, 1);
        renderConfiguredChannels();
      }
    });
  });
}

// Channel type dropdown switcher
const selectChannelType = document.getElementById('select-channel-type');
if (selectChannelType) {
  selectChannelType.addEventListener('change', (e) => {
    const type = e.target.value;
    document.querySelectorAll('.channel-field-group').forEach(group => {
      group.classList.add('hidden');
    });
    const targetGroup = document.getElementById(`fields-${type}`);
    if (targetGroup) {
      targetGroup.classList.remove('hidden');
    }
  });
}

// Cancel channel editing
const btnCancelEditChannel = document.getElementById('btn-cancel-edit-channel');
if (btnCancelEditChannel) {
  btnCancelEditChannel.addEventListener('click', () => {
    resetChannelForm();
    renderConfiguredChannels();
  });
}

// Add / Update channel button handler
const btnAddChannel = document.getElementById('btn-add-channel');
if (btnAddChannel) {
  btnAddChannel.addEventListener('click', () => {
    const type = document.getElementById('select-channel-type').value;
    let url = '';

    if (type === 'telegram') {
      const token = document.getElementById('ch-tg-token').value.trim();
      const chatId = document.getElementById('ch-tg-chatid').value.trim();
      if (!token || !chatId) {
        showToast('请填写 Telegram Bot Token 和 Chat ID', 'error');
        return;
      }
      url = `telegram://${token}@telegram?channels=${chatId}`;
      document.getElementById('ch-tg-token').value = '';
      document.getElementById('ch-tg-chatid').value = '';
    } else if (type === 'bark') {
      const key = document.getElementById('ch-bark-key').value.trim();
      let host = document.getElementById('ch-bark-host').value.trim() || 'api.day.app';
      host = host.replace(/^https?:\/\//, '').replace(/\/+$/, '');
      if (!key) {
        showToast('请填写 Bark Device Key', 'error');
        return;
      }
      url = `bark://${key}@${host}/`;
      document.getElementById('ch-bark-key').value = '';
    } else if (type === 'discord') {
      const raw = document.getElementById('ch-discord-url').value.trim();
      if (!raw) {
        showToast('请填写 Discord Webhook 地址', 'error');
        return;
      }
      const match = raw.match(/webhooks\/(\d+)\/([a-zA-Z0-9_-]+)/);
      if (match) {
        url = `discord://${match[2]}@${match[1]}`;
      } else if (raw.startsWith('discord://')) {
        url = raw;
      } else {
        showToast('Discord Webhook 格式不正确，需包含 webhooks/{id}/{token}', 'error');
        return;
      }
      document.getElementById('ch-discord-url').value = '';
    } else if (type === 'slack') {
      const raw = document.getElementById('ch-slack-url').value.trim();
      if (!raw) {
        showToast('请填写 Slack Webhook 地址', 'error');
        return;
      }
      const match = raw.match(/services\/([a-zA-Z0-9]+)\/([a-zA-Z0-9]+)\/([a-zA-Z0-9]+)/);
      if (match) {
        url = `slack://${match[1]}/${match[2]}/${match[3]}`;
      } else if (raw.startsWith('slack://')) {
        url = raw;
      } else {
        showToast('Slack Webhook 格式不正确，需包含 services/{a}/{b}/{c}', 'error');
        return;
      }
      document.getElementById('ch-slack-url').value = '';
    } else if (type === 'smtp') {
      const host = document.getElementById('ch-smtp-host').value.trim();
      const port = document.getElementById('ch-smtp-port').value.trim() || '587';
      const user = document.getElementById('ch-smtp-user').value.trim();
      const pass = document.getElementById('ch-smtp-pass').value.trim();
      const from = document.getElementById('ch-smtp-from').value.trim();
      const to = document.getElementById('ch-smtp-to').value.trim();
      const subject = document.getElementById('ch-smtp-subject').value.trim();
      if (!host || !to) {
        showToast('请至少填写 SMTP 服务器与收件人邮箱', 'error');
        return;
      }
      const encUser = encodeURIComponent(user);
      const encPass = encodeURIComponent(pass);
      const encFrom = encodeURIComponent(from);
      const encTo = encodeURIComponent(to);
      const qParts = [];
      if (from) qParts.push(`from=${encFrom}`);
      if (to) qParts.push(`to=${encTo}`);
      if (subject) qParts.push(`subject=${encodeURIComponent(subject)}`);
      const qStr = qParts.length > 0 ? `?${qParts.join('&')}` : '';

      if (user) {
        url = `smtp://${encUser}:${encPass}@${host}:${port}/${qStr}`;
      } else {
        url = `smtp://${host}:${port}/${qStr}`;
      }
      document.getElementById('ch-smtp-pass').value = '';
    } else if (type === 'ntfy') {
      const topic = document.getElementById('ch-ntfy-topic').value.trim();
      let host = document.getElementById('ch-ntfy-host').value.trim() || 'ntfy.sh';
      host = host.replace(/^https?:\/\//, '').replace(/\/+$/, '');
      if (!topic) {
        showToast('请填写 Ntfy 订阅 Topic', 'error');
        return;
      }
      url = `ntfy://${host}/${topic}`;
      document.getElementById('ch-ntfy-topic').value = '';
    } else if (type === 'gotify') {
      let host = document.getElementById('ch-gotify-host').value.trim();
      const token = document.getElementById('ch-gotify-token').value.trim();
      const useTLS = document.getElementById('ch-gotify-tls') ? document.getElementById('ch-gotify-tls').checked : true;
      host = host.replace(/^https?:\/\//, '').replace(/\/+$/, '');
      if (!host || !token) {
        showToast('请填写 Gotify 服务器地址和 App Token', 'error');
        return;
      }
      const scheme = useTLS ? 'gotifys' : 'gotify';
      url = `${scheme}://${host}/${token}`;
      document.getElementById('ch-gotify-token').value = '';
    } else if (type === 'webhook') {
      const raw = document.getElementById('ch-webhook-url').value.trim();
      if (!raw) {
        showToast('请填写 Webhook 地址', 'error');
        return;
      }
      url = raw.startsWith('generic+') ? raw : `generic+${raw}`;
      document.getElementById('ch-webhook-url').value = '';
    } else if (type === 'custom') {
      const raw = document.getElementById('ch-custom-url').value.trim();
      if (!raw) {
        showToast('请填写 Shoutrrr URL', 'error');
        return;
      }
      url = raw;
      document.getElementById('ch-custom-url').value = '';
    }

    if (url) {
      if (!state.editingChannels) {
        state.editingChannels = [];
      }
      if (state.editingChannelIndex >= 0 && state.editingChannelIndex < state.editingChannels.length) {
        state.editingChannels[state.editingChannelIndex] = url;
        showToast('通知渠道配置修改已保存', 'success');
        resetChannelForm();
      } else {
        state.editingChannels.push(url);
        showToast('已添加通知渠道配置', 'success');
      }
      renderConfiguredChannels();
    }
  });
}

// Settings Modal Open
elements.btnSettingsModal.addEventListener('click', () => {
  if (!state.settings) return;

  resetChannelForm();
  document.getElementById('cfg-interval').value = state.settings.interval;
  document.getElementById('cfg-thresholds').value = state.settings.alert_thresholds || '30,15,7,3';
  document.getElementById('cfg-timeout').value = state.settings.timeout;
  
  state.editingChannels = [...(state.settings.shoutrrr_urls || [])];
  renderConfiguredChannels();

  document.getElementById('cfg-apprise-api').value = state.settings.apprise_api_url;
  document.getElementById('cfg-apprise-urls').value = (state.settings.apprise_urls || []).join('\n');

  if (document.getElementById('cfg-icp')) {
    document.getElementById('cfg-icp').value = state.settings.icp || '';
  }
  if (document.getElementById('cfg-mps')) {
    document.getElementById('cfg-mps').value = state.settings.mps || '';
  }
  if (document.getElementById('cfg-default-theme')) {
    document.getElementById('cfg-default-theme').value = localStorage.getItem('argus_theme') || state.settings.default_theme || 'auto';
  }

  // 回填通知发送策略
  const notifMode = state.settings.notification_mode || 'realtime';
  if (elements.settingNotificationMode) {
    elements.settingNotificationMode.value = notifMode;
  }
  if (elements.settingNotificationBatchInterval) {
    elements.settingNotificationBatchInterval.value = state.settings.notification_batch_interval || '1h';
  }
  if (elements.batchIntervalGroup) {
    elements.batchIntervalGroup.classList.toggle('hidden', notifMode !== 'batch');
  }
  if (elements.batchActionsBar) {
    elements.batchActionsBar.classList.toggle('hidden', notifMode !== 'batch');
  }
  updatePendingBatchBadge(state.settings.pending_aggregated || 0);

  renderAppriseStatus();
  renderSecuritySettings();
  loadDNSData();

  const activeTab = document.querySelector('.settings-tab.active');
  updateSettingsFooter(activeTab ? activeTab.dataset.tab : 'tab-general');

  openModal('modal-settings');
});

// Settings Form Submit
elements.settingsForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const interval = document.getElementById('cfg-interval').value.trim();
  const alert_thresholds = document.getElementById('cfg-thresholds').value.trim() || '30,15,7,3';
  const timeout = document.getElementById('cfg-timeout').value.trim();
  const shoutrrrRaw = state.editingChannels || [];
  const apprise_enabled = elements.appriseEnabledCheck.checked && state.settings.apprise_available;
  const apprise_api_url = document.getElementById('cfg-apprise-api').value.trim();
  const appriseRaw = document.getElementById('cfg-apprise-urls').value.split('\n').map(s => s.trim()).filter(Boolean);

  const turnstile_enabled = document.getElementById('cfg-turnstile-enabled').checked;
  const turnstile_site_key = document.getElementById('cfg-turnstile-sitekey').value.trim();
  const turnstile_secret_key = document.getElementById('cfg-turnstile-secret').value.trim();

  const icp = document.getElementById('cfg-icp') ? document.getElementById('cfg-icp').value.trim() : '';
  const mps = document.getElementById('cfg-mps') ? document.getElementById('cfg-mps').value.trim() : '';
  const default_theme = document.getElementById('cfg-default-theme') ? document.getElementById('cfg-default-theme').value : 'auto';

  const notification_mode = elements.settingNotificationMode ? elements.settingNotificationMode.value : 'realtime';
  const notification_batch_interval = elements.settingNotificationBatchInterval ? elements.settingNotificationBatchInterval.value : '1h';

  const payload = {
    interval,
    threshold_days: 15,
    alert_thresholds,
    timeout,
    notification_mode,
    notification_batch_interval,
    shoutrrr_urls: shoutrrrRaw,
    apprise_enabled,
    apprise_api_url,
    apprise_urls: appriseRaw,
    turnstile_enabled,
    turnstile_site_key,
    turnstile_secret_key,
    icp,
    mps,
    default_theme,
  };

  try {
    await api('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
    showToast('系统与安全设置已更新', 'success');
    closeModal('modal-settings');
    await loadSettings();
  } catch (err) {
    // Handled in api()
  }
});

// Send Test Notification
elements.btnTestNotification.addEventListener('click', async () => {
  elements.btnTestNotification.disabled = true;
  try {
    const res = await api('/api/test-notification', { method: 'POST' });
    showToast(res.message || '测试告警通知已成功发送', 'success');
  } catch (err) {
    // Handled in api()
  } finally {
    elements.btnTestNotification.disabled = false;
  }
});

// Base64URL helpers for WebAuthn
function bufferDecode(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Utility formatting functions
function formatDate(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  return d.toISOString().split('T')[0];
}

function formatTimeAgo(isoStr) {
  if (!isoStr) return '';
  const diff = (Date.now() - new Date(isoStr).getTime()) / 1000;
  if (diff < 60) return '刚刚';
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  return `${Math.floor(diff / 86400)} 天前`;
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Global Instant Tooltip (Hover-triggered)
function initGlobalTooltip() {
  const tooltipEl = document.getElementById('global-tooltip');
  const tooltipText = document.getElementById('global-tooltip-text');
  if (!tooltipEl || !tooltipText) return;

  let currentTarget = null;

  document.addEventListener('mouseover', (e) => {
    const target = e.target.closest('[data-tooltip]');
    if (!target) return;

    const tip = target.getAttribute('data-tooltip');
    if (!tip) return;

    currentTarget = target;
    tooltipText.textContent = tip;
    tooltipEl.classList.remove('arrow-top', 'arrow-bottom');

    const rect = target.getBoundingClientRect();
    tooltipEl.style.display = 'block';
    const tipWidth = tooltipEl.offsetWidth;
    const tipHeight = tooltipEl.offsetHeight;

    let left = rect.left + rect.width / 2 - tipWidth / 2;
    if (left < 10) left = 10;
    if (left + tipWidth > window.innerWidth - 10) left = window.innerWidth - tipWidth - 10;

    let top = rect.top - tipHeight - 8;
    if (top < 10) {
      top = rect.bottom + 8;
      tooltipEl.classList.add('arrow-top');
    } else {
      tooltipEl.classList.add('arrow-bottom');
    }

    tooltipEl.style.left = `${Math.round(left)}px`;
    tooltipEl.style.top = `${Math.round(top)}px`;
    tooltipEl.classList.add('is-visible');
    tooltipEl.setAttribute('aria-hidden', 'false');
  });

  document.addEventListener('mouseout', (e) => {
    if (!currentTarget) return;
    const target = e.target.closest('[data-tooltip]');
    if (target === currentTarget) {
      tooltipEl.classList.remove('is-visible');
      tooltipEl.setAttribute('aria-hidden', 'true');
      currentTarget = null;
    }
  });

  window.addEventListener('scroll', () => {
    if (currentTarget) {
      tooltipEl.classList.remove('is-visible');
      tooltipEl.setAttribute('aria-hidden', 'true');
      currentTarget = null;
    }
  }, { passive: true });
}

// -------------------------------------------------------------
// DNS Providers & Dynamic API Sync Client Modules
// -------------------------------------------------------------

async function loadDNSData() {
  try {
    const [metaList, savedList, syncList] = await Promise.all([
      api('/api/dns/providers/meta').catch(() => []),
      api('/api/dns/providers').catch(() => []),
      api('/api/dns/sync-configs').catch(() => []),
    ]);

    state.dnsProvidersMeta = metaList || [];
    state.savedDNSProviders = savedList || [];
    state.dnsSyncConfigs = syncList || [];

    renderDNSProvidersDropdown();
    renderSavedDNSProvidersList();
    renderDNSSyncConfigsList();
  } catch (err) {
    console.error('Failed to load DNS data', err);
  }
}

function renderDNSProvidersDropdown() {
  if (!elements.dnsOptgroupSaved || !elements.dnsProviderSelect) return;

  // 1. Saved accounts
  elements.dnsOptgroupSaved.innerHTML = '';
  if (state.savedDNSProviders.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.disabled = true;
    opt.textContent = '(暂无已保存账号，请使用下方直接输入或先添加凭据)';
    elements.dnsOptgroupSaved.appendChild(opt);
  } else {
    state.savedDNSProviders.forEach(p => {
      const opt = document.createElement('option');
      opt.value = `saved_${p.id}`;
      opt.textContent = `${p.name} · ${p.provider_type} (${p.auth_key_mask})`;
      elements.dnsOptgroupSaved.appendChild(opt);
    });
  }
}

function renderSavedDNSProvidersList() {
  if (!elements.dnsProvidersList) return;

  if (state.savedDNSProviders.length === 0) {
    elements.dnsProvidersList.innerHTML = `
      <div class="text-muted text-xs p-3 text-center border-dashed rounded">
        暂无已保存的 DNS API 凭据，点击右上角 “+ 新增凭据” 添加。
      </div>`;
    return;
  }

  elements.dnsProvidersList.innerHTML = state.savedDNSProviders.map(p => `
    <div class="dns-card-item">
      <div class="dns-card-info">
        <div class="dns-card-title">
          <span>${escapeHtml(p.name)}</span>
          <span class="badge badge-blue">${escapeHtml(p.provider_type)}</span>
        </div>
        <div class="dns-card-sub">
          密钥: <code>${escapeHtml(p.auth_key_mask)}</code> · 更新时间: ${formatDate(p.updated_at)}
        </div>
      </div>
      <div class="flex items-center gap-1">
        <button type="button" class="btn btn-secondary btn-sm" onclick="handleEditDNSProvider(${p.id})">编辑</button>
        <button type="button" class="btn btn-secondary btn-sm text-rose" onclick="handleDeleteDNSProvider(${p.id})">删除</button>
      </div>
    </div>
  `).join('');
}

function renderDNSSyncConfigsList() {
  if (!elements.dnsSyncConfigsList) return;

  if (state.dnsSyncConfigs.length === 0) {
    elements.dnsSyncConfigsList.innerHTML = `
      <div class="text-muted text-xs p-3 text-center border-dashed rounded">
        暂无域名同步规则与黑名单。在“域名 API”中勾选自动同步即可在此管理。
      </div>`;
    return;
  }

  elements.dnsSyncConfigsList.innerHTML = state.dnsSyncConfigs.map(c => {
    const blacklistTags = (c.blacklist && c.blacklist.length > 0)
      ? c.blacklist.map(b => `<span class="dns-tag-item dns-tag-blocked" title="黑名单规则">${escapeHtml(b)}</span>`).join('')
      : '<span class="text-muted text-xs">无黑名单限制</span>';

    const lastSyncStr = c.last_sync_at ? `上次同步: ${formatDate(c.last_sync_at)}` : '尚未执行同步';
    const statusClass = (c.last_sync_status && c.last_sync_status.includes('失败')) ? 'text-rose' : 'text-emerald';

    return `
      <div class="dns-card-item">
        <div class="dns-card-info" style="flex: 1; min-width: 0;">
          <div class="dns-card-title">
            <span class="text-main font-bold font-mono">${escapeHtml(c.domain)}</span>
            <span class="badge badge-purple">${escapeHtml(c.provider_name || c.provider_type || 'DNS 凭据')}</span>
            ${c.auto_sync ? '<span class="badge badge-emerald">自动巡检同步</span>' : '<span class="badge badge-gray">手动同步</span>'}
          </div>
          <div class="dns-card-sub flex flex-col gap-1 mt-1">
            <div class="flex items-center gap-1 flex-wrap">
              <span class="text-xs text-muted">过滤黑名单:</span>
              ${blacklistTags}
            </div>
            <div class="text-xs ${statusClass}">
              ${lastSyncStr}${c.last_sync_status ? ' · ' + escapeHtml(c.last_sync_status) : ''}
            </div>
          </div>
        </div>
        <div class="flex items-center gap-1 ml-3">
          <button type="button" class="btn btn-secondary btn-sm" onclick="handleEditDomainAPI('${escapeHtml(c.domain)}')">编辑</button>
          <button type="button" class="btn btn-secondary btn-sm" onclick="handleTriggerSyncRule(${c.id})">立即同步</button>
          <button type="button" class="btn btn-secondary btn-sm text-rose" onclick="handleDeleteSyncRule(${c.id})">删除</button>
        </div>
      </div>
    `;
  }).join('');
}

// 凭据下拉与自定义输入联动
if (elements.dnsProviderSelect) {
  elements.dnsProviderSelect.addEventListener('change', (e) => {
    const val = e.target.value;
    if (val.startsWith('saved_')) {
      if (elements.dnsCustomCredsBox) elements.dnsCustomCredsBox.classList.add('hidden');
      const pId = parseInt(val.replace('saved_', ''), 10);
      const saved = state.savedDNSProviders.find(p => p.id === pId);
      renderPermissionHint('dns-sync-perm-hint', saved ? saved.provider_type : '');
    } else if (val.startsWith('custom_')) {
      if (elements.dnsCustomCredsBox) elements.dnsCustomCredsBox.classList.remove('hidden');
      const pType = val.replace('custom_', '');
      renderPermissionHint('dns-sync-perm-hint', pType);
      const meta = state.dnsProvidersMeta.find(m => m.type === pType);

      const lblKey = document.getElementById('lbl-dns-key');
      const lblSecret = document.getElementById('lbl-dns-secret');
      const grpSecret = document.getElementById('group-dns-secret');
      const lblZone = document.getElementById('lbl-dns-zone');

      if (meta) {
        if (lblKey) lblKey.innerHTML = `${meta.key_label || 'API Token / Key'} <span class="text-rose">*</span>`;
        if (elements.dnsAuthKeyInput) elements.dnsAuthKeyInput.placeholder = `请输入 ${meta.key_label || 'API Key'}`;

        if (meta.auth_fields && meta.auth_fields.includes('auth_secret')) {
          if (grpSecret) grpSecret.classList.remove('hidden');
          if (lblSecret) lblSecret.textContent = meta.secret_label || 'SecretKey';
          if (elements.dnsAuthSecretInput) elements.dnsAuthSecretInput.placeholder = `请输入 ${meta.secret_label || 'SecretKey'}`;
        } else {
          if (grpSecret) grpSecret.classList.add('hidden');
        }

        if (lblZone) lblZone.textContent = meta.zone_label || 'Zone ID / Site ID (可选)';
      }
    } else {
      if (elements.dnsCustomCredsBox) elements.dnsCustomCredsBox.classList.add('hidden');
      renderPermissionHint('dns-sync-perm-hint', '');
    }
  });
}

// 当输入主域名时，若已有已保存的该域名黑名单规则，自动回填
if (elements.dnsSyncDomain) {
  elements.dnsSyncDomain.addEventListener('blur', (e) => {
    const dom = e.target.value.trim().toLowerCase();
    if (!dom) return;

    const existing = state.dnsSyncConfigs.find(c => c.domain.toLowerCase() === dom);
    if (existing) {
      if (elements.dnsBlacklistText && !elements.dnsBlacklistText.value.trim()) {
        elements.dnsBlacklistText.value = existing.blacklist.join('\n');
        showToast(`已自动载入 ${dom} 原有黑名单规则`, 'info');
      }
      if (elements.dnsDefaultPortInput) elements.dnsDefaultPortInput.value = existing.default_port || '443';
      if (elements.dnsAutoTaskCheck) elements.dnsAutoTaskCheck.checked = existing.auto_sync;
    }
  });
}

// 提取当前表单的 DNS 参数与黑名单
function extractDNSSyncFormPayload() {
  const providerVal = elements.dnsProviderSelect.value;
  if (!providerVal) {
    throw new Error('请先选择 DNS 服务商或已保存的凭据账号');
  }

  const domain = elements.dnsSyncDomain.value.trim().toLowerCase();
  if (!domain) {
    throw new Error('请输入目标主域名 (如 example.com)');
  }

  let providerID = 0;
  let providerType = '';
  let authKey = '';
  let authSecret = '';
  let zoneID = '';

  if (providerVal.startsWith('saved_')) {
    providerID = parseInt(providerVal.replace('saved_', ''), 10);
  } else if (providerVal.startsWith('custom_')) {
    providerType = providerVal.replace('custom_', '');
    authKey = elements.dnsAuthKeyInput.value.trim();
    authSecret = elements.dnsAuthSecretInput ? elements.dnsAuthSecretInput.value.trim() : '';
    zoneID = elements.dnsZoneIdInput ? elements.dnsZoneIdInput.value.trim() : '';

    if (!authKey) {
      throw new Error('请输入 API Key / Token 访问凭据');
    }

    if (providerType === 'cloudflare' && /^[0-9a-fA-F]{37}$/.test(authKey) && !authSecret) {
      throw new Error('检测到您输入的是 Cloudflare Global API Key (37位十六进制)，请务必填写绑定的账号邮箱 (Secret)！若使用 API Token 则无需邮箱。');
    }
  }

  // 提取黑名单规则
  const blacklistLines = (elements.dnsBlacklistText.value || '').split('\n');
  const blacklist = [];
  const seenBlack = {};
  blacklistLines.forEach(l => {
    const r = l.trim().toLowerCase();
    if (r && !r.startsWith('#') && !seenBlack[r]) {
      seenBlack[r] = true;
      blacklist.push(r);
    }
  });

  return {
    provider_id: providerID,
    provider_type: providerType,
    auth_key: authKey,
    auth_secret: authSecret,
    zone_id: zoneID,
    domain: domain,
    blacklist: blacklist,
  };
}

// 拉取解析记录并预览 (含黑名单实时对比)
if (elements.btnDnsPreview) {
  elements.btnDnsPreview.addEventListener('click', async () => {
    let payload;
    try {
      payload = extractDNSSyncFormPayload();
    } catch (err) {
      showToast(err.message, 'warning');
      return;
    }

    const btn = elements.btnDnsPreview;
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-sm"></span> 正在通过 API 拉取...`;

    try {
      const res = await api('/api/dns/fetch-records', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      // 渲染预览结果卡片
      elements.dnsPreviewContainer.classList.remove('hidden');
      elements.previewTotalCount.textContent = res.total_records;
      elements.previewAllowedCount.textContent = res.allowed_count;
      elements.previewBlockedCount.textContent = res.blocked_count;

      // 允许导入的域名
      elements.dnsPreviewAllowedList.innerHTML = (res.allowed_domains && res.allowed_domains.length > 0)
        ? res.allowed_domains.map(d => `<span class="dns-tag-item dns-tag-allowed" title="将被加入监控">${escapeHtml(d)}</span>`).join('')
        : '<span class="text-muted text-xs">没有匹配到待导入的有效子域名</span>';

      // 命中黑名单被过滤的域名
      if (res.blocked_domains && res.blocked_domains.length > 0) {
        elements.dnsPreviewBlockedBox.classList.remove('hidden');
        elements.dnsPreviewBlockedList.innerHTML = res.blocked_domains.map(d =>
          `<span class="dns-tag-item dns-tag-blocked" title="命中黑名单规则，已自动过滤排除">${escapeHtml(d)} (已排除)</span>`
        ).join('');
      } else {
        elements.dnsPreviewBlockedBox.classList.add('hidden');
        elements.dnsPreviewBlockedList.innerHTML = '';
      }

      showToast(`拉取成功：共获取 ${res.total_records} 条记录，${res.allowed_count} 个待导入，${res.blocked_count} 个命中黑名单跳过`, 'info');
    } catch (err) {
      showToast(err.message || '拉取解析记录失败', 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = origHtml;
    }
  });
}

// 直接同步导入监控
if (elements.btnDnsExecuteSync) {
  elements.btnDnsExecuteSync.addEventListener('click', async () => {
    let payload;
    try {
      payload = extractDNSSyncFormPayload();
    } catch (err) {
      showToast(err.message, 'warning');
      return;
    }

    const rdapMode = elements.dnsRdapModeSelect ? elements.dnsRdapModeSelect.value : 'auto';
    const defaultPort = elements.dnsDefaultPortInput ? (elements.dnsDefaultPortInput.value.trim() || '443') : '443';
    let checkSSL = true;
    let checkDomain = false;

    if (rdapMode === 'domain-only') {
      checkSSL = false;
      checkDomain = true;
    } else if (rdapMode === 'all') {
      checkSSL = true;
      checkDomain = true;
    } else if (rdapMode === 'none') {
      checkSSL = true;
      checkDomain = false;
    } else {
      // auto
      checkSSL = true;
      checkDomain = isApexDomain(payload.domain);
    }

    const btn = elements.btnDnsExecuteSync;
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-sm"></span> 正在同步导入...`;

    try {
      // 1. 如果勾选了“同时保存此凭据”，先保存到后端
      if (elements.dnsSaveCredsCheck && elements.dnsSaveCredsCheck.checked && payload.provider_type && payload.auth_key) {
        const meta = state.dnsProvidersMeta.find(m => m.type === payload.provider_type);
        const credRes = await api('/api/dns/providers', {
          method: 'POST',
          body: JSON.stringify({
            name: `${meta ? meta.name : payload.provider_type} (${payload.domain})`,
            provider_type: payload.provider_type,
            auth_key: payload.auth_key,
            auth_secret: payload.auth_secret,
          }),
        });
        if (credRes && credRes.id) {
          payload.provider_id = credRes.id;
        }
      }

      // 2. 将域名 API 配置持久化保存到 dns_sync_configs，以便首页识别和后续管理
      const isAuto = elements.dnsAutoTaskCheck && elements.dnsAutoTaskCheck.checked;
      await api('/api/dns/sync-configs', {
        method: 'POST',
        body: JSON.stringify({
          provider_id: payload.provider_id,
          domain: payload.domain,
          zone_id: payload.zone_id,
          blacklist: payload.blacklist,
          auto_sync: isAuto,
          check_domain: checkDomain,
          default_port: defaultPort,
        }),
      }).catch(e => console.warn('Save sync config failed', e));

      // 3. 执行同步导入
      const syncRes = await api('/api/dns/sync-now', {
        method: 'POST',
        body: JSON.stringify({
          fetch_params: payload,
          check_ssl: checkSSL,
          check_domain: checkDomain,
          default_port: defaultPort,
        }),
      });

      showToast(syncRes.message || `同步完成：成功新增 ${syncRes.added} 个监控目标`, 'success');

      // 重新加载数据
      await Promise.all([loadDomains(), loadDNSData()]);

      // 延时关闭弹窗
      setTimeout(() => {
        closeModal('modal-batch-backup');
      }, 1200);
    } catch (err) {
      showToast(err.message || '执行同步导入失败', 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = origHtml;
    }
  });
}

// 官方各平台所需 API 权限说明字典
const DNS_PROVIDER_PERMISSIONS = {
  cloudflare: {
    title: 'Cloudflare 权限要求与凭证说明',
    detail: '1. 推荐使用 API Token，需具备权限：Zone.DNS:Read (只读) 与 Zone.Zone:Read (区域读取，用于匹配 ZoneID)。若未配置 Zone 读取权限，可手动在规则中填写 Zone ID。\n2. 若使用 Global API Key (37 位十六进制)，必须同时在 Secret/邮箱 处填写绑定的 Cloudflare 账号邮箱。',
  },
  aliyun: {
    title: '阿里云 DNS (Alidns) 权限要求',
    detail: 'RAM 访问控制策略需包含系统策略 AliyunDNSReadOnlyAccess (包含 DescribeDomainRecords、DescribeDomains 等只读 Action)。',
  },
  aliyun_esa: {
    title: '阿里云 ESA 权限要求',
    detail: 'RAM 访问控制策略需包含系统策略 AliyunESAReadOnlyAccess (包含 ListSites、ListRecords 等只读 Action)。',
  },
  tencent: {
    title: '腾讯云 DNSPod 权限要求',
    detail: 'CAM 访问策略需包含系统策略 QcloudDNSPodReadOnlyAccess (或包含 dnspod:DescribeRecordList、dnspod:DescribeDomainList 等只读权限)。',
  },
  dnspod_token: {
    title: 'DNSPod 经典 Token 权限要求',
    detail: '需在 DNSPod 控制台创建并开启对应主域名的只读读取权限 Token (ID,Token)。',
  },
  edgeone: {
    title: '腾讯云 EdgeOne 权限要求',
    detail: 'CAM 策略需包含系统策略 QcloudTEOReadOnlyAccess (EdgeOne 边缘安全加速平台只读权限)。',
  },
  volcengine: {
    title: '火山引擎 DNS 权限要求',
    detail: '火山引擎 IAM 访问控制策略需包含系统策略 DNSReadOnlyAccess (包含 dns:ListZones 与 dns:ListRecords 只读权限)。',
  },
  huawei: {
    title: '华为云 DNS 权限要求',
    detail: 'IAM 用户权限需包含系统策略 DNS ReadOnlyAccess (云解析服务只读权限)。',
  },
  aws_route53: {
    title: 'AWS Route 53 权限要求',
    detail: 'AWS IAM Policy 需包含 route53:ListHostedZones, route53:ListHostedZonesByName 与 route53:ListResourceRecordSets 只读权限。',
  },
  godaddy: {
    title: 'GoDaddy 权限要求',
    detail: '需申请 Production 生产环境的 API Key & Secret，具备 Domains 读取权限。',
  },
  digitalocean: {
    title: 'DigitalOcean 权限要求',
    detail: 'Personal Access Token 需勾选 Read (只读) 作用域权限。',
  },
  vultr: {
    title: 'Vultr 权限要求',
    detail: '需在 Vultr 账户后台生成 API Key，并将本监控系统的出口 IP 加入白名单。',
  },
};

// 显式权限提示渲染函数
function renderPermissionHint(containerId, providerType) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const cleanType = (providerType || '').replace('custom_', '');
  const meta = (state.dnsProvidersMeta || []).find(m => m.type === cleanType);
  const info = DNS_PROVIDER_PERMISSIONS[cleanType] || (meta && meta.required_permissions ? {
    title: `${meta.name || cleanType} 权限要求`,
    detail: meta.required_permissions,
  } : null);

  if (!info) {
    container.classList.add('hidden');
    container.innerHTML = '';
    return;
  }

  const detailText = (meta && meta.required_permissions) ? meta.required_permissions : info.detail;
  container.classList.remove('hidden');
  container.innerHTML = `
    <svg class="dns-perm-alert-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
    </svg>
    <div class="dns-perm-alert-content">
      <span class="dns-perm-alert-title">${escapeHtml(info.title)}</span>
      <div class="dns-perm-alert-text">${escapeHtml(detailText)}</div>
    </div>
  `;
}

// 凭据账号管理：打开添加凭据弹窗
if (elements.btnAddDNSProvider) {
  elements.btnAddDNSProvider.addEventListener('click', () => {
    document.getElementById('modal-dns-provider-title').textContent = '添加凭据';
    if (elements.dnsProviderForm) elements.dnsProviderForm.reset();
    document.getElementById('form-dns-provider-id').value = '';
    if (formProviderTypeSelect) {
      formProviderTypeSelect.dispatchEvent(new Event('change'));
    }
    openModal('modal-dns-provider-edit');
  });
}

// 凭据表单服务商切换联动
const formProviderTypeSelect = document.getElementById('form-dns-provider-type');
if (formProviderTypeSelect) {
  formProviderTypeSelect.addEventListener('change', (e) => {
    const pType = e.target.value;
    renderPermissionHint('form-dns-perm-hint', pType);
    const meta = state.dnsProvidersMeta.find(m => m.type === pType);
    const lblKey = document.getElementById('form-lbl-dns-key');
    const lblSecret = document.getElementById('form-lbl-dns-secret');
    const grpSecret = document.getElementById('form-group-dns-secret');

    if (meta) {
      if (lblKey) lblKey.innerHTML = `${meta.key_label || 'API Token / Key'} <span class="text-rose">*</span>`;
      if (document.getElementById('form-dns-auth-key')) {
        document.getElementById('form-dns-auth-key').placeholder = `请输入 ${meta.key_label || 'API Key'}`;
      }
      if (meta.auth_fields && meta.auth_fields.includes('auth_secret')) {
        if (grpSecret) grpSecret.classList.remove('hidden');
        if (lblSecret) lblSecret.textContent = meta.secret_label || 'SecretKey';
        const secInput = document.getElementById('form-dns-auth-secret');
        if (secInput) {
          secInput.placeholder = pType === 'cloudflare'
            ? '若使用 Global Key 必填 Cloudflare 登录邮箱，Token 请留空'
            : `请输入 ${meta.secret_label || 'SecretKey'}`;
        }
      } else {
        if (grpSecret) grpSecret.classList.add('hidden');
      }
    }
  });
}

// 保存凭据表单提交
if (elements.dnsProviderForm) {
  elements.dnsProviderForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const idVal = document.getElementById('form-dns-provider-id').value;
    const name = document.getElementById('form-dns-provider-name').value.trim();
    const pType = document.getElementById('form-dns-provider-type').value;
    const authKey = document.getElementById('form-dns-auth-key').value.trim();
    const authSecret = document.getElementById('form-dns-auth-secret').value.trim();

    if (pType === 'cloudflare' && /^[0-9a-fA-F]{37}$/.test(authKey) && !authSecret) {
      showToast('检测到您输入的是 Cloudflare Global API Key (37位十六进制)，请务必填写绑定的账号邮箱！若使用 API Token 则无需邮箱。', 'warning');
      const secretInput = document.getElementById('form-dns-auth-secret');
      if (secretInput) {
        secretInput.focus();
      }
      return;
    }

    try {
      await api('/api/dns/providers', {
        method: 'POST',
        body: JSON.stringify({
          id: idVal ? parseInt(idVal, 10) : 0,
          name: name,
          provider_type: pType,
          auth_key: authKey,
          auth_secret: authSecret,
        }),
      });

      showToast('DNS 接口凭据保存成功', 'success');
      closeModal('modal-dns-provider-edit');
      await loadDNSData();
    } catch (err) {
      showToast(err.message || '保存失败', 'error');
    }
  });
}

// 编辑凭据
window.handleEditDNSProvider = function(id) {
  const p = state.savedDNSProviders.find(item => item.id === id);
  if (!p) return;

  document.getElementById('modal-dns-provider-title').textContent = '编辑凭据';
  document.getElementById('form-dns-provider-id').value = p.id;
  document.getElementById('form-dns-provider-name').value = p.name;
  if (formProviderTypeSelect) {
    formProviderTypeSelect.value = p.provider_type;
    formProviderTypeSelect.dispatchEvent(new Event('change'));
  }
  document.getElementById('form-dns-auth-key').value = p.auth_key_mask;
  document.getElementById('form-dns-auth-secret').value = p.has_secret ? '********' : '';

  openModal('modal-dns-provider-edit');
};

// 删除凭据
window.handleDeleteDNSProvider = function(id) {
  confirmModal('确定要删除此 DNS 访问凭据吗？关联的同步规则将无法拉取数据。', async () => {
    try {
      await api(`/api/dns/providers/${id}`, { method: 'DELETE' });
      showToast('凭据删除成功', 'success');
      await loadDNSData();
    } catch (err) {
      showToast(err.message || '删除失败', 'error');
    }
  });
};

// 触发某个主域名的同步规则立即执行
window.handleTriggerSyncRule = async function(configId) {
  const c = state.dnsSyncConfigs.find(item => item.id === configId);
  showToast(`正在从 DNS API 同步 ${c ? c.domain : ''}...`, 'info');
  try {
    const res = await api('/api/dns/sync-now', {
      method: 'POST',
      body: JSON.stringify({ sync_config_id: configId }),
    });

    showToast(res.message || '同步完成', 'success');
    await Promise.all([loadDomains(), loadDNSData()]);
  } catch (err) {
    showToast(err.message || '同步失败', 'error');
  }
};

// 删除同步规则
window.handleDeleteSyncRule = function(configId) {
  confirmModal('确定删除此主域名的动态同步规则与黑名单吗？已导入的监控目标不会被删除。', async () => {
    try {
      await api(`/api/dns/sync-configs/${configId}`, { method: 'DELETE' });
      showToast('规则删除成功', 'success');
      await loadDNSData();
      renderDashboard();
    } catch (err) {
      showToast(err.message || '删除失败', 'error');
    }
  });
};

// 首页主域名快速编辑 API 与凭据模态框
window.handleEditDomainAPI = function(apex) {
  if (!apex) return;
  const normApex = apex.toLowerCase();
  const conf = (state.dnsSyncConfigs || []).find(c => (c.domain || '').toLowerCase() === normApex);

  // 1. 目标主域名
  const domInput = document.getElementById('edit-api-domain');
  if (domInput) domInput.value = normApex;

  // 2. 规则 ID
  const idInput = document.getElementById('edit-api-config-id');
  if (idInput) idInput.value = conf ? conf.id : '';

  // 3. 填充凭据下拉框
  const selectProv = document.getElementById('edit-api-provider-select');
  if (selectProv) {
    selectProv.innerHTML = '';
    if (!state.savedDNSProviders || state.savedDNSProviders.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '-- 暂无可用的凭据账号，请先添加凭据 --';
      selectProv.appendChild(opt);
    } else {
      state.savedDNSProviders.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = `${p.name} · ${p.provider_type} (${p.auth_key_mask})`;
        if (conf && conf.provider_id === p.id) {
          opt.selected = true;
        }
        selectProv.appendChild(opt);
      });
      if (conf && conf.provider_id) {
        selectProv.value = conf.provider_id;
      }
    }
  }

  // 4. Zone ID
  const zoneInput = document.getElementById('edit-api-zone-id');
  if (zoneInput) zoneInput.value = conf ? (conf.zone_id || '') : '';

  // 5. 默认探测端口
  const portInput = document.getElementById('edit-api-default-port');
  if (portInput) portInput.value = conf ? (conf.default_port || '443') : '443';

  // 6. 黑名单过滤规则
  const blacklistInput = document.getElementById('edit-api-blacklist');
  if (blacklistInput) {
    blacklistInput.value = (conf && conf.blacklist && conf.blacklist.length > 0) ? conf.blacklist.join('\n') : '';
  }

  // 7. 自动同步与 RDAP 检查
  const autoSyncCheck = document.getElementById('edit-api-auto-sync');
  if (autoSyncCheck) autoSyncCheck.checked = conf ? !!conf.auto_sync : true;

  const checkDomCheck = document.getElementById('edit-api-check-domain');
  if (checkDomCheck) checkDomCheck.checked = conf ? (conf.check_domain !== false) : true;

  const disabledCheck = document.getElementById('edit-api-disabled');
  if (disabledCheck) disabledCheck.checked = Boolean(conf && conf.is_disabled);

  // 动态修改标题
  const titleEl = document.getElementById('modal-domain-api-title');
  if (titleEl) {
    titleEl.textContent = conf ? '编辑主域名 API 与凭据' : '配置域名 DNS API 模式';
  }

  // 8. 快捷修改当前选中的凭据密钥或添加凭据
  const btnQuickEdit = document.getElementById('btn-quick-edit-credential');
  if (btnQuickEdit) {
    btnQuickEdit.textContent = (!state.savedDNSProviders || state.savedDNSProviders.length === 0) ? '+ 新建凭据' : '修改当前密钥';
    btnQuickEdit.onclick = () => {
      const pId = parseInt(selectProv ? selectProv.value : '0', 10);
      if (pId > 0) {
        handleEditDNSProvider(pId);
      } else {
        if (elements.btnAddDNSProvider) {
          elements.btnAddDNSProvider.click();
        }
      }
    };
  }

  // 9. 解绑 API 按钮
  const btnDelete = document.getElementById('btn-delete-domain-api');
  if (btnDelete) {
    if (conf && conf.id) {
      btnDelete.style.display = '';
      btnDelete.onclick = () => {
        confirmModal(`确定要解绑 ${normApex} 的 API 同步规则吗？解绑后将恢复为纯手动监控目标。`, async () => {
          try {
            await api(`/api/dns/sync-configs/${conf.id}`, { method: 'DELETE' });
            showToast('已解绑域名 API 同步规则', 'success');
            closeModal('modal-domain-api-edit');
            await loadDNSData();
            renderDashboard();
          } catch (err) {
            showToast(err.message || '解绑失败', 'error');
          }
        });
      };
    } else {
      btnDelete.style.display = 'none';
    }
  }

  openModal('modal-domain-api-edit');
};

// 保存主域名 API 与凭据配置的核心函数
async function saveDomainAPIConfig(triggerSyncNow = false) {
  const domain = (document.getElementById('edit-api-domain').value || '').trim();
  const providerId = parseInt(document.getElementById('edit-api-provider-select').value || '0', 10);
  const configId = parseInt(document.getElementById('edit-api-config-id').value || '0', 10);
  const zoneId = (document.getElementById('edit-api-zone-id').value || '').trim();
  const defaultPort = (document.getElementById('edit-api-default-port').value || '443').trim();
  const rawBlacklist = document.getElementById('edit-api-blacklist').value || '';
  const autoSync = document.getElementById('edit-api-auto-sync').checked;
  const checkDomain = document.getElementById('edit-api-check-domain').checked;
  const isDisabled = document.getElementById('edit-api-disabled') ? document.getElementById('edit-api-disabled').checked : false;

  if (!domain) {
    showToast('主域名不能为空', 'error');
    return;
  }
  if (!providerId) {
    showToast('请选择关联的 DNS 账号凭据', 'error');
    return;
  }

  const blacklist = rawBlacklist
    .split(/[\r\n,]+/)
    .map(s => s.trim().toLowerCase())
    .filter(s => s.length > 0);

  try {
    const res = await api('/api/dns/sync-configs', {
      method: 'POST',
      body: JSON.stringify({
        id: configId,
        provider_id: providerId,
        domain: domain,
        zone_id: zoneId,
        blacklist: blacklist,
        auto_sync: autoSync,
        check_domain: checkDomain,
        is_disabled: isDisabled,
        default_port: defaultPort,
      }),
    });

    const savedId = (res && res.id) ? res.id : configId;
    showToast('域名 API 配置已保存', 'success');

    if (triggerSyncNow) {
      showToast(`正在从 DNS API 动态同步 ${domain} 的子域名...`, 'info');
      try {
        const syncRes = await api('/api/dns/sync-now', {
          method: 'POST',
          body: JSON.stringify({ sync_config_id: savedId }),
        });
        showToast(syncRes.message || '动态同步完成', 'success');
      } catch (syncErr) {
        showToast(`保存成功，但同步出错: ${syncErr.message || syncErr}`, 'warning');
      }
    }

    closeModal('modal-domain-api-edit');
    await Promise.all([loadDomains(), loadDNSData()]);
    renderDashboard();
  } catch (err) {
    showToast(err.message || '保存配置失败', 'error');
  }
}

// 绑定模态框提交事件
const formDomainApiEdit = document.getElementById('form-domain-api-edit');
if (formDomainApiEdit) {
  formDomainApiEdit.addEventListener('submit', async (e) => {
    e.preventDefault();
    await saveDomainAPIConfig(false);
  });
}

const btnSaveAndSyncDomainApi = document.getElementById('btn-save-and-sync-domain-api');
if (btnSaveAndSyncDomainApi) {
  btnSaveAndSyncDomainApi.addEventListener('click', async () => {
    await saveDomainAPIConfig(true);
  });
}

// Header Brand Logo 点击返回首页
function initBrandLogo() {
  const brandLogo = document.getElementById('brand-logo');
  if (brandLogo) {
    brandLogo.addEventListener('click', (e) => {
      // 允许 Ctrl / Cmd / Shift / Alt 点击以在新标签页打开 /
      if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
      e.preventDefault();

      // 重置视图状态回到首页主域名列表
      state.viewMode = 'groups';
      state.currentApex = null;
      state.activeFilter = 'all';
      state.searchQuery = '';
      state.currentPage = 1;
      if (elements.searchInput) {
        elements.searchInput.value = '';
      }
      if (elements.filterTabs) {
        elements.filterTabs.forEach(t => {
          if (t.dataset.filter === 'all') {
            t.classList.add('active');
          } else {
            t.classList.remove('active');
          }
        });
      }
      if (window.history && window.history.pushState) {
        window.history.pushState({}, '', '/');
      }
      renderDashboard();
    });
  }
}

// ========================================================
// 外观主题控制器 (跟随系统 / 浅色模式 / 暗色模式)
// ========================================================
const THEME_STORAGE_KEY = 'argus_theme';

function initThemeManager() {
  const btnThemeToggle = document.getElementById('btn-theme-toggle');

  function getSavedTheme() {
    return localStorage.getItem(THEME_STORAGE_KEY) || 'auto';
  }

  function renderThemeToggleUI(theme) {
    if (!btnThemeToggle) return;

    const iconSun = `
      <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="5"></circle>
        <line x1="12" y1="1" x2="12" y2="3"></line>
        <line x1="12" y1="21" x2="12" y2="23"></line>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
        <line x1="1" y1="12" x2="3" y2="12"></line>
        <line x1="21" y1="12" x2="23" y2="12"></line>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
      </svg>
    `;

    const iconMoon = `
      <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
      </svg>
    `;

    const iconAuto = `
      <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
        <line x1="8" y1="21" x2="16" y2="21"></line>
        <line x1="12" y1="17" x2="12" y2="21"></line>
      </svg>
    `;

    if (theme === 'light') {
      btnThemeToggle.innerHTML = iconSun;
      btnThemeToggle.title = '当前外观: 浅色模式 (点击切换为暗色模式)';
    } else if (theme === 'dark') {
      btnThemeToggle.innerHTML = iconMoon;
      btnThemeToggle.title = '当前外观: 暗色模式 (点击切换为跟随系统)';
    } else {
      btnThemeToggle.innerHTML = iconAuto;
      btnThemeToggle.title = '当前外观: 跟随系统 (点击切换为浅色模式)';
    }
  }

  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else if (theme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    renderThemeToggleUI(theme);
  }

  // 初始化应用当前主题
  const initialTheme = getSavedTheme();
  applyTheme(initialTheme);
  window.applyTheme = applyTheme;

  const cfgDefaultTheme = document.getElementById('cfg-default-theme');
  if (cfgDefaultTheme) {
    cfgDefaultTheme.value = initialTheme;
    cfgDefaultTheme.addEventListener('change', (e) => {
      const selected = e.target.value;
      localStorage.setItem(THEME_STORAGE_KEY, selected);
      applyTheme(selected);
      const label = selected === 'light' ? '浅色模式' : (selected === 'dark' ? '暗色模式' : '跟随系统');
      showToast(`外观已切换为: ${label}`, 'info');
    });
  }

  // 绑定点击切换事件 (auto -> light -> dark -> auto)
  if (btnThemeToggle) {
    btnThemeToggle.addEventListener('click', () => {
      const cur = getSavedTheme();
      let next = 'auto';
      if (cur === 'auto') {
        next = 'light';
      } else if (cur === 'light') {
        next = 'dark';
      } else {
        next = 'auto';
      }
      localStorage.setItem(THEME_STORAGE_KEY, next);
      applyTheme(next);
      if (cfgDefaultTheme) {
        cfgDefaultTheme.value = next;
      }

      const label = next === 'light' ? '浅色模式' : (next === 'dark' ? '暗色模式' : '跟随系统');
      showToast(`外观已切换为: ${label}`, 'info');
    });
  }

  // 监听操作系统配色变化
  const colorSchemeQuery = window.matchMedia('(prefers-color-scheme: dark)');
  if (colorSchemeQuery.addEventListener) {
    colorSchemeQuery.addEventListener('change', () => {
      if (getSavedTheme() === 'auto') {
        applyTheme('auto');
      }
    });
  }
}

// ==========================================
// 系统消息中心与通知策略交互
// ==========================================
function updateUnreadBadges(unreadCount, pendingAggregated) {
  if (unreadCount !== undefined) {
    state.unreadNotificationsCount = unreadCount || 0;
  }
  if (pendingAggregated !== undefined) {
    state.pendingAggregatedCount = pendingAggregated;
  }

  const bellBadge = elements.notificationUnreadBadge;
  if (bellBadge) {
    if (state.unreadNotificationsCount > 0) {
      bellBadge.textContent = state.unreadNotificationsCount > 99 ? '99+' : state.unreadNotificationsCount;
      bellBadge.classList.remove('hidden');
    } else {
      bellBadge.classList.add('hidden');
    }
  }

  const centerPill = elements.centerUnreadPill;
  if (centerPill) {
    if (state.unreadNotificationsCount > 0) {
      centerPill.textContent = `${state.unreadNotificationsCount} 条未读`;
      centerPill.classList.remove('hidden');
    } else {
      centerPill.classList.add('hidden');
    }
  }

  updatePendingBatchBadge(state.pendingAggregatedCount);
}

function updatePendingBatchBadge(count) {
  const pill = elements.batchPendingPill;
  const cnt = elements.batchPendingCount;
  if (pill && cnt) {
    cnt.textContent = count || 0;
    pill.classList.toggle('hidden', !count || count <= 0);
  }
}

async function fetchUnreadNotificationCount() {
  if (!state.isAuthenticated) return;
  try {
    const data = await api('/api/notifications/unread-count');
    updateUnreadBadges(data.unread_count, data.pending_aggregated);
  } catch (e) {
    // 静默忽略
  }
}

async function loadNotifications() {
  const listContainer = elements.notificationListContainer;
  const emptyState = elements.notificationEmptyState;
  if (!listContainer) return;

  const unreadOnly = elements.chkUnreadOnly?.checked ? 'true' : 'false';

  listContainer.innerHTML = '<div class="text-xs text-muted" style="text-align: center; padding: 2rem;">加载通知记录中...</div>';
  if (emptyState) emptyState.classList.add('hidden');

  try {
    const data = await api(`/api/notifications?limit=100&offset=0&unread_only=${unreadOnly}`);
    state.notifications = data.list || [];
    updateUnreadBadges(data.unread_count);
    renderNotificationList();
  } catch (err) {
    listContainer.innerHTML = `<div class="text-xs text-rose" style="text-align: center; padding: 2rem;">加载失败: ${escapeHtml(err.message || '未知错误')}</div>`;
  }
}

function renderNotificationList() {
  const listContainer = elements.notificationListContainer;
  const emptyState = elements.notificationEmptyState;
  if (!listContainer) return;

  if (!state.notifications || state.notifications.length === 0) {
    listContainer.innerHTML = '';
    if (emptyState) emptyState.classList.remove('hidden');
    return;
  }

  if (emptyState) emptyState.classList.add('hidden');

  listContainer.innerHTML = state.notifications.map((item) => {
    const isUnread = !item.is_read;
    const level = item.level || 'info';
    let levelBadge = '';
    if (level === 'critical') {
      levelBadge = '<span class="badge badge-rose">紧急告警</span>';
    } else if (level === 'warning') {
      levelBadge = '<span class="badge badge-amber">警告</span>';
    } else if (level === 'notice') {
      levelBadge = '<span class="badge badge-yellow">注意</span>';
    } else {
      levelBadge = '<span class="badge badge-blue">信息</span>';
    }

    const typeBadge = item.type === 'test' 
      ? '<span class="badge badge-subtle">测试消息</span>' 
      : (item.type === 'summary' ? '<span class="badge badge-purple">合并汇总</span>' : '');

    const targetBadge = item.target 
      ? `<span class="notification-target-badge">${escapeHtml(item.target)}</span>` 
      : '';

    const formattedTime = item.created_at ? new Date(item.created_at).toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    }) : '';

    return `
      <div class="notification-item level-${level} ${isUnread ? 'unread' : ''}" data-id="${item.id}">
        <div class="notification-item-header">
          <div class="notification-title-wrap">
            ${isUnread ? '<span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:var(--color-blue);"></span>' : ''}
            <span class="notification-item-title">${escapeHtml(item.title)}</span>
            ${levelBadge}
            ${typeBadge}
            ${targetBadge}
          </div>
          <span class="notification-time">${escapeHtml(formattedTime)}</span>
        </div>
        <div class="notification-item-body">${escapeHtml(item.content)}</div>
        <div class="notification-item-actions">
          ${isUnread ? `<button type="button" class="btn btn-ghost btn-sm btn-mark-one-read" data-id="${item.id}" style="font-size:0.75rem;">标为已读</button>` : ''}
          <button type="button" class="btn btn-ghost btn-sm text-rose btn-delete-notification" data-id="${item.id}" style="font-size:0.75rem;">删除</button>
        </div>
      </div>
    `;
  }).join('');

  // 标为已读
  listContainer.querySelectorAll('.btn-mark-one-read').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.id, 10);
      try {
        await api('/api/notifications/read', {
          method: 'POST',
          body: JSON.stringify({ id }),
        });
        await fetchUnreadNotificationCount();
        await loadNotifications();
      } catch (err) {
        // Handled in api()
      }
    });
  });

  // 删除单条
  listContainer.querySelectorAll('.btn-delete-notification').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.id, 10);
      try {
        await api(`/api/notifications/${id}`, { method: 'DELETE' });
        showToast('已删除该条通知', 'success');
        await fetchUnreadNotificationCount();
        await loadNotifications();
      } catch (err) {
        // Handled in api()
      }
    });
  });
}

function initNotificationCenter() {
  // 顶栏铃铛点击打开消息中心模态框
  if (elements.btnNotificationsCenter) {
    elements.btnNotificationsCenter.addEventListener('click', () => {
      openModal('modal-notifications-center');
      loadNotifications();
    });
  }

  // 刷新按钮
  if (elements.btnRefreshNotifications) {
    elements.btnRefreshNotifications.addEventListener('click', () => {
      loadNotifications();
    });
  }

  // 仅看未读过滤
  if (elements.chkUnreadOnly) {
    elements.chkUnreadOnly.addEventListener('change', () => {
      loadNotifications();
    });
  }

  // 全部已读
  if (elements.btnMarkAllRead) {
    elements.btnMarkAllRead.addEventListener('click', async () => {
      try {
        await api('/api/notifications/read', {
          method: 'POST',
          body: JSON.stringify({ all: true }),
        });
        showToast('已全部标记为已读', 'success');
        await fetchUnreadNotificationCount();
        await loadNotifications();
      } catch (err) {
        // Handled in api()
      }
    });
  }

  // 清空历史
  if (elements.btnClearNotifications) {
    elements.btnClearNotifications.addEventListener('click', async () => {
      const confirmed = await showConfirm('确定要清空系统内所有历史通知记录吗？此操作不可撤销。', {
        title: '清空历史通知',
        okText: '确认清空',
        cancelText: '取消',
        isDanger: true,
      });
      if (!confirmed) return;

      try {
        await api('/api/notifications', { method: 'DELETE' });
        showToast('历史通知记录已全部清空', 'success');
        await fetchUnreadNotificationCount();
        await loadNotifications();
      } catch (err) {
        // Handled in api()
      }
    });
  }

  // 设置面板通知策略联动
  if (elements.settingNotificationMode) {
    elements.settingNotificationMode.addEventListener('change', (e) => {
      const isBatch = e.target.value === 'batch';
      if (elements.batchIntervalGroup) elements.batchIntervalGroup.classList.toggle('hidden', !isBatch);
      if (elements.batchActionsBar) elements.batchActionsBar.classList.toggle('hidden', !isBatch);
    });
  }

  // 立即发送待合并通知
  if (elements.btnFlushBatch) {
    elements.btnFlushBatch.addEventListener('click', async () => {
      elements.btnFlushBatch.disabled = true;
      try {
        const res = await api('/api/notifications/flush-batch', { method: 'POST' });
        showToast(res.message || '已成功合并推送通知', 'success');
        await fetchUnreadNotificationCount();
        if (elements.modalNotificationsCenter && !elements.modalNotificationsCenter.classList.contains('hidden')) {
          await loadNotifications();
        }
      } catch (err) {
        // Handled in api()
      } finally {
        elements.btnFlushBatch.disabled = false;
      }
    });
  }

  // 定时轻量轮询未读数与待发合并数 (每 30 秒)
  setInterval(() => {
    if (state.isAuthenticated) {
      fetchUnreadNotificationCount();
    }
  }, 30000);
}

// Start Application
initGlobalTooltip();
initBrandLogo();
initThemeManager();
initNotificationCenter();
checkAuth();
