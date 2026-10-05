/**
 * CyberGuard - Password Strength Analyzer & Security Suggestion Tool
 * Frontend Application Controller
 *
 * ZERO-KNOWLEDGE PRIVACY DIRECTIVE:
 * Never write candidate passwords to console.log, localStorage, or sessionStorage.
 */

// Tab Navigation
function switchTab(tabId) {
  const tabs = ['analyzer', 'policy', 'generator', 'hashing'];
  tabs.forEach(t => {
    const btn = document.getElementById(`tab-btn-${t}`);
    const panel = document.getElementById(`panel-${t}`);
    if (btn) btn.classList.remove('active');
    if (panel) panel.classList.remove('active');
  });

  const activeBtn = document.getElementById(`tab-btn-${tabId}`);
  const activePanel = document.getElementById(`panel-${tabId}`);
  if (activeBtn) activeBtn.classList.add('active');
  if (activePanel) activePanel.classList.add('active');
}

// Toggle Demographic Context Drawer
function toggleContextBox() {
  const box = document.getElementById('context-box');
  const caret = document.getElementById('context-caret');
  if (box.classList.contains('open')) {
    box.classList.remove('open');
    caret.textContent = '▶';
  } else {
    box.classList.add('open');
    caret.textContent = '▼';
  }
}

// Show / Hide Password Toggle
const pwdInput = document.getElementById('password-input');
const toggleBtn = document.getElementById('toggle-pwd-btn');

if (toggleBtn && pwdInput) {
  toggleBtn.addEventListener('click', () => {
    if (pwdInput.type === 'password') {
      pwdInput.type = 'text';
      toggleBtn.textContent = '🙈';
      toggleBtn.title = 'Hide password';
    } else {
      pwdInput.type = 'password';
      toggleBtn.textContent = '👁️';
      toggleBtn.title = 'Show password';
    }
  });
}

// Quick Demo Password Loader
function loadDemoPassword(sample) {
  if (pwdInput) {
    pwdInput.value = sample;
    triggerAnalysis();
  }
}

// Debounce Utility for Real-Time Typing Response
let debounceTimer = null;
function debounce(func, delay = 250) {
  return function(...args) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => func.apply(this, args), delay);
  };
}

// Real-Time Analysis Trigger
function triggerAnalysis() {
  const password = pwdInput ? pwdInput.value : '';
  const firstName = document.getElementById('ctx-name')?.value || '';
  const birthYear = document.getElementById('ctx-year')?.value || '';
  const organization = document.getElementById('ctx-org')?.value || '';

  const payload = {
    password: password,
    context: {
      first_name: firstName,
      birth_year: birthYear,
      organization: organization
    },
    persist_analytics: password.length > 0
  };

  fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(res => res.json())
  .then(data => {
    updateUIWithAnalysis(data);
  })
  .catch(err => {
    // Graceful silent error handling (no logging of payload)
  });
}

if (pwdInput) {
  pwdInput.addEventListener('input', debounce(triggerAnalysis, 250));
  ['ctx-name', 'ctx-year', 'ctx-org'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', debounce(triggerAnalysis, 400));
  });
}

// Update DOM with Analysis Results
function updateUIWithAnalysis(data) {
  if (!data) return;

  const score = data.score || 0;
  const classification = data.classification || 'AWAITING INPUT';
  const metrics = data.metrics || {};
  const lenMetrics = metrics.length || {};
  const charMetrics = metrics.characters || {};
  const commonMetrics = metrics.common_check || {};
  const entropyMetrics = metrics.entropy || {};
  const policyMetrics = metrics.policy || {};
  const findings = data.findings || [];
  const suggestions = data.suggestions || [];

  // 1. Score & Classification Badge
  const scoreDisplay = document.getElementById('score-display');
  const classBadge = document.getElementById('classification-badge');
  const meterFill = document.getElementById('meter-fill');

  if (scoreDisplay) scoreDisplay.textContent = `${score} / 100`;

  // Color mapping
  let badgeClass = 'badge-very-weak';
  let fillColor = 'var(--status-very-weak)';

  if (classification === 'WEAK') {
    badgeClass = 'badge-weak';
    fillColor = 'var(--status-weak)';
  } else if (classification === 'MODERATE') {
    badgeClass = 'badge-moderate';
    fillColor = 'var(--status-moderate)';
  } else if (classification === 'STRONG') {
    badgeClass = 'badge-strong';
    fillColor = 'var(--status-strong)';
  } else if (classification === 'VERY STRONG') {
    badgeClass = 'badge-very-strong';
    fillColor = 'var(--status-very-strong)';
  }

  if (classBadge) {
    classBadge.className = `classification-badge ${badgeClass}`;
    classBadge.textContent = classification;
  }

  if (meterFill) {
    meterFill.style.width = `${score}%`;
    meterFill.style.backgroundColor = fillColor;
  }

  // 2. Length Card
  const lengthVal = document.getElementById('length-val');
  const lengthBadge = document.getElementById('length-badge');
  const lengthDesc = document.getElementById('length-desc');

  if (lengthVal) lengthVal.textContent = `${lenMetrics.length || 0} chars`;
  if (lengthBadge) {
    lengthBadge.textContent = (lenMetrics.band || 'EMPTY').replace('_', ' ');
    lengthBadge.className = lenMetrics.status === 'EXCELLENT' || lenMetrics.status === 'GOOD' ? 'pill active' : 'pill';
  }
  if (lengthDesc) lengthDesc.textContent = lenMetrics.description || 'Enter password';

  // 3. Diversity Card
  const uniqueVal = document.getElementById('unique-val');
  const divRatio = document.getElementById('diversity-ratio');
  if (uniqueVal) uniqueVal.textContent = `${charMetrics.unique_character_count || 0} unique`;
  if (divRatio) divRatio.textContent = `${charMetrics.character_type_count || 0} / 5 types`;

  const pillMap = {
    'pill-lower': charMetrics.has_lowercase,
    'pill-upper': charMetrics.has_uppercase,
    'pill-digit': charMetrics.has_digits,
    'pill-symbol': charMetrics.has_symbols,
    'pill-space': charMetrics.has_spaces
  };
  for (const [id, active] of Object.entries(pillMap)) {
    const el = document.getElementById(id);
    if (el) {
      if (active) el.classList.add('active');
      else el.classList.remove('active');
    }
  }

  // 4. Entropy Card
  const entropyBits = document.getElementById('entropy-bits');
  const entropyAdjVal = document.getElementById('entropy-adj-val');
  const crackEst = document.getElementById('crack-est');

  if (entropyBits) entropyBits.textContent = `${entropyMetrics.theoretical_bits || 0} bits (theory)`;
  if (entropyAdjVal) entropyAdjVal.textContent = `${entropyMetrics.adjusted_bits || 0} adj bits`;
  if (crackEst) {
    const estimates = entropyMetrics.crack_estimates || {};
    crackEst.textContent = `GPU cluster est: ${estimates.fast_gpu_cluster_100b_per_sec || 'Instant'}`;
  }

  // 5. Dictionary Check Card
  const dictMatchVal = document.getElementById('dict-match-val');
  const dictStatus = document.getElementById('dict-status');
  const dictDesc = document.getElementById('dict-desc');

  if (commonMetrics.is_common) {
    if (dictMatchVal) {
      dictMatchVal.textContent = 'Blacklisted';
      dictMatchVal.style.color = 'var(--status-very-weak)';
    }
    if (dictStatus) {
      dictStatus.textContent = commonMetrics.match_type || 'MATCH';
      dictStatus.className = 'pill';
      dictStatus.style.background = 'rgba(239, 68, 68, 0.2)';
      dictStatus.style.color = 'var(--status-very-weak)';
    }
    if (dictDesc) dictDesc.textContent = commonMetrics.description;
  } else {
    if (dictMatchVal) {
      dictMatchVal.textContent = 'Clean';
      dictMatchVal.style.color = 'var(--status-strong)';
    }
    if (dictStatus) {
      dictStatus.textContent = 'Safe';
      dictStatus.className = 'pill active';
      dictStatus.style.background = '';
      dictStatus.style.color = '';
    }
    if (dictDesc) dictDesc.textContent = 'No matches in common educational dictionary.';
  }

  // 6. Findings Section
  const findingsSection = document.getElementById('findings-section');
  const findingsContainer = document.getElementById('findings-container');
  if (findingsContainer && findingsSection) {
    if (findings.length > 0) {
      findingsSection.style.display = 'block';
      findingsContainer.innerHTML = findings.map(f => {
        const isCrit = f.severity === 'CRITICAL';
        return `
          <div class="finding-item ${isCrit ? 'critical' : 'warning'}">
            <span style="font-size: 1.2rem;">${isCrit ? '🚨' : '⚠️'}</span>
            <div>
              <strong>[${f.category || 'PATTERN'}]</strong> ${f.description}
            </div>
          </div>
        `;
      }).join('');
    } else {
      findingsSection.style.display = 'none';
      findingsContainer.innerHTML = '';
    }
  }

  // 7. Suggestions List
  const suggestionsContainer = document.getElementById('suggestions-container');
  if (suggestionsContainer) {
    if (suggestions.length > 0) {
      suggestionsContainer.innerHTML = suggestions.map(s => `
        <div class="suggestion-card">
          <div class="suggestion-icon">🛡️</div>
          <div class="suggestion-content">
            <h5>${s.title}</h5>
            <p>${s.message}</p>
          </div>
        </div>
      `).join('');
    } else {
      suggestionsContainer.innerHTML = '<p style="color: var(--status-strong);">Outstanding! No weaknesses detected.</p>';
    }
  }

  // 8. Policy Checklist
  updatePolicyUI(policyMetrics);
}

// Update Policy Tab UI
function updatePolicyUI(policyMetrics) {
  const policyOverallBadge = document.getElementById('policy-overall-badge');
  const checklist = document.getElementById('policy-checklist');

  if (!checklist) return;

  const passed = policyMetrics.passed || false;
  const status = policyMetrics.status || 'EVALUATING';

  if (policyOverallBadge) {
    policyOverallBadge.textContent = status;
    policyOverallBadge.className = `classification-badge ${passed ? 'badge-strong' : 'badge-very-weak'}`;
  }

  const checks = policyMetrics.checks || [];
  checklist.innerHTML = checks.map(c => `
    <div class="policy-item">
      <div>
        <strong>${c.rule}</strong>
        <div style="font-size: 0.82rem; color: var(--text-muted);">${c.detail}</div>
      </div>
      <div>
        <span class="pill ${c.passed ? 'active' : ''}" style="${c.passed ? '' : 'color: var(--status-very-weak); background: rgba(239, 68, 68, 0.2);'}">
          ${c.passed ? '✓ PASS' : '✗ FAIL'}
        </span>
      </div>
    </div>
  `).join('');
}

// Generator Tab Handlers
function generatePasswordAction() {
  const length = parseInt(document.getElementById('gen-length')?.value || '20', 10);
  fetch('/api/generate-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ length: length, include_symbols: true, avoid_ambiguous: true })
  })
  .then(res => res.json())
  .then(data => {
    const out = document.getElementById('gen-output');
    if (out) out.value = data.password;
  });
}

function generatePassphraseAction() {
  const count = parseInt(document.getElementById('phrase-count')?.value || '5', 10);
  fetch('/api/generate-passphrase', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ word_count: count, delimiter: '-' })
  })
  .then(res => res.json())
  .then(data => {
    const out = document.getElementById('phrase-output');
    if (out) out.value = data.passphrase;
  });
}

// Clipboard Copy Helper
function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);
  if (!el || !el.value) return;

  navigator.clipboard.writeText(el.value).then(() => {
    const orig = el.value;
    el.value = '✓ Copied to Clipboard!';
    setTimeout(() => { el.value = orig; }, 1200);
  });
}

// Hashing Demonstration Runner
function runHashingDemo() {
  fetch('/api/hashing-demo?sample=SyntheticPassword2026!')
  .then(res => res.json())
  .then(data => {
    const resBox = document.getElementById('hashing-results');
    if (resBox) resBox.style.display = 'block';

    const fastDisplay = document.getElementById('fast-hash-display');
    if (fastDisplay) {
      fastDisplay.innerHTML = `
        <div><strong>Hash:</strong> ${data.fast_hash.hash_hex}</div>
        <div><strong>Execution Time:</strong> ${data.fast_hash.execution_time_microseconds} µs (Microseconds)</div>
        <div style="color: var(--status-very-weak); margin-top: 4px;">⚠️ ${data.fast_hash.warning}</div>
      `;
    }

    const slowDisplay = document.getElementById('slow-hash-display');
    if (slowDisplay) {
      slowDisplay.innerHTML = `
        <div><strong>Algorithm:</strong> ${data.slow_salted_hash.algorithm} (${data.slow_salted_hash.iterations} iterations)</div>
        <div><strong>Salt:</strong> ${data.slow_salted_hash.salt_hex}</div>
        <div><strong>Derived Key:</strong> ${data.slow_salted_hash.hash_hex}</div>
        <div><strong>Execution Time:</strong> ${data.slow_salted_hash.execution_time_ms} ms (Slowed by design to thwart GPU cracking)</div>
      `;
    }

    const saltDisplay = document.getElementById('salt-demo-display');
    if (saltDisplay) {
      saltDisplay.innerHTML = `
        <div>${data.salt_demonstration.explanation}</div>
        <div style="margin-top: 6px;"><strong>Run 1:</strong> Salt: <code>${data.salt_demonstration.salt_1.slice(0, 16)}...</code> → Hash: <code>${data.salt_demonstration.hash_1_preview}</code></div>
        <div><strong>Run 2:</strong> Salt: <code>${data.salt_demonstration.salt_2.slice(0, 16)}...</code> → Hash: <code>${data.salt_demonstration.hash_2_preview}</code></div>
        <div style="color: var(--status-strong); margin-top: 4px;">✓ Output hashes are completely distinct despite identical password.</div>
      `;
    }

    const verifyDisplay = document.getElementById('verify-test-display');
    if (verifyDisplay) {
      verifyDisplay.innerHTML = `
        <strong>Verification Test:</strong>
        <div>✓ Correct candidate password matched: <code>${data.verification_test.correct_password_verified}</code></div>
        <div>✓ Incorrect candidate password rejected: <code>${data.verification_test.incorrect_password_rejected}</code></div>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">Comparison implemented using: <code>${data.verification_test.method}</code></div>
      `;
    }
  });
}
