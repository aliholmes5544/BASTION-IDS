/* ═══════════════════════════════════════════════════════════
   BASTION IDS — Core JavaScript
   Particles · Counters · Charts · Interactions
   ═══════════════════════════════════════════════════════════ */

'use strict';

// ── Page Loader (runs on every page) ─────────────────────
(function initPageLoader() {
  // Inject loader elements if not already in DOM
  if (!document.getElementById('page-loader')) {
    var prog = document.createElement('div');
    prog.id = 'page-progress';
    document.body.appendChild(prog);

    var ldr = document.createElement('div');
    ldr.id  = 'page-loader';
    ldr.innerHTML =
      '<div class="page-loader-ring"></div>' +
      '<div class="page-loader-text">' + ((window.BASTION_I18N && window.BASTION_I18N.loading) || 'LOADING') + '</div>';
    document.body.appendChild(ldr);
  }

  var loader   = document.getElementById('page-loader');
  var progress = document.getElementById('page-progress');
  var timer, startTime, hiding = false;

  function startLoader() {
    if (!loader || !progress || hiding) return;
    hiding   = false;
    startTime = Date.now();
    progress.classList.add('running');
    progress.style.transition = 'none';
    progress.style.width = '0%';

    loader.classList.add('visible');

    // Animate progress bar toward ~80%
    var pct = 0;
    clearInterval(timer);
    timer = setInterval(function() {
      var inc = pct < 30 ? 14 : pct < 60 ? 7 : pct < 78 ? 2 : 0.3;
      pct = Math.min(80, pct + inc);
      progress.style.transition = 'width 0.18s ease';
      progress.style.width = pct + '%';
      if (pct >= 80) clearInterval(timer);
    }, 150);
  }

  function finishLoader() {
    if (!loader || !progress) return;
    clearInterval(timer);
    // Ensure minimum visible time of 500ms
    var elapsed = Date.now() - (startTime || 0);
    var delay   = loader.classList.contains('visible') ? Math.max(0, 500 - elapsed) : 0;
    setTimeout(function() {
      hiding = true;
      progress.style.transition = 'width 0.2s ease';
      progress.style.width = '100%';
      setTimeout(function() {
        loader.classList.remove('visible');
        setTimeout(function() {
          progress.classList.remove('running');
          progress.style.transition = 'none';
          progress.style.width = '0%';
          hiding = false;
        }, 200);
      }, 200);
    }, delay);
  }

  // Intercept all same-origin link clicks
  document.addEventListener('click', function(e) {
    var link = e.target.closest('a[href]');
    if (!link) return;
    var href = link.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript') ||
        link.hasAttribute('download') || link.target === '_blank' ||
        e.ctrlKey || e.metaKey || e.shiftKey) return;
    try {
      var url = new URL(href, window.location.href);
      if (url.origin !== window.location.origin) return;
    } catch(ex) { return; }
    e.preventDefault();
    startLoader();
    setTimeout(function() { window.location.href = href; }, 80);
  });

  // Intercept all form submits (GET or POST)
  document.addEventListener('submit', function() {
    startLoader();
  });

  // Finish when new page is painted
  window.addEventListener('pageshow', function() {
    startTime = startTime || Date.now() - 9999; // ensure no artificial delay on hard load
    finishLoader();
  });

  // Also hide immediately if no loader was started (normal page load)
  if (!loader.classList.contains('visible')) {
    progress.classList.remove('running');
  }
})();

// ── Particles Canvas ─────────────────────────────────────
(function initParticles() {
  const canvas = document.getElementById('particles-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let W, H, particles = [], mouse = { x: -999, y: -999 };
  const PARTICLE_COUNT = 35;
  const CONNECTION_DIST = 120;
  const COLORS = ['rgba(0,212,255,', 'rgba(123,47,255,', 'rgba(0,255,148,'];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function createParticle() {
    const color = COLORS[Math.floor(Math.random() * COLORS.length)];
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r:  Math.random() * 2 + 0.5,
      color,
      opacity: Math.random() * 0.5 + 0.2,
    };
  }

  function init() {
    resize();
    particles = Array.from({ length: PARTICLE_COUNT }, createParticle);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECTION_DIST) {
          const alpha = (1 - dist / CONNECTION_DIST) * 0.15;
          ctx.beginPath();
          ctx.strokeStyle = `rgba(0,212,255,${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    // Mouse connections
    particles.forEach(p => {
      const dx = p.x - mouse.x, dy = p.y - mouse.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 180) {
        const alpha = (1 - dist / 180) * 0.4;
        ctx.beginPath();
        ctx.strokeStyle = `rgba(0,212,255,${alpha})`;
        ctx.lineWidth = 0.8;
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.stroke();
      }
    });

    // Particles
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `${p.color}${p.opacity})`;
      ctx.fill();
    });

    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', resize);
  window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });

  init();
  draw();
})();

// ── Live Clock — toggles time ↔ date every 30 s ──────────
(function liveClock() {
  const el = document.getElementById('live-clock');
  if (!el) return;
  var _ci18n = window.BASTION_I18N || {};
  const DAYS   = _ci18n.days   || ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const MONTHS = _ci18n.months || ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const start  = Date.now();
  function tick() {
    const now     = new Date();
    const elapsed = Math.floor((Date.now() - start) / 1000);
    const showDate = Math.floor(elapsed / 30) % 2 === 1;
    if (showDate) {
      el.textContent = DAYS[now.getDay()] + ' ' + now.getDate() + ' ' + MONTHS[now.getMonth()];
    } else {
      el.textContent = String(now.getHours()).padStart(2,'0') + ':'
                     + String(now.getMinutes()).padStart(2,'0') + ':'
                     + String(now.getSeconds()).padStart(2,'0');
    }
  }
  tick();
  setInterval(tick, 1000);
})();

// ── Counter Animation ────────────────────────────────────
function animateCounter(el, target, duration = 1500, suffix = '') {
  const start = performance.now();
  const isFloat = target % 1 !== 0;
  function step(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    const current = eased * target;
    el.textContent = (isFloat ? current.toFixed(1) : Math.round(current).toLocaleString()) + suffix;
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function initCounters() {
  document.querySelectorAll('[data-count]').forEach(el => {
    const target  = parseFloat(el.dataset.count);
    const suffix  = el.dataset.suffix || '';
    const duration= parseInt(el.dataset.duration) || 1500;
    animateCounter(el, target, duration, suffix);
  });
}

// ── Intersection Observer for animations ─────────────────
function initScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'none';
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('.anim-fade-up, .anim-slide-left').forEach(el => {
    observer.observe(el);
  });
}

// ── Flash Messages auto-dismiss ──────────────────────────
function initFlashMessages() {
  document.querySelectorAll('.flash-message').forEach(msg => {
    setTimeout(() => {
      msg.style.transition = 'all 0.4s ease';
      msg.style.opacity = '0';
      msg.style.transform = 'translateY(-10px)';
      setTimeout(() => msg.remove(), 400);
    }, 5000);
  });
}

// ── Upload Zone ──────────────────────────────────────────
function initUploadZone() {
  const zone  = document.getElementById('upload-zone');
  const input = document.getElementById('file-input');
  const info  = document.getElementById('file-info');
  const form  = document.getElementById('scan-form');
  const overlay = document.getElementById('scan-overlay');

  if (!zone) return;

  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('dragover');
  });

  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));

  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });

  input.addEventListener('change', () => {
    if (input.files[0]) handleFile(input.files[0]);
  });

  function handleFile(file) {
    const nameLower = file.name.toLowerCase();
    if (!nameLower.endsWith('.csv') && !nameLower.endsWith('.pcap') && !nameLower.endsWith('.pcapng')) {
      var i18n = window.BASTION_I18N || {};
      showError(i18n.onlyCSV || 'Only CSV files are accepted.');
      return;
    }
    const size = (file.size / 1024 / 1024).toFixed(2);
    if (info) {
      // Build preview with DOM APIs so file.name is never injected into innerHTML
      info.innerHTML =
        '<div class="file-preview">' +
          '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
            '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>' +
          '</svg>' +
          '<div>' +
            '<div class="file-preview-name" style="font-weight:600;color:var(--text-1)"></div>' +
            '<div style="font-size:11px;color:var(--text-3)">' + size + ' MB</div>' +
          '</div>' +
        '</div>';
      info.querySelector('.file-preview-name').textContent = file.name;
      info.style.display = 'block';
    }
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
  }

  if (form) {
    form.addEventListener('submit', e => {
      if (!input.files || !input.files[0]) {
        e.preventDefault();
        var i18n = window.BASTION_I18N || {};
        showError(i18n.selectCSV || 'Please select a CSV file first.');
        return;
      }
      if (overlay) overlay.classList.add('active');
      animateScanText();
    });
  }

  function animateScanText() {
    var _i18n = window.BASTION_I18N || {};
    const texts = [
      _i18n.scanPhase1 || 'INITIALIZING SCAN...',
      _i18n.scanPhase2 || 'LOADING MODELS...',
      _i18n.scanPhase3 || 'ANALYZING FLOWS...',
      _i18n.scanPhase4 || 'CLASSIFYING THREATS...'
    ];
    const el = document.getElementById('scan-status-text');
    if (!el) return;
    let i = 0;
    var scanTextTimer = setInterval(function() {
      el.textContent = texts[i % texts.length];
      i++;
    }, 1800);
    // Clean up when the page unloads (navigation away after form submit)
    window.addEventListener('pagehide', function() { clearInterval(scanTextTimer); }, { once: true });
  }
}

function showError(msg) {
  const container = document.getElementById('flash-container');
  if (!container) { alert(msg); return; }
  const div = document.createElement('div');
  div.className = 'alert alert-error flash-message anim-fade-up';
  div.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span class="error-msg-text"></span>';
  div.querySelector('.error-msg-text').textContent = msg;
  container.prepend(div);
  setTimeout(() => { div.style.opacity = '0'; setTimeout(() => div.remove(), 400); }, 4000);
}

// ── Table Search/Filter ──────────────────────────────────
function initTableFilter() {
  const searchInput = document.getElementById('table-search');
  if (!searchInput) return;
  const table = document.getElementById('flows-table');
  if (!table) return;
  const rows = table.querySelectorAll('tbody tr.expandable');

  searchInput.addEventListener('input', function() {
    const q = this.value.toLowerCase();
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      var show = text.includes(q);
      row.style.display = show ? '' : 'none';
      // Keep expand-row sibling in sync
      var next = row.nextElementSibling;
      if (next && next.classList.contains('expand-row')) {
        next.style.display = show ? '' : 'none';
        if (!show) next.classList.remove('open');
      }
    });
  });
}

// ── Filter Chips ─────────────────────────────────────────
function initFilterChips() {
  document.querySelectorAll('.filter-chip[data-filter]').forEach(chip => {
    chip.addEventListener('click', function() {
      document.querySelectorAll('.filter-chip[data-filter]').forEach(c => c.classList.remove('active'));
      this.classList.add('active');
      const filter = this.dataset.filter;
      const table  = document.getElementById('flows-table');
      if (!table) return;
      table.querySelectorAll('tbody tr.expandable').forEach(row => {
        var show;
        if (filter === 'all') { show = true; }
        else {
          const sev = row.dataset.severity || '';
          show = sev.toLowerCase() === filter.toLowerCase();
        }
        row.style.display = show ? '' : 'none';
        // Keep expand-row sibling in sync
        var next = row.nextElementSibling;
        if (next && next.classList.contains('expand-row')) {
          next.style.display = show ? '' : 'none';
          if (!show) next.classList.remove('open');
        }
      });
    });
  });
}

// ── Dashboard Charts ─────────────────────────────────────
function initDashboardCharts(chartData) {
  if (typeof Chart === 'undefined') return;

  Chart.defaults.color = '#8899bb';
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.borderColor = 'rgba(0,212,255,0.08)';

  const CHART_COLORS = {
    SAFE:     '#00ff94',
    MEDIUM:   '#ffb800',
    HIGH:     '#ff6b35',
    CRITICAL: '#ff3e5f',
    UNKNOWN:  '#8899bb',
  };

  const THREAT_PALETTE = [
    '#00d4ff','#7b2fff','#00ff94','#ff3e5f',
    '#ff6b35','#ffb800','#a78bfa','#34d399',
    '#f87171','#60a5fa','#fbbf24','#e879f9',
  ];

  // Severity Donut
  const sevCtx = document.getElementById('sev-chart');
  if (sevCtx && chartData.sev) {
    const labels = Object.keys(chartData.sev);
    const values = Object.values(chartData.sev);
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: labels.map(l => CHART_COLORS[l] || '#8899bb'),
          borderWidth: 2,
          borderColor: '#0d1528',
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true,
        cutout: '72%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 16, usePointStyle: true, pointStyleWidth: 10, font: { size: 11 } }
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.parsed.toLocaleString()} ${(window.BASTION_I18N && window.BASTION_I18N.flowsLabel) || 'flows'}`
            }
          }
        },
        animation: { animateRotate: true, duration: 1200 },
      }
    });
  }

  // Threat Type Bar
  const threatCtx = document.getElementById('threat-chart');
  if (threatCtx && chartData.threats) {
    const labels = Object.keys(chartData.threats);
    const values = Object.values(chartData.threats);
    new Chart(threatCtx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: (window.BASTION_I18N && window.BASTION_I18N.detectedFlows) || 'Detected Flows',
          data: values,
          backgroundColor: labels.map((_, i) => THREAT_PALETTE[i % THREAT_PALETTE.length] + '99'),
          borderColor:      labels.map((_, i) => THREAT_PALETTE[i % THREAT_PALETTE.length]),
          borderWidth: 1,
          borderRadius: 6,
          borderSkipped: false,
        }]
      },
      options: {
        responsive: true,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { color: 'rgba(0,212,255,0.06)' },
            ticks: { font: { size: 11 } }
          },
          y: {
            grid: { display: false },
            ticks: { font: { size: 11 } }
          }
        },
        animation: { duration: 1000 },
      }
    });
  }

  // Timeline Line
  const tlCtx = document.getElementById('timeline-chart');
  if (tlCtx && chartData.timeline) {
    const labels  = chartData.timeline.map(d => d.date);
    const threats = chartData.timeline.map(d => d.threats);
    const totals  = chartData.timeline.map(d => d.total);
    new Chart(tlCtx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: (window.BASTION_I18N && window.BASTION_I18N.threatsChart) || 'Threats',
            data: threats,
            borderColor: '#ff3e5f',
            backgroundColor: 'rgba(255,62,95,0.1)',
            fill: true,
            tension: 0.4,
            pointBackgroundColor: '#ff3e5f',
            pointRadius: 4,
            pointHoverRadius: 7,
          },
          {
            label: (window.BASTION_I18N && window.BASTION_I18N.totalFlowsChart) || 'Total Flows',
            data: totals,
            borderColor: '#00d4ff',
            backgroundColor: 'rgba(0,212,255,0.07)',
            fill: true,
            tension: 0.4,
            pointBackgroundColor: '#00d4ff',
            pointRadius: 4,
            pointHoverRadius: 7,
          }
        ]
      },
      options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        plugins: { legend: { position: 'top', labels: { usePointStyle: true, pointStyleWidth: 8 } } },
        scales: {
          x: { grid: { color: 'rgba(0,212,255,0.06)' }, ticks: { font: { size: 11 } } },
          y: { grid: { color: 'rgba(0,212,255,0.06)' }, ticks: { font: { size: 11 } }, beginAtZero: true }
        },
        animation: { duration: 1200 },
      }
    });
  }
}

// ── Result Charts ────────────────────────────────────────
function initResultCharts(chartData) {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = '#8899bb';

  // Benign vs Malicious
  const bmCtx = document.getElementById('bm-chart');
  if (bmCtx) {
    new Chart(bmCtx, {
      type: 'doughnut',
      data: {
        labels: [(window.BASTION_I18N && window.BASTION_I18N.benign) || 'Benign', (window.BASTION_I18N && window.BASTION_I18N.malicious) || 'Malicious'],
        datasets: [{
          data: [chartData.benign, chartData.malicious],
          backgroundColor: ['rgba(0,255,148,0.8)', 'rgba(255,62,95,0.8)'],
          borderColor: ['#00ff94', '#ff3e5f'],
          borderWidth: 2,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true,
        cutout: '68%',
        plugins: {
          legend: { position: 'bottom', labels: { usePointStyle: true, pointStyleWidth: 10, font: { size: 12 } } }
        },
        animation: { animateRotate: true, duration: 1000 },
      }
    });
  }

  // Severity Bar
  const sevCtx = document.getElementById('sev-result-chart');
  if (sevCtx && chartData.severity) {
    const labels = Object.keys(chartData.severity);
    const values = Object.values(chartData.severity);
    const colors = { SAFE: '#00ff94', MEDIUM: '#ffb800', HIGH: '#ff6b35', CRITICAL: '#ff3e5f', UNKNOWN: '#8899bb' };
    new Chart(sevCtx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: labels.map(l => (colors[l] || '#8899bb') + '99'),
          borderColor: labels.map(l => colors[l] || '#8899bb'),
          borderWidth: 1,
          borderRadius: 8,
          borderSkipped: false,
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { font: { size: 12 } } },
          y: { grid: { color: 'rgba(0,212,255,0.06)' }, beginAtZero: true }
        },
        animation: { duration: 900 },
      }
    });
  }

  // Threat Breakdown
  const threatCtx = document.getElementById('threat-result-chart');
  if (threatCtx && chartData.threats && Object.keys(chartData.threats).length) {
    const PALETTE = ['#ff3e5f','#ff6b35','#ffb800','#00d4ff','#7b2fff','#00ff94','#a78bfa','#34d399'];
    const labels = Object.keys(chartData.threats);
    const values = Object.values(chartData.threats);
    new Chart(threatCtx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: labels.map((_, i) => PALETTE[i % PALETTE.length] + '99'),
          borderColor:      labels.map((_, i) => PALETTE[i % PALETTE.length]),
          borderWidth: 1,
          borderRadius: 6,
          borderSkipped: false,
        }]
      },
      options: {
        responsive: true,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(0,212,255,0.06)' }, beginAtZero: true },
          y: { grid: { display: false }, ticks: { font: { size: 11 } } }
        },
        animation: { duration: 900 },
      }
    });
  }
}

// ── History Search ───────────────────────────────────────
function initHistorySearch() {
  const input = document.getElementById('history-search');
  if (!input) return;
  const items = document.querySelectorAll('.history-item');
  input.addEventListener('input', function() {
    const q = this.value.toLowerCase();
    items.forEach(item => {
      const text = item.textContent.toLowerCase();
      item.style.display = text.includes(q) ? '' : 'none';
    });
  });
}

// ── Init ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCounters();
  initScrollAnimations();
  initFlashMessages();
  initUploadZone();
  initTableFilter();
  initFilterChips();
  initHistorySearch();

  // Chart data injected by templates
  if (window.BASTION_DASHBOARD) initDashboardCharts(window.BASTION_DASHBOARD);
  if (window.BASTION_RESULT)    initResultCharts(window.BASTION_RESULT);
});

// ═══════════════════════════════════════════════════════════
// BASTION IDS — Feature Upgrade JavaScript
// ═══════════════════════════════════════════════════════════

// ── Toast System (redesigned: slide from right, progress bar, stacking) ──────
function showToast(message, type, duration) {
  type     = type     || 'info';
  duration = duration || 4000;

  var container = document.getElementById('toast-container');
  if (!container) return;

  var _ti18n = window.BASTION_I18N || {};
  var titles   = { success: _ti18n.toastSuccess || 'SUCCESS', error: _ti18n.toastError || 'ERROR', warning: _ti18n.toastWarning || 'WARNING', info: _ti18n.toastInfo || 'INFO' };
  var iconSVGs = {
    success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error:   '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warning: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info:    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  };

  var toast = document.createElement('div');
  toast.className = 'toast ' + type;

  // Build inner HTML: icon wrap + body + close + progress bar
  // message is set via textContent to prevent XSS from server error strings
  toast.innerHTML =
    '<div class="toast-icon-wrap">' + (iconSVGs[type] || iconSVGs.info) + '</div>' +
    '<div class="toast-body">' +
      '<div class="toast-title">' + (titles[type] || 'INFO') + '</div>' +
      '<div class="toast-msg"></div>' +
    '</div>' +
    '<button class="toast-close" title="Close">&#x2715;</button>' +
    '<div class="toast-progress" style="animation-duration:' + duration + 'ms"></div>';
  toast.querySelector('.toast-msg').textContent = message;

  container.appendChild(toast);

  // Dismiss
  function dismiss() {
    clearTimeout(timer);
    toast.classList.add('hiding');
    setTimeout(function() { if (toast.parentNode) toast.remove(); }, 320);
  }

  var timer = setTimeout(dismiss, duration);

  toast.querySelector('.toast-close').addEventListener('click', function(e) {
    e.stopPropagation();
    dismiss();
  });
  toast.addEventListener('click', dismiss);
}

// ── Sortable Tables ───────────────────────────────────────
function makeTableSortable(tableId) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var ths = table.querySelectorAll('thead th.sortable');
  ths.forEach(function(th, idx) {
    th.addEventListener('click', function() {
      var isAsc = th.classList.contains('asc');
      ths.forEach(function(t) { t.classList.remove('asc','desc'); });
      th.classList.add(isAsc ? 'desc' : 'asc');
      var tbody = table.querySelector('tbody');
      var rows  = Array.from(tbody.querySelectorAll('tr:not(.expand-row)'));
      rows.sort(function(a, b) {
        var cells_a = a.querySelectorAll('td');
        var cells_b = b.querySelectorAll('td');
        if (!cells_a[idx] || !cells_b[idx]) return 0;
        var aVal = cells_a[idx].textContent.trim();
        var bVal = cells_b[idx].textContent.trim();
        var aNum = parseFloat(aVal.replace(/[^0-9.\-]/g,''));
        var bNum = parseFloat(bVal.replace(/[^0-9.\-]/g,''));
        var cmp;
        if (!isNaN(aNum) && !isNaN(bNum)) {
          cmp = aNum - bNum;
        } else {
          cmp = aVal.localeCompare(bVal);
        }
        return isAsc ? -cmp : cmp;
      });
      rows.forEach(function(row) {
        tbody.appendChild(row);
        var next = row.nextElementSibling;
        if (next && next.classList.contains('expand-row')) {
          tbody.appendChild(next);
        }
      });
    });
  });
}

// ── Column Visibility Toggle ──────────────────────────────
function initColumnToggle(tableId, toggleContainerId) {
  var table     = document.getElementById(tableId);
  var container = document.getElementById(toggleContainerId);
  if (!table || !container) return;

  var storageKey = 'col-toggle-' + tableId;
  var saved      = {};
  try { saved = JSON.parse(localStorage.getItem(storageKey) || '{}'); } catch(e) {}

  var ths = table.querySelectorAll('thead th');
  ths.forEach(function(th, idx) {
    var label = th.textContent.trim();
    if (!label || label === '#') return;

    var btn = document.createElement('button');
    btn.className = 'col-toggle-btn';
    btn.textContent = label;

    var colHidden = saved[idx] === true;
    if (colHidden) {
      btn.classList.add('hidden-col');
      setColVisible(table, idx, false);
    }

    btn.addEventListener('click', function() {
      var hidden = btn.classList.toggle('hidden-col');
      setColVisible(table, idx, !hidden);
      saved[idx] = hidden;
      try { localStorage.setItem(storageKey, JSON.stringify(saved)); } catch(e) {}
    });

    container.appendChild(btn);
  });
}

function setColVisible(table, idx, visible) {
  var rows = table.querySelectorAll('tr');
  rows.forEach(function(row) {
    var cells = row.querySelectorAll('th, td');
    if (cells[idx]) {
      cells[idx].style.display = visible ? '' : 'none';
    }
  });
}

// ── Row Expansion ─────────────────────────────────────────
function initRowExpansion() {
  document.querySelectorAll('tr.expandable').forEach(function(row) {
    row.addEventListener('click', function(e) {
      if (e.target.closest('a') || e.target.closest('button')) return;
      var expandRow = row.nextElementSibling;
      if (expandRow && expandRow.classList.contains('expand-row')) {
        expandRow.classList.toggle('open');
      }
    });
  });
}

// ── Sidebar Collapse ──────────────────────────────────────
function toggleSidebar() {
  var sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;
  sidebar.classList.toggle('collapsed');
  var isCollapsed = sidebar.classList.contains('collapsed');
  try { localStorage.setItem('sidebar-collapsed', isCollapsed ? '1' : '0'); } catch(e) {}
  updateMainContentMargin();
}

function updateMainContentMargin() {
  var sidebar = document.querySelector('.sidebar');
  var main    = document.querySelector('.main-content');
  if (!sidebar || !main) return;
  var w = sidebar.classList.contains('collapsed') ? '64px' : '200px';
  main.style.marginLeft = w;
  main.style.width = 'calc(100% - ' + w + ')';
}

(function restoreSidebar() {
  try {
    if (localStorage.getItem('sidebar-collapsed') === '1') {
      var sidebar = document.querySelector('.sidebar');
      if (sidebar) {
        sidebar.classList.add('collapsed');
        updateMainContentMargin();
      }
    }
  } catch(e) {}
})();

// ── Dashboard SSE Auto-Refresh ────────────────────────────
function initDashboardStream() {
  if (!document.getElementById('dash-total-scans')) return;
  if (typeof EventSource === 'undefined') return;
  var es = new EventSource('/api/dashboard/stream');
  es.onmessage = function(e) {
    try {
      var d = JSON.parse(e.data);
      var elScans   = document.getElementById('dash-total-scans');
      var elFlows   = document.getElementById('dash-total-flows');
      var elThreats = document.getElementById('dash-total-threats');
      var elUnread  = document.getElementById('dash-unread-count');
      if (elScans   && d.total_scans   !== undefined) elScans.textContent   = d.total_scans.toLocaleString();
      if (elFlows   && d.total_flows   !== undefined) elFlows.textContent   = d.total_flows.toLocaleString();
      if (elThreats && d.total_threats !== undefined) elThreats.textContent = d.total_threats.toLocaleString();
      if (elUnread  && d.unread_count  !== undefined) {
        elUnread.textContent = d.unread_count > 0 ? d.unread_count : '';
        elUnread.style.display = d.unread_count > 0 ? 'flex' : 'none';
      }
    } catch(ex) {}
  };
  es.onerror = function() {
    es.close();
    // Reconnect after 5 seconds on error
    setTimeout(initDashboardStream, 5000);
  };
}

// ── Threat Level Gauge ────────────────────────────────────
function renderThreatGauge(containerId, level) {
  var el = document.getElementById(containerId);
  if (!el) return;

  level = Math.max(0, Math.min(10, level || 0));
  var color;
  if      (level <= 3)  color = '#00ff94';
  else if (level <= 6)  color = '#ffb800';
  else if (level <= 9)  color = '#ff6b35';
  else                  color = '#ff3e5f';

  var _gi18n = window.BASTION_I18N || {};
  var label;
  if      (level <= 2)  label = _gi18n.gaugeMinimal  || 'MINIMAL';
  else if (level <= 4)  label = _gi18n.gaugeLow      || 'LOW';
  else if (level <= 6)  label = _gi18n.gaugeMedium   || 'MEDIUM';
  else if (level <= 8)  label = _gi18n.gaugeHigh     || 'HIGH';
  else                  label = _gi18n.gaugeCritical || 'CRITICAL';

  var radius = 54;
  var circumference = 2 * Math.PI * radius;
  var fill = (level / 10) * circumference;

  el.innerHTML =
    '<div class="threat-gauge">' +
      '<svg width="140" height="140" viewBox="0 0 140 140">' +
        '<circle cx="70" cy="70" r="' + radius + '" fill="none" stroke="rgba(0,212,255,0.08)" stroke-width="12"/>' +
        '<circle cx="70" cy="70" r="' + radius + '" fill="none" stroke="' + color + '" stroke-width="12"' +
          ' stroke-linecap="round"' +
          ' stroke-dasharray="' + fill + ' ' + (circumference - fill) + '"' +
          ' style="filter:drop-shadow(0 0 8px ' + color + ');transition:stroke-dasharray 1s ease"/>' +
      '</svg>' +
      '<div class="threat-gauge-value">' +
        '<span class="threat-gauge-num" style="color:' + color + '">' + level + '</span>' +
        '<span class="threat-gauge-label">' + label + '</span>' +
      '</div>' +
    '</div>';
}

// ── Flow Triage ───────────────────────────────────────────
function triageFlow(scanId, flowId, status, btn) {
  fetch('/api/triage', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scan_id: scanId, flow_id: flowId, status: status})
  })
  .then(function(r) { if (!r.ok) throw new Error(r.statusText); return r.json(); })
  .then(function() {
    var i18n = window.BASTION_I18N || {};
    var TRIAGE_MAP = { confirmed: i18n.triageConfirmed, investigated: i18n.triageInvestigated, false_positive: i18n.triageFalsePos };
    var label = TRIAGE_MAP[status] || status.replace('_',' ');
    showToast((i18n.flowMarkedAs || 'Flow marked as') + ' ' + label, 'success');
    var actionsEl = btn.closest('.triage-actions');
    if (actionsEl) {
      var span = document.createElement('span');
      span.className = 'triage-applied ' + status;
      span.textContent = label;
      actionsEl.innerHTML = '';
      actionsEl.appendChild(span);
    }
  })
  .catch(function() { showToast((window.BASTION_I18N && window.BASTION_I18N.triageFailed) || 'Triage failed', 'error'); });
}

// ── Scan Tagging ──────────────────────────────────────────
function addTag(scanId, tag, inputEl) {
  if (!tag || !tag.trim()) return;
  fetch('/api/tag', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scan_id: scanId, tag: tag.trim(), action: 'add'})
  })
  .then(function(r) { return r.json(); })
  .then(function(d) {
    if (d.ok) {
      showToast((window.BASTION_I18N && window.BASTION_I18N.tagAdded) || 'Tag added', 'success');
      if (inputEl) inputEl.value = '';
      // Reload tag area
      var tagArea = document.getElementById('tags-' + scanId);
      if (tagArea) {
        var tagVal = tag.trim();
        var chip = document.createElement('span');
        chip.className = 'tag-chip';
        chip.appendChild(document.createTextNode(tagVal));
        var removeBtn = document.createElement('button');
        removeBtn.className = 'tag-chip-remove';
        removeBtn.textContent = '×';
        removeBtn.addEventListener('click', (function(sid, tv, btn) {
          return function() { removeTag(sid, tv, btn); };
        })(scanId, tagVal, removeBtn));
        chip.appendChild(removeBtn);
        var addForm = tagArea.querySelector('.tag-add-form');
        if (addForm) tagArea.insertBefore(chip, addForm);
        else tagArea.appendChild(chip);
      }
    }
  })
  .catch(function() { showToast((window.BASTION_I18N && window.BASTION_I18N.failedAddTag) || 'Failed to add tag', 'error'); });
}

function removeTag(scanId, tag, el) {
  fetch('/api/tag', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scan_id: scanId, tag: tag, action: 'remove'})
  })
  .then(function(r) { return r.json(); })
  .then(function(d) {
    if (d.ok) {
      var chip = el.closest('.tag-chip');
      if (chip) chip.remove();
      showToast((window.BASTION_I18N && window.BASTION_I18N.tagRemoved) || 'Tag removed', 'info');
    }
  })
  .catch(function() { showToast((window.BASTION_I18N && window.BASTION_I18N.failedRemoveTag) || 'Failed to remove tag', 'error'); });
}

// ── Whois Lookup ──────────────────────────────────────────
function lookupWhois(ip, containerId) {
  var el = document.getElementById(containerId);
  if (!el) return;
  // Auto-open the parent expand-row so the result is visible
  var expandRow = el.closest('tr.expand-row');
  if (expandRow) expandRow.classList.add('open');
  el.innerHTML = '<span class="skeleton skeleton-text" style="width:200px;display:inline-block"></span>';
  fetch('/api/whois/' + encodeURIComponent(ip))
    .then(function(r) { if (!r.ok) throw new Error(r.statusText); return r.json(); })
    .then(function(d) {
      var i18n = window.BASTION_I18N || {};
      if (d.private) {
        el.innerHTML = '<span style="font-size:12px;color:var(--text-3)">' + (i18n.whoisPrivate || 'Private/internal IP — no public WHOIS data') + '</span>';
        return;
      }
      var parts = [];
      if (d.hostname && d.hostname !== ip) parts.push(d.hostname);
      if (d.org)     parts.push(d.org);
      if (d.city)    parts.push(d.city);
      if (d.country) parts.push(d.country);
      var span = document.createElement('span');
      span.className = 'mono';
      span.style.fontSize = '12px';
      span.style.color = 'var(--text-2)';
      if (parts.length) {
        span.textContent = parts.join(' \u00b7 ');
      } else {
        var noData = document.createElement('span');
        noData.style.color = 'var(--text-3)';
        noData.textContent = i18n.whoisNoData || 'No data found';
        span.appendChild(noData);
      }
      el.innerHTML = '';
      el.appendChild(span);
    })
    .catch(function() {
      var i18n = window.BASTION_I18N || {};
      el.innerHTML = '<span style="color:var(--text-3);font-size:12px">' + (i18n.whoisFailed || 'Lookup failed') + '</span>';
    });
}

// ── Watchlist AJAX add ────────────────────────────────────
function watchlistAdd(ip, note, btn) {
  var i18n = window.BASTION_I18N || {};
  if (!ip) { showToast(i18n.noIP || 'No IP address', 'error'); return; }
  btn.disabled = true;
  btn.textContent = '…';
  fetch('/watchlist/add', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ip: ip, note: note || ''})
  })
  .then(function(r) { return r.json(); })
  .then(function(d) {
    if (d.ok) {
      showToast('🎯 ' + ip + ' ' + (i18n.addedToWatchlist || 'added to watchlist'), 'success');
      btn.textContent = i18n.watching || '✓ Watching';
      btn.style.color = 'var(--green)';
      btn.style.borderColor = 'var(--green)';
    } else {
      showToast(d.error || (i18n.failedToAdd || 'Failed to add'), 'warning');
      btn.disabled = false;
      btn.textContent = i18n.watchLabel || '🎯 Watch';
    }
  })
  .catch(function() {
    showToast(i18n.networkError || 'Network error', 'error');
    btn.disabled = false;
    btn.textContent = i18n.watchLabel || '🎯 Watch';
  });
}

// ── Notification actions ──────────────────────────────────
function markNotifRead(id) {
  fetch('/api/notifications/mark_read', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: id})
  })
  .then(function(r) { if (!r.ok) throw new Error(r.statusText); return r.json(); })
  .then(function() {
    var el = document.getElementById('notif-' + id);
    if (el) el.classList.remove('unread');
    updateBellBadge(-1);
    showToast((window.BASTION_I18N && window.BASTION_I18N.markedAsRead) || 'Marked as read', 'info');
  })
  .catch(function() { showToast((window.BASTION_I18N && window.BASTION_I18N.networkError) || 'Network error', 'error'); });
}

function markAllNotifsRead() {
  fetch('/api/notifications/mark_read', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({all: true})
  })
  .then(function(r) { if (!r.ok) throw new Error(r.statusText); return r.json(); })
  .then(function() {
    document.querySelectorAll('.notif-item.unread').forEach(function(el) {
      el.classList.remove('unread');
    });
    var badge = document.querySelector('.notif-badge');
    if (badge) badge.remove();
    showToast((window.BASTION_I18N && window.BASTION_I18N.allNotifsRead) || 'All notifications marked as read', 'success');
  })
  .catch(function() { showToast((window.BASTION_I18N && window.BASTION_I18N.networkError) || 'Network error', 'error'); });
}

function deleteNotif(id) {
  fetch('/api/notifications/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: id})
  })
  .then(function(r) { if (!r.ok) throw new Error(r.statusText); return r.json(); })
  .then(function() {
    var el = document.getElementById('notif-' + id);
    if (el) {
      el.style.opacity = '0';
      setTimeout(function() { el.remove(); }, 300);
    }
    showToast((window.BASTION_I18N && window.BASTION_I18N.notifDeleted) || 'Notification deleted', 'info');
  })
  .catch(function() { showToast((window.BASTION_I18N && window.BASTION_I18N.networkError) || 'Network error', 'error'); });
}

function updateBellBadge(delta) {
  var badge = document.querySelector('.notif-badge');
  if (!badge) return;
  var current = parseInt(badge.textContent) || 0;
  var newCount = Math.max(0, current + delta);
  if (newCount === 0) badge.remove();
  else badge.textContent = newCount > 9 ? '9+' : newCount;
}

// ── Export CSV (audit log) ────────────────────────────────
function exportAuditCSV() {
  var table = document.getElementById('audit-table');
  if (!table) return;
  var rows = Array.from(table.querySelectorAll('tr'));
  var csv  = rows.map(function(row) {
    return Array.from(row.querySelectorAll('th,td')).map(function(cell) {
      return '"' + cell.textContent.trim().replace(/"/g,'""') + '"';
    }).join(',');
  }).join('\n');
  var blob = new Blob([csv], {type: 'text/csv'});
  var url  = URL.createObjectURL(blob);
  var a    = document.createElement('a');
  a.href = url; a.download = 'bastion_audit_log.csv';
  a.click();
  URL.revokeObjectURL(url);
}

// ── Flash → Toast conversion ──────────────────────────────
function convertFlashToToasts() {
  document.querySelectorAll('.flash-message').forEach(function(msg) {
    var type = msg.classList.contains('alert-error') ? 'error' : 'success';
    var text = msg.textContent.trim();
    msg.remove();
    showToast(text, type);
  });
}

// ── Audit log table search ────────────────────────────────
function initAuditSearch() {
  var input = document.getElementById('audit-search');
  if (!input) return;
  input.addEventListener('input', function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll('#audit-table tbody tr').forEach(function(row) {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

// ── Global Row Severity Color Applicator ──────────────────
function applyRowSeverityColors() {
  document.querySelectorAll('.data-table tbody tr').forEach(function(row) {
    var sev = (row.getAttribute('data-severity') || '').toUpperCase();
    if (!sev) {
      // Scan badge elements in cells
      row.querySelectorAll('.badge').forEach(function(badge) {
        var txt = badge.textContent.trim().toUpperCase();
        if (['CRITICAL','HIGH','MEDIUM','SAFE','UNKNOWN'].indexOf(txt) !== -1) {
          sev = txt;
        }
      });
    }
    if (!sev) return;
    var cls = 'sev-' + sev.toLowerCase();
    if (!row.classList.contains(cls)) {
      row.classList.add(cls);
    }
    if (sev === 'CRITICAL') {
      row.classList.add('neon-critical');
    }
  });
}

// ── DOMContentLoaded additions ────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  // Restore sidebar
  try {
    if (localStorage.getItem('sidebar-collapsed') === '1') {
      var sidebar = document.querySelector('.sidebar');
      if (sidebar) {
        sidebar.classList.add('collapsed');
        updateMainContentMargin();
      }
    }
  } catch(e) {}

  // Row expansion
  initRowExpansion();

  // Dashboard SSE — skip if the page already provides its own inline SSE
  // (dashboard.html connects to /api/dashboard/live; this avoids a duplicate connection)
  if (!window.BASTION_DASHBOARD) {
    initDashboardStream();
  }

  // Make all .data-table sortable
  document.querySelectorAll('.data-table').forEach(function(t) {
    if (t.id) makeTableSortable(t.id);
  });

  // Column toggle for flows-table
  initColumnToggle('flows-table', 'col-toggle-container');

  // Audit search
  initAuditSearch();

  // Convert flash messages to toasts (after small delay so DOM is ready)
  setTimeout(convertFlashToToasts, 100);

  // Wire all Watch buttons to AJAX
  document.querySelectorAll('.watch-btn').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.preventDefault();
      watchlistAdd(btn.dataset.ip, btn.dataset.note, btn);
    });
  });

  // Apply row severity colors globally on all pages
  applyRowSeverityColors();

  // Re-apply after any dynamic content updates (MutationObserver)
  var tableObs = new MutationObserver(function(mutations) {
    var needsUpdate = mutations.some(function(m) {
      return m.type === 'childList' && m.addedNodes.length > 0;
    });
    if (needsUpdate) { applyRowSeverityColors(); initRowExpansion(); }
  });
  document.querySelectorAll('.data-table tbody').forEach(function(tbody) {
    tableObs.observe(tbody, { childList: true });
  });
});
