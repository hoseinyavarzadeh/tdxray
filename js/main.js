/* ============================================================
   TDXRay — main.js
   ============================================================ */

/* ── Heatmap Canvas — ember spread + token reveal ───────────── */
(function () {
  const canvas = document.getElementById('heatmap-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const CELL = 60;

  const TOKENS = [
    // --- TDXRay Primitives & Hardware ---
    'SEP', 'TSX', 'MWT', 'L+P', 'TDX', 'CVM', 'TEE', 'L1D', 'LLC', 'GPA', 'HPA',
    'cache', 'trace', 'leak', 'fault', 'probe', 'hit', 'miss', 'way', 'tag',
    'cl', 'set', 'bus', 'sync', 'trap', 'exit', 'call', 'ret', 'ptr', 'off',

    // --- Tokenizer & AI "Fragments" ---
    'BPE', 'vocab', 'hash', 'map', 'idx', 'token', 'toke', 'quer', 'user',
    'prompt', 'input', 'out', 'llama', 'gemma', 'bert', 'gpt', 'soft', 'max',
    'emb', 'layer', 'head', 'mask', 'top', 'temp', 'dist', 'next', 'prev',
    'the', 'ing', 'tion', 'ment', 'ence', 'auth', 'pass', 'word', 'prot',

    // --- Data Exfil & Logic ---
    'AES', 'key', 'table', 'round', 'bit', 'byte', 'hex', '0x4f', '0x2c',
    'addr', 'data', 'file', 'sys', 'root', 'admin', 'flag', 'init', 'true',
    'Name', 'SSN', 'CVC', 'exp', 'mail', '4581', '3/28', '91.5', '94.2',
    'oracle', 'noise', 'wait', 'lock', 'root', 'save', 'load', 'stor'
  ];

  let cols, rows, cells, tokenMap;

  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    cols     = Math.ceil(canvas.width  / CELL) + 1;
    rows     = Math.ceil(canvas.height / CELL) + 1;
    cells    = new Float32Array(cols * rows);
    tokenMap = {};
  }

  function idx(x, y) { return y * cols + x; }

  function ignite(cx, cy) {
    if (cx < 0 || cx >= cols || cy < 0 || cy >= rows) return;
    cells[idx(cx, cy)] = Math.min(1, cells[idx(cx, cy)] + 0.9 + Math.random() * 0.1);

    // const dirs = [[-1,0],[1,0],[0,-1],[0,1],[-1,-1],[1,-1],[-1,1],[1,1]];
    // const spreadCount = 2 + Math.floor(Math.random() * 3);
    // dirs.sort(() => Math.random() - 0.5).slice(0, spreadCount).forEach(([dx, dy], i) => {
    //   const nx = cx + dx, ny = cy + dy;
    //   if (nx < 0 || nx >= cols || ny < 0 || ny >= rows) return;
    //   setTimeout(() => {
    //     cells[idx(nx, ny)] = Math.min(1, cells[idx(nx, ny)] + 0.4 + Math.random() * 0.3);
    //     if (Math.random() < 0.45) {
    //       const nx2 = nx + dx, ny2 = ny + dy;
    //       if (nx2 >= 0 && nx2 < cols && ny2 >= 0 && ny2 < rows) {
    //         setTimeout(() => {
    //           cells[idx(nx2, ny2)] = Math.min(1, cells[idx(nx2, ny2)] + 0.2 + Math.random() * 0.2);
    //         }, 60 + Math.random() * 80);
    //       }
    //     }
    //   }, 40 + i * 30 + Math.random() * 60);
    // });
  }

  function spawnCluster() {
    let cx, cy, distFromCenter;
    do {
      cx = Math.floor(Math.random() * cols);
      cy = Math.floor(Math.random() * rows);
      const nx = (cx / cols - 0.5) * 2;
      const ny = (cy / rows - 0.5) * 2;
      distFromCenter = nx * nx + ny * ny;
    } while (distFromCenter < 0.35);

    if (true) {
      const key = cx + ',' + cy;
      tokenMap[key] = TOKENS[Math.floor(Math.random() * TOKENS.length)];
    }
    ignite(cx, cy);
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const v = cells[idx(x, y)];
        if (v < 0.015) continue;

        const nx  = (x / cols - 0.5) * 2;
        const ny  = (y / rows - 0.5) * 2;
        const vig = Math.max(0, 1 - (nx * nx + ny * ny) * 0.6);
        const a   = v * vig;
        if (a < 0.01) continue;

        let r, g, b;
        if (v < 0.4) {
          const t = v / 0.4;
          r = 0; g = Math.round(t * 185); b = Math.round(90 + t * 130);
        } else if (v < 0.75) {
          const t = (v - 0.4) / 0.35;
          r = Math.round(t * 20); g = Math.round(185 + t * 55); b = Math.round(220 - t * 10);
        } else {
          const t = (v - 0.75) / 0.25;
          r = Math.round(20 + t * 215); g = Math.round(240 + t * 15); b = Math.round(210 + t * 45);
        }

        ctx.fillStyle = `rgba(${r},${g},${b},${Math.min(1, a * 1.6).toFixed(3)})`;
        ctx.fillRect(x * CELL, y * CELL, CELL, CELL);

        if (v > 0.65) {
          const t = (v - 0.65) / 0.35;
          ctx.fillStyle = `rgba(220,255,255,${(t * a * 0.85).toFixed(3)})`;
          const m = CELL * 0.3;
          ctx.fillRect(x * CELL + m, y * CELL + m, CELL - m * 2, CELL - m * 2);
        }

        const key = x + ',' + y;
        if (tokenMap[key] && v > 0.05) {
          const textAlpha = Math.min(1, (v - 0.05) / 0.1) * vig;
          ctx.save();
          ctx.font = '500 13px monospace';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillStyle = `rgba(220,255,255,${textAlpha.toFixed(3)})`;
          ctx.fillText(tokenMap[key], x * CELL + CELL / 2, y * CELL + CELL / 2);
          ctx.restore();
          if (v < 0.02) delete tokenMap[key];
        }
      }
    }
  }

  function loop() {
    for (let i = 0; i < cells.length; i++) {
      if (cells[i] > 0) {
        cells[i] *= 0.982;
        if (cells[i] < 0.01) cells[i] = 0;
      }
    }
    draw();
    requestAnimationFrame(loop);
  }

  function scheduleNext() {
    setTimeout(() => { spawnCluster(); scheduleNext(); }, 600 + Math.random() * 1200);
  }

  resize();
  window.addEventListener('resize', resize);
  for (let i = 0; i < 4; i++) spawnCluster();
  scheduleNext();
  loop();
})();

/* ── Cache table synced with scan ───────────────────────────── */
function animateCacheLines() {
  const cls = document.querySelectorAll('td.cl');
  if (!cls.length) return;
  cls.forEach(cl => cl.classList.remove('hit'));

  // fire hits at the halfway point so they land as the line sweeps through
  const count = 3 + Math.floor(Math.random() * 5);
  [...cls].sort(() => Math.random() - 0.5).slice(0, count)
    .forEach((cl, i) => setTimeout(() => cl.classList.add('hit'), 3000 + i * 20));
}
setInterval(animateCacheLines, 3000);
animateCacheLines();

/* ── Scroll reveal ──────────────────────────────────────────── */
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.classList.add('visible');
      revealObserver.unobserve(e.target);
    }
  });
}, { threshold: 0.12 });

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

/* ── Bar chart animation on scroll ─────────────────────────── */
const barObserver = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.querySelectorAll('.bar-fill').forEach((bar, i) => {
        setTimeout(() => bar.classList.add('animate'), i * 150);
      });
      barObserver.unobserve(e.target);
    }
  });
}, { threshold: 0.3 });

document.querySelectorAll('.accuracy-bar-group').forEach(el => barObserver.observe(el));

/* ── Cache-line animation ───────────────────────────────────── */
function animateCacheLines() {
  const cls = document.querySelectorAll('.cl');
  if (!cls.length) return;
  cls.forEach(cl => cl.classList.remove('hit'));
  const count = Math.floor(Math.random() * 4) + 2;
  const indices = [];
  while (indices.length < count) {
    const r = Math.floor(Math.random() * cls.length);
    if (!indices.includes(r)) indices.push(r);
  }
  indices.forEach((idx, i) => {
    setTimeout(() => cls[idx].classList.add('hit'), i * 180);
  });
}
setInterval(animateCacheLines, 2200);
animateCacheLines();

/* ── FAQ accordion ──────────────────────────────────────────── */
document.querySelectorAll('.faq-q').forEach(btn => {
  btn.addEventListener('click', () => {
    const item = btn.closest('.faq-item');
    const isOpen = item.classList.contains('open');
    document.querySelectorAll('.faq-item.open').forEach(i => i.classList.remove('open'));
    if (!isOpen) item.classList.add('open');
  });
});

/* ── Smooth active nav highlighting ────────────────────────── */
const sections = document.querySelectorAll('section[id], div[id]');
const navLinks = document.querySelectorAll('.nav-links a');

const navObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(a => {
        a.style.color = '';
        if (a.getAttribute('href') === '#' + entry.target.id) {
          a.style.color = 'var(--teal)';
        }
      });
    }
  });
}, { rootMargin: '-40% 0px -55% 0px' });

sections.forEach(s => navObserver.observe(s));

/* ── Copy BibTeX ────────────────────────────────────────────── */
const copyBtn = document.getElementById('copy-bibtex');
if (copyBtn) {
  copyBtn.addEventListener('click', () => {
    const bib = document.getElementById('bibtex-content').textContent;
    navigator.clipboard.writeText(bib).then(() => {
      copyBtn.textContent = 'Copied!';
      setTimeout(() => copyBtn.textContent = 'Copy BibTeX', 2500);
    });
  });
}

/* ── Terminal typewriter ────────────────────────────────────── */
function typewriterEffect() {
  const el = document.getElementById('typewriter');
  if (!el) return;
  const lines = el.querySelectorAll('.tw-line');
  let i = 0;
  function showNext() {
    if (i < lines.length) {
      lines[i].style.opacity = '1';
      i++;
      setTimeout(showNext, 400 + Math.random() * 300);
    }
  }
  const twObserver = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) {
      setTimeout(showNext, 400);
      twObserver.disconnect();
    }
  }, { threshold: 0.5 });
  twObserver.observe(el);
}
typewriterEffect();

/* ── Number counter ─────────────────────────────────────────── */
function animateCounter(el) {
  const target = parseFloat(el.dataset.target);
  const suffix = el.dataset.suffix || '';
  const duration = 1800;
  const start = performance.now();
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 3);
    const val = target * ease;
    el.textContent = (val % 1 === 0 ? Math.floor(val) : val.toFixed(1)) + suffix;
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

const counterObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.querySelectorAll('.number[data-target]').forEach(animateCounter);
      counterObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('.stats-row').forEach(el => counterObserver.observe(el));

/* ── Theme toggle ────────────────────────────────────────────── */
(function () {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  const saved = localStorage.getItem('tdxray-theme');
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');

  btn.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    if (isLight) {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('tdxray-theme', 'dark');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
      localStorage.setItem('tdxray-theme', 'light');
    }
  });
})();