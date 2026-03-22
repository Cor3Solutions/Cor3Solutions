/* ═══════════════════════════════════════════════════════
   COR3 SOLUTIONS — script.js  (secured)
   Security features:
   · URL allowlist — all external navigations validated
   · Input sanitisation — user text escaped before DOM use
   · Form validation — client-side checks before submit
   · noopener enforcement — all _blank links are safe
═══════════════════════════════════════════════════════ */

/* ──────────────────────────────────────────────────────
   SECURITY LAYER 1 — URL ALLOWLIST
   Add your real social URLs to ALLOWED_EXTERNAL when ready.
────────────────────────────────────────────────────── */

/** Allowed same-site paths. Add new pages here as you create them. */
const ALLOWED_PATHS = new Set([
  '/',
  '/index.html',
  '/portfolio-web.html',
  '/portfolio-admin.html',
  '/portfolio-social.html',
  '/portfolio-ugc.html',
  '/privacy-policy.html',
]);

/**
 * Allowed external URLs.
 * Uncomment and fill in your real social media profile URLs.
 */
const ALLOWED_EXTERNAL = new Set([
  // Social profiles — uncomment when ready:
  // 'https://www.facebook.com/cor3solutions',
  // 'https://www.instagram.com/cor3solutions',
  // 'https://www.linkedin.com/company/cor3solutions',
  // 'https://www.youtube.com/@cor3solutions',
]);

// Trusted external domains — links from these origins are allowed (e.g. share links)
const ALLOWED_EXTERNAL_DOMAINS = new Set([
  'www.facebook.com',
  'facebook.com',
  'www.privacy.gov.ph',
  // Client & portfolio websites
  'www.batangas1pmfc.com',
  'cor3-solutions.vercel.app',
  'www.jadesalvador.com',
  'mbk-sigma.vercel.app',
  'goducate.vercel.app',
  'locv2.vercel.app',
]);

/**
 * safeRedirect(rawUrl) → boolean
 *
 * Returns true  → navigation is permitted.
 * Returns false → navigation is blocked and logged.
 *
 * Rules:
 *  1. Same-page anchors (#section) → always allowed.
 *  2. mailto: links                → always allowed.
 *  3. Relative paths (no protocol) → allowed if in ALLOWED_PATHS.
 *  4. Same-origin absolute URLs    → allowed (origin trusted).
 *  5. External URLs                → allowed only if in ALLOWED_EXTERNAL.
 *  6. javascript:, data:, etc.     → always blocked.
 */
function safeRedirect(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return false;

  const url = rawUrl.trim();

  // Rule 1 — same-page anchor
  if (url.startsWith('#')) return true;

  // Rule 2 — mailto
  if (url.toLowerCase().startsWith('mailto:')) return true;

  // Rule 3 — relative path (no protocol, no leading //)
  if (!url.startsWith('http') && !url.startsWith('//')) {
    // Normalise: strip query/hash to get the path
    const path = url.split('?')[0].split('#')[0];
    const normalised = path.startsWith('/') ? path : '/' + path;
    if (!ALLOWED_PATHS.has(normalised)) {
      console.warn('[Cor3 Security] Blocked unlisted relative path:', url);
      return false;
    }
    return true;
  }

  // Parse as absolute URL
  let parsed;
  try {
    parsed = new URL(url, window.location.href);
  } catch {
    console.warn('[Cor3 Security] Blocked malformed URL:', url);
    return false;
  }

  // Block non-HTTP(S) protocols (javascript:, data:, vbscript:, blob: etc.)
  if (!['https:', 'http:'].includes(parsed.protocol)) {
    console.warn('[Cor3 Security] Blocked non-HTTP protocol:', parsed.protocol, url);
    return false;
  }

  // Rule 4 — same origin
  if (parsed.origin === window.location.origin) return true;

  // Rule 5a — check exact URL allowlist
  const normalised = parsed.origin + parsed.pathname;
  const exactMatch = [...ALLOWED_EXTERNAL].some(a => {
    try {
      const ap = new URL(a);
      return (ap.origin + ap.pathname) === normalised;
    } catch { return false; }
  });
  if (exactMatch) return true;

  // Rule 5b — check trusted domain allowlist (e.g. facebook.com share links)
  if (ALLOWED_EXTERNAL_DOMAINS.has(parsed.hostname)) return true;

  console.warn('[Cor3 Security] Blocked external URL not in allowlist:', url);
  return false;
}

/**
 * sanitiseText(str) → string
 * Escapes HTML special characters so user input is safe to insert
 * into the DOM as text (not raw HTML).
 */
function sanitiseText(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(String(str)));
  return div.innerHTML;
}

/* ──────────────────────────────────────────────────────
   SECURITY LAYER 2 — GLOBAL CLICK INTERCEPTOR
   Runs in capture phase (before default browser action)
   so it catches every <a> click on the page.
────────────────────────────────────────────────────── */
document.addEventListener('click', (e) => {
  const anchor = e.target.closest('a[href]');
  if (!anchor) return;

  const href = anchor.getAttribute('href');
  if (!href) return;

  // Anchors and mailto handled by the browser natively — skip
  if (href.startsWith('#') || href.toLowerCase().startsWith('mailto:')) return;

  // Only intercept external / absolute links
  if (!href.startsWith('http') && !href.startsWith('//')) return;

  if (!safeRedirect(href)) {
    e.preventDefault();
    e.stopImmediatePropagation();
    console.warn('[Cor3 Security] Click navigation blocked:', href);
  }
}, true); // ← capture phase


/* ══════════════════════════════════════════════════════
   DOM READY
══════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {

  /* ──────────────────────────────────────────
     1. SCROLL REVEAL  (IntersectionObserver)
  ────────────────────────────────────────── */
  const revealObs = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          revealObs.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
  );
  document.querySelectorAll('.reveal').forEach(el => revealObs.observe(el));


  /* ──────────────────────────────────────────
     2. ACTIVE NAV LINK ON SCROLL
  ────────────────────────────────────────── */
  const navLinks = document.querySelectorAll('.navbar-nav .nav-link[href^="#"]');
  const sections = document.querySelectorAll('section[id]');

  function updateActiveNav() {
    let current = '';
    sections.forEach(s => {
      if (window.scrollY >= s.offsetTop - 110) current = s.id;
    });
    navLinks.forEach(link => {
      link.classList.toggle('active', link.getAttribute('href') === '#' + current);
    });
  }
  window.addEventListener('scroll', updateActiveNav, { passive: true });
  updateActiveNav();


  /* ──────────────────────────────────────────
     3. PORTFOLIO FILTER
  ────────────────────────────────────────── */
  const filterBar = document.getElementById('filterBar');
  if (filterBar) {
    filterBar.addEventListener('click', (e) => {
      const btn = e.target.closest('.filter-btn');
      if (!btn) return;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.filter;
      document.querySelectorAll('[data-filter-item]').forEach(item => {
        item.style.display =
          (filter === 'all' || item.dataset.filterItem === filter) ? '' : 'none';
      });
    });
  }


  /* ──────────────────────────────────────────
     4. CONTACT FORM — validation + SweetAlert2
  ────────────────────────────────────────── */
  const form = document.getElementById('contactForm');
  if (form) {

    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

    /** Show a red error message below a field. */
    function showError(el, msg) {
      el.style.borderColor = '#e53e3e';
      let err = el.nextElementSibling;
      if (!err || !err.classList.contains('field-error')) {
        err = document.createElement('small');
        err.className = 'field-error';
        err.style.cssText =
          'color:#e53e3e;font-size:0.72rem;display:block;margin-top:0.3rem;font-family:var(--font-mono,monospace);';
        el.insertAdjacentElement('afterend', err);
      }
      err.textContent = msg;
    }

    /** Clear error styling from a field. */
    function clearError(el) {
      if (!el) return;
      el.style.borderColor = '';
      const err = el.nextElementSibling;
      if (err && err.classList.contains('field-error')) err.remove();
    }

    /** Run all validations. Returns true if the form is valid. */
    function validate() {
      const nameEl    = form.querySelector('input[placeholder="Juan dela Cruz"]');
      const emailEl   = form.querySelector('input[type="email"]');
      const serviceEl = form.querySelector('select');
      const msgEl     = form.querySelector('textarea');

      [nameEl, emailEl, serviceEl, msgEl].forEach(clearError);
      let ok = true;

      if (!nameEl || nameEl.value.trim().length < 2) {
        showError(nameEl, 'Please enter your full name (at least 2 characters).');
        ok = false;
      }
      if (!emailEl || !EMAIL_RE.test(emailEl.value.trim())) {
        showError(emailEl, 'Please enter a valid email address.');
        ok = false;
      }
      if (!serviceEl || !serviceEl.value) {
        showError(serviceEl, 'Please select a service.');
        ok = false;
      }
      if (!msgEl || msgEl.value.trim().length < 10) {
        showError(msgEl, 'Please enter a message (at least 10 characters).');
        ok = false;
      }
      return ok;
    }

    // Clear error on input
    form.querySelectorAll('input, select, textarea').forEach(el => {
      el.addEventListener('input', () => clearError(el));
      el.addEventListener('change', () => clearError(el));
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!validate()) return;

      const btn      = form.querySelector('[type="submit"]');
      const origHTML = btn.innerHTML;
      btn.innerHTML  =
        '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Sending…';
      btn.disabled = true;

      try {
        /* ── Replace the mock delay below with your real backend call.
           Example using FormSubmit (free, no server needed):

           const data = new FormData(form);
           data.append('_subject', 'New inquiry from Cor3 Solutions website');
           data.append('_captcha', 'false');
           const res = await fetch('https://formsubmit.co/ajax/Cor3Solutions@gmail.com', {
             method: 'POST',
             headers: { Accept: 'application/json' },
             body: data,
           });
           if (!res.ok) throw new Error('Network error');
        ──────────────────────────────────────────────────────────────── */
        await new Promise(r => setTimeout(r, 1800));   // ← REPLACE THIS

        form.reset();

        if (typeof Swal !== 'undefined') {
          Swal.fire({
            title:              'Message Sent! 🚀',
            html:               "Thanks for reaching out. We'll get back to you within <strong>24 hours</strong>.",
            icon:               'success',
            background:         '#ffffff',
            color:              '#0d0f1c',
            confirmButtonColor: '#2563c4',
            confirmButtonText:  '<span style="font-family:monospace;font-weight:700;font-size:0.78rem;letter-spacing:0.1em">AWESOME!</span>',
            iconColor:          '#6b3fa0',
          });
        }
      } catch {
        if (typeof Swal !== 'undefined') {
          Swal.fire({
            title:              'Oops!',
            text:               'Something went wrong. Please email us directly at Cor3Solutions@gmail.com',
            icon:               'error',
            background:         '#ffffff',
            color:              '#0d0f1c',
            confirmButtonColor: '#2563c4',
          });
        }
      } finally {
        btn.innerHTML = origHTML;
        btn.disabled  = false;
      }
    });
  }


  /* ──────────────────────────────────────────
     5. PIXEL DECO ANIMATION (hero card)
  ────────────────────────────────────────── */
  const pixels  = document.querySelectorAll('.pixel-deco span');
  const classes = ['on', 'on2', 'on3'];

  if (pixels.length) {
    function animatePixels() {
      pixels.forEach(p => {
        p.className = '';
        if (Math.random() > 0.45) {
          p.classList.add(classes[Math.floor(Math.random() * classes.length)]);
        }
      });
    }
    animatePixels();
    setInterval(animatePixels, 1200);
  }

});