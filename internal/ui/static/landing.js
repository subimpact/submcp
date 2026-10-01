// internal/ui/static/landing.js
// Vanilla JS for the submcp landing page.
// No libraries, no scroll listeners. Everything honors prefers-reduced-motion.

(() => {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- 1. Live data: /api/public/stats ---------- */
  const paintUpstreams = (upstreams) => {
    const list = $('#upstream-list');
    list.innerHTML = '';
    if (!upstreams || !upstreams.length) {
      const li = document.createElement('li');
      li.className = 'upstream-error';
      li.textContent = 'Stats unavailable';
      list.appendChild(li);
      return;
    }
    upstreams.forEach((u) => {
      const li = document.createElement('li');
      li.className = 'upstream-row';

      const name = document.createElement('span');
      name.className = 'upstream-name';
      name.textContent = u.name;

      const type = document.createElement('span');
      type.className = 'upstream-type';
      type.textContent = u.type;

      const status = document.createElement('span');
      const healthy = u.error_status === 'NONE';
      status.className = 'upstream-status ' + (healthy ? 'ok' : 'err');
      status.textContent = healthy ? 'healthy' : 'error';

      li.appendChild(name);
      li.appendChild(type);
      li.appendChild(status);
      list.appendChild(li);
    });
  };

  const paintStatsError = () => {
    ['#stat-tools', '#stat-servers', '#stat-uptime'].forEach((sel) => {
      const el = $(sel);
      if (el) el.textContent = '?';
    });
    const list = $('#upstream-list');
    list.innerHTML = '';
    const li = document.createElement('li');
    li.className = 'upstream-error';
    li.textContent = 'Stats unavailable';
    list.appendChild(li);
  };

  const loadStats = async () => {
    try {
      const res = await fetch('/api/public/stats');
      if (!res.ok) throw new Error('bad status ' + res.status);
      const d = await res.json();

      const tools = $('#stat-tools');
      const servers = $('#stat-servers');
      const uptime = $('#stat-uptime');
      if (!tools || !servers || !uptime) return;

      // Numeric targets stored for the count-up; uptime renders as-is.
      tools.dataset.target = String(d.tools);
      servers.dataset.target = String(d.servers);
      uptime.textContent = d.uptime;

      if (prefersReduced) {
        tools.textContent = String(d.tools);
        servers.textContent = String(d.servers);
        countUpDone();
      }

      // If the band was already scrolled into view before the fetch
      // resolved, cue the count-up now.
      const band = $('#live-band');
      if (band && band.dataset.cued && !prefersReduced) {
        ['#stat-tools', '#stat-servers'].forEach((sel) => {
          const el = $(sel);
          const to = parseInt(el.dataset.target, 10);
          if (Number.isFinite(to)) countUp(el, to);
        });
      }

      paintUpstreams(d.upstreams);
    } catch (e) {
      paintStatsError();
    }
  };

  /* ---------- 2. Count-up (live band) ---------- */
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);

  const countUp = (el, to) => {
    const duration = 400;
    const start = performance.now();
    const tick = (now) => {
      const p = Math.min((now - start) / duration, 1);
      el.textContent = String(Math.round(to * easeOut(p)));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  const countUpDone = () => {
    const el = $('#live-band');
    if (!el) return;
    ['#stat-tools', '#stat-servers'].forEach((sel) => {
      const n = $(sel);
      if (n && n.dataset.target) n.textContent = n.dataset.target;
    });
  };

  const observeStats = () => {
    const band = $('#live-band');
    if (!band || band.dataset.cued) return;
    band.dataset.cued = '1';
    if (prefersReduced) {
      countUpDone();
      return;
    }
    ['#stat-tools', '#stat-servers'].forEach((sel) => {
      const el = $(sel);
      const to = parseInt(el.dataset.target, 10);
      if (Number.isFinite(to)) countUp(el, to);
    });
    const uptime = $('#stat-uptime');
    if (uptime && uptime.textContent === '') uptime.textContent = '-';
  };

  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          observeStats();
          io.disconnect();
        }
      });
    }, { threshold: 0.4 });
    const band = $('#live-band');
    if (band) io.observe(band);
  }

  /* ---------- 3. Hero canvas: signal switchboard ---------- */
  const initCanvas = () => {
    const canvas = $('#hero-canvas');
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext('2d');

    let width = 0;
    let height = 0;
    let raf = null;

    const SEGMENTS = 40;
    // Convergence node sits near center-right.
    let node = { x: 0, y: 0 };

    class Segment {
      constructor() { this.reset(true); }
      // A signal ray: the anchor stays on the top/right edge, the head
      // travels toward the convergence node, so the drawn 1px segment
      // grows as the signal arrives.
      reset(seeded) {
        const fromTop = Math.random() < 0.55;
        if (fromTop) {
          this.ax = Math.random() * width;
          this.ay = -6;
        } else {
          this.ax = width + 6;
          this.ay = Math.random() * height;
        }
        this.x = this.ax;
        this.y = this.ay;
        this.t = seeded && !prefersReduced ? Math.random() * 2600 : 0;
        this.speed = 1800 + Math.random() * 1600;
        this.amber = Math.random() < 0.22;
      }
      update(dt) {
        this.t += dt;
        const p = Math.min(this.t / this.speed, 1);
        const ease = p * p * (3 - 2 * p); // smoothstep
        this.x = this.ax + (node.x - this.ax) * ease;
        this.y = this.ay + (node.y - this.ay) * ease;
        if (p >= 1) this.reset(false);
      }
    }

    const segments = Array.from({ length: SEGMENTS }, () => new Segment());

    const resize = () => {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = width;
      canvas.height = height;
      node = { x: width * 0.72, y: height * 0.5 };
    };
    resize();
    window.addEventListener('resize', () => {
      resize();
      if (prefersReduced) drawStatic();
    });

    const strokeFor = (s) =>
      s.amber ? 'rgba(255,166,41,0.55)' : 'rgba(154,151,147,0.28)';

    const pulse = (t) => 0.5 + 0.5 * Math.sin(t * (Math.PI / 1.2)); // 2.4s cycle

    const drawNode = (t) => {
      const a = pulse(t);
      ctx.fillStyle = `rgba(255,166,41,${0.18 + 0.32 * a})`;
      ctx.beginPath();
      ctx.arc(node.x, node.y, 3 + 2 * a, 0, Math.PI * 2);
      ctx.fill();
    };

    const render = (now) => {
      if (!canvas.__last) canvas.__last = now;
      const dt = Math.min(now - canvas.__last, 50);
      canvas.__last = now;

      ctx.clearRect(0, 0, width, height);
      ctx.lineWidth = 1;
      segments.forEach((s) => {
        s.update(dt);
        ctx.strokeStyle = strokeFor(s);
        ctx.beginPath();
        ctx.moveTo(s.ax, s.ay);
        ctx.lineTo(s.x, s.y);
        ctx.stroke();
      });
      drawNode(now / 1000);
      raf = requestAnimationFrame(render);
    };

    const drawStatic = () => {
      ctx.clearRect(0, 0, width, height);
      ctx.lineWidth = 1;
      segments.forEach((s) => {
        s.t = s.speed; // park each ray just before arrival
        s.update(0);
        ctx.strokeStyle = strokeFor(s);
        ctx.beginPath();
        ctx.moveTo(s.ax, s.ay);
        ctx.lineTo(s.x, s.y);
        ctx.stroke();
      });
      ctx.fillStyle = 'rgba(255,166,41,0.85)';
      ctx.beginPath();
      ctx.arc(node.x, node.y, 4, 0, Math.PI * 2);
      ctx.fill();
    };

    if (prefersReduced) {
      drawStatic();
      return;
    }

    raf = requestAnimationFrame(render);

    // Pause the rAF loop when the tab is hidden.
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        if (raf) cancelAnimationFrame(raf);
        raf = null;
      } else if (raf === null) {
        raf = requestAnimationFrame(render);
      }
    });
  };

  /* ---------- 4. Marquee: duplicate content for a seamless loop ---------- */
  const initMarquee = () => {
    const track = $('.marquee-track');
    const seq = $('#marquee-seq');
    if (!track || !seq) return;
    const clone = seq.cloneNode(true);
    clone.removeAttribute('id');
    track.appendChild(clone);
  };

  /* ---------- 5. Scroll reveals ---------- */
  const initReveals = () => {
    const targets = document.querySelectorAll('.reveal');
    if (!targets.length) return;
    if (prefersReduced || !('IntersectionObserver' in window)) {
      targets.forEach((el) => el.classList.add('in'));
      return;
    }
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    targets.forEach((el) => io.observe(el));
  };

  /* ---------- 6. Sticky-stack dim: JS fallback ---------- */
  // Native scroll-scrub via animation-timeline: view() takes priority.
  // Where it is unsupported, an IntersectionObserver dims the previous
  // card as the next one scrolls over it. No scroll listeners, ever.
  const initStack = () => {
    if (prefersReduced) return;
    const native = window.CSS && CSS.supports('animation-timeline', 'view()');
    if (native) return;

    const cards = Array.from(document.querySelectorAll('.stack-card'));
    if (!cards.length || !('IntersectionObserver' in window)) return;

    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        const idx = cards.indexOf(entry.target);
        const prev = idx > 0 ? cards[idx - 1] : null;
        if (!prev) return;
        // The card approaching the sticky position dims the one beneath.
        const past = entry.isIntersecting &&
          entry.boundingClientRect.top < window.innerHeight * 0.14;
        prev.classList.toggle('dimmed', past);
      });
    }, { threshold: [0, 0.2, 0.5], rootMargin: '-14% 0px 0px 0px' });

    cards.forEach((c) => io.observe(c));
  };

  /* ---------- boot ---------- */
  initCanvas();
  initMarquee();
  initReveals();
  initStack();
  loadStats();
})();