// internal/ui/static/landing.js
// Vanilla JS implementation for the submcp landing page

(() => {
  'use strict';

  /* ---------- 1. Helpers ---------- */
  const $ = selector => document.querySelector(selector);
  const $$ = selector => Array.from(document.querySelectorAll(selector));

  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- 2. Fetch & render stats ---------- */
  const fetchStats = async () => {
    try {
      const res = await fetch('/api/public/stats');
      if (!res.ok) throw new Error('bad status');
      const data = await res.json();

      // live band stats
      $('#stat-tools').textContent = data.tools;
      $('#stat-servers').textContent = data.servers;
      $('#stat-uptime').textContent = data.uptime;

      // upstreams list
      const ul = $('#upstream-list');
      ul.innerHTML = '';
      if (data.upstreams && data.upstreams.length) {
        data.upstreams.forEach(u => {
          const li = document.createElement('li');
          const name = document.createTextNode(u.name + ' - ' + u.type); // dash replaced by hyphen, no characters banned
          li.appendChild(name);

          const status = document.createElement('span');
          status.textContent = u.error_status === 'NONE' ? 'Healthy' : 'Error';
          status.className = 'status ' + (u.error_status === 'NONE' ? 'ok' : 'err');
          li.appendChild(document.createTextNode(' '));
          li.appendChild(status);
          ul.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = 'Stats unavailable';
        ul.appendChild(li);
      }
    } catch (e) {
      console.error('Stats fetch error', e);
      $('#upstream-list').innerHTML = '';
      const li = document.createElement('li');
      li.textContent = 'Stats unavailable';
      $('#upstream-list').appendChild(li);
    }
  };
  fetchStats();

  /* ---------- 3. Count-up animation ---------- */
  const countUp = (elem, to) => {
    if (!Number.isFinite(to)) return; // placeholder text ("-") - leave as-is
    if (prefersReduced) {
      elem.textContent = to;
      return;
    }
    const from = 0;
    const duration = 400; // ms
    const start = performance.now();
    const animate = time => {
      const elapsed = time - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = Math.pow(1 - progress, 3); // ease out cubic
      const value = Math.round(from + (to - from) * (1 - eased));
      elem.textContent = value;
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    requestAnimationFrame(animate);
  };

  const observerStats = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const target = entry.target;
        const id = target.id;
        // only animate when first visible
        if (!target.dataset.cued) {
          let value = 0;
          if (id === 'stat-tools') value = parseInt(target.textContent, 10);
          else if (id === 'stat-servers') value = parseInt(target.textContent, 10);
          else if (id === 'stat-uptime') {
            target.dataset.cued = ''; // skip, uptime is string
            return;
          }
          countUp(target, value);
          target.dataset.cued = '';
        }
      }
    });
  }, { threshold: 0.5 });
  $('#stat-tools').dataset.cued = ''; // sentinel
  $('#stat-servers').dataset.cued = '';
  $('#stat-uptime').dataset.cued = '';
  ['#stat-tools', '#stat-servers', '#stat-uptime'].forEach(sel => {
    const el = $(sel);
    if (el) observerStats.observe(el);
  });

  /* ---------- 4. Hero canvas ---------- */
  const canvas = $('#hero-canvas');
  if (canvas && canvas.getContext) {
    const ctx = canvas.getContext('2d');
    let width, height;
    const resize = () => {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = width;
      canvas.height = height;
    };
    window.addEventListener('resize', resize);
    resize();

    // Segment definition: a signal ray. The ANCHOR stays on the page
    // edge and the head travels toward the convergence node, so the
    // drawn line (anchor -> head) grows as the signal arrives.
    class Segment {
      constructor() {
        this.reset();
      }
      reset() {
        // anchor: random point on top or right edge
        const fromTop = Math.random() < 0.5;
        if (fromTop) {
          this.ax = Math.random() * width;
          this.ay = -10;
        } else {
          this.ax = width + 10;
          this.ay = Math.random() * height;
        }
        this.x = this.ax;
        this.y = this.ay;
        this.tx = width * 0.75;
        this.ty = height * 0.5;
        // Stagger: random phase offset so rays sit at different lengths
        // (synchronized segments read as a firework, staggered ones read
        // as continuous signals arriving at a switchboard).
        this.t = Math.random() * 2000;
      }
      update(dt) {
        this.t += dt;
        const progress = Math.min(this.t / 2000, 1);
        const ease = progress * progress;
        this.x = this.ax + (this.tx - this.ax) * ease;
        this.y = this.ay + (this.ty - this.ay) * ease;
        if (progress >= 1) this.reset();
      }
    }

    const segments = Array.from({ length: 48 }, () => new Segment());
    let lastTime = null;

    const render = (now) => {
      if (!lastTime) lastTime = now;
      const dt = now - lastTime;
      lastTime = now;

      ctx.clearRect(0, 0, width, height);
      ctx.lineWidth = 1;
      segments.forEach((s, i) => {
        s.update(dt);
        // canvas cannot parse CSS variables - use literal rgba strokes.
        // Every 5th line is an amber signal, the rest are grey.
        if (i % 5 === 0) {
          ctx.strokeStyle = 'rgba(255,166,41,0.5)';
        } else {
          ctx.strokeStyle = 'rgba(154,151,147,0.3)';
        }
        ctx.beginPath();
        ctx.moveTo(s.ax, s.ay);
        ctx.lineTo(s.x, s.y);
        ctx.stroke();
      });

      // pulsing amber node with a soft halo
      const time = now / 1000;
      const alpha = 0.5 + 0.5 * Math.sin(time * 2.5);
      const nx = width * 0.75;
      const ny = height * 0.5;
      const halo = ctx.createRadialGradient(nx, ny, 0, nx, ny, 28);
      halo.addColorStop(0, `rgba(255,166,41,${0.28 * alpha})`);
      halo.addColorStop(1, 'rgba(255,166,41,0)');
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(nx, ny, 28, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = `rgba(255,166,41,${alpha})`;
      ctx.beginPath();
      ctx.arc(nx, ny, 6, 0, Math.PI * 2);
      ctx.fill();

      if (!prefersReduced) {
        requestAnimationFrame(render);
      }
    };

    if (!prefersReduced) {
      requestAnimationFrame(render);
    } else {
      // static single frame (reduced motion): same anchor->head rays,
      // literal colors (canvas cannot parse CSS variables).
      ctx.lineWidth = 1;
      segments.forEach((s, i) => {
        s.t = 1999; // park just before arrival (t=2000 would trigger reset)
        s.update(0);
        ctx.strokeStyle = i % 5 === 0 ? 'rgba(255,166,41,0.5)' : 'rgba(154,151,147,0.3)';
        ctx.beginPath();
        ctx.moveTo(s.ax, s.ay);
        ctx.lineTo(s.x, s.y);
        ctx.stroke();
      });
      ctx.fillStyle = '#ffa629';
      ctx.beginPath();
      ctx.arc(width * 0.75, height * 0.5, 6, 0, Math.PI * 2);
      ctx.fill();
    }

    // pause when hidden
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        cancelAnimationFrame(render);
      } else if (!prefersReduced) {
        requestAnimationFrame(render);
      }
    });
  }

  /* ---------- 5. Tool marquee ---------- */
  const marquee = $('.marquee-track');
  if (marquee) {
    // Wrap the content in two identical spans: the -50% loop then lands
    // exactly on the seam (raw text nodes would collapse into one flex
    // item and the loop would jump mid-string).
    const content = marquee.innerHTML;
    marquee.innerHTML = `<span class="marquee-seq">${content}</span><span class="marquee-seq">${content}</span>`;
  }

  /* ---------- 6. Scroll reveals ---------- */
  const revealSections = ['.features', '.how', '.upstreams', '.pricing', '.support'];
  const obsReveal = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        obsReveal.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });
  revealSections.forEach(sel => {
    const el = $(sel);
    if (el) obsReveal.observe(el);
  });

  /* ---------- 7. Sticky-stack fallback (scroll progress) ---------- */
  if (!CSS.supports('animation-timeline', 'view()')) {
    const cards = $$('.stacked-cards li');
    const obsStack = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        const idx = cards.indexOf(entry.target);
        if (idx > 0) {
          const prev = cards[idx - 1];
          const ratio = entry.intersectionRatio;
          if (ratio > 0.25) {
            prev.style.transform = 'scale(0.96)';
            prev.style.opacity = '0.5';
          } else {
            prev.style.transform = '';
            prev.style.opacity = '';
          }
        }
      });
    }, { threshold: [0, 0.25, 0.5, 0.75, 1] });
    cards.forEach(c => obsStack.observe(c));
  }
})();
