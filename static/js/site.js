// Adds a Copy button to every code block inside a post or page.
document.querySelectorAll('.prose .highlight pre, .prose > pre').forEach((pre) => {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'copy';
  btn.textContent = 'Copy';
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pre.innerText);
      btn.textContent = 'Copied';
    } catch {
      const range = document.createRange();
      range.selectNodeContents(pre);
      getSelection()?.removeAllRanges();
      getSelection()?.addRange(range);
      btn.textContent = 'Press Ctrl+C';
    }
    setTimeout(() => (btn.textContent = 'Copy'), 1500);
  });
  const wrap = document.createElement('div');
  wrap.className = 'code-wrap';
  pre.replaceWith(wrap);
  wrap.append(pre, btn);
});

// Visit counts from busuanzi. Full URL as Referer, else all views count as "/".
if (!['localhost', '127.0.0.1'].includes(location.hostname)) {
  const show = (el, n) => {
    if (!el || !n) return;
    el.querySelector('span').textContent = n.toLocaleString('en-US');
    el.hidden = false;
  };
  const cb = 'BusuanziCallback_' + Date.now();
  const s = document.createElement('script');
  window[cb] = (data) => {
    show(document.querySelector('.byline .views'), data?.page_pv);
    show(document.querySelector('.site-visits'), data?.site_pv);
    delete window[cb];
    s.remove();
  };
  s.referrerPolicy = 'no-referrer-when-downgrade';
  s.src = 'https://busuanzi.ibruce.info/busuanzi?jsonpCallback=' + cb;
  s.async = true;
  document.head.append(s);
}

// Hovering a note number lights up its note, and back.
document.querySelectorAll('.note-ref').forEach((ref) => {
  const note = ref.nextElementSibling;
  if (!note?.classList.contains('side')) return;
  const lit = (on) => { ref.classList.toggle('lit', on); note.classList.toggle('lit', on); };
  for (const el of [ref, note]) {
    el.addEventListener('mouseenter', () => lit(true));
    el.addEventListener('mouseleave', () => lit(false));
  }
});

// Draw the end fleuron on scroll.
const endMark = document.querySelector('.end-mark');
if (endMark && 'IntersectionObserver' in window) {
  endMark.classList.add('will-draw');
  new IntersectionObserver((entries, obs) => {
    if (!entries[0].isIntersecting) return;
    endMark.classList.add('drawn');
    obs.disconnect();
  }, { threshold: 0.6 }).observe(endMark);
}

// Contents list: open in the right column, mark the current section.
const toc = document.querySelector('.toc details');
if (toc) {
  const wide = matchMedia('(min-width: 861px)');
  const sync = () => { if (wide.matches) toc.open = true; };
  sync();
  wide.addEventListener('change', sync);

  const links = [...toc.querySelectorAll('a')];
  const heads = links.map((a) => document.getElementById(decodeURIComponent(a.hash.slice(1)))).filter(Boolean);
  const mark = () => {
    let current = heads[0];
    for (const h of heads) if (h.getBoundingClientRect().top < 120) current = h;
    // Last headings may never reach the top, so mark the last one at the page end
    if (innerHeight + scrollY >= document.documentElement.scrollHeight - 2) current = heads[heads.length - 1];
    links.forEach((a) => a.classList.toggle('active', a.hash === '#' + current.id));
  };
  addEventListener('scroll', mark, { passive: true });
  mark();
}
