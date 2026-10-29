// Mockup helper. The SF Symbol names in data-i are the design spec. The drawings here only approximate them.
const P = {
  'arrow.clockwise': '<path d="M13 8a5 5 0 1 1-1.7-3.8"/><path d="M13.2 2.6v3.2h-3.2"/>',
  'checkmark.circle': '<circle cx="8" cy="8" r="6"/><path d="M5.2 8.2l2 2 3.6-4"/>',
  'arrow.up.circle': '<circle cx="8" cy="8" r="6"/><path d="M8 11V5.4M5.8 7.5L8 5.3l2.2 2.2"/>',
  'exclamationmark.shield': '<path d="M8 1.8l5 1.8v4c0 3-2.2 5-5 6.4C5.2 12.6 3 10.6 3 7.6v-4z"/><path d="M8 5.4v3M8 10.5v.1"/>',
  'questionmark.circle': '<circle cx="8" cy="8" r="6"/><path d="M6.4 6.5a1.7 1.7 0 1 1 2.5 1.5c-.6.4-.9.7-.9 1.3M8 11.3v.1"/>',
  'exclamationmark.triangle': '<path d="M8 2.3l6 10.5H2z"/><path d="M8 6.6v3M8 11.1v.1"/>',
  'pin': '<path d="M9.6 2l4.4 4.4-1.7.6-2 2 .3 3-1 1-2.7-2.7L3 13.5M5.3 7.3l3.4-3.4"/>',
  'hand.raised': '<path d="M5 8.3V4.2a.9.9 0 0 1 1.8 0V7M6.8 7V3.2a.9.9 0 0 1 1.8 0V7M8.6 7V3.6a.9.9 0 0 1 1.8 0V8M10.4 8V5.6a.9.9 0 0 1 1.8 0v3.7c0 2.5-1.5 4.2-4 4.2-1.6 0-2.6-.8-3.4-2L3 8.7a.9.9 0 0 1 1.4-1.1z"/>',
  'checkmark.seal': '<path d="M8 1.6l1.6 1.2 2-.1.7 1.9 1.7 1.1-.6 1.9.6 1.9-1.7 1.1-.7 1.9-2-.1L8 14.4l-1.6-1.2-2 .1-.7-1.9-1.7-1.1.6-1.9-.6-1.9 1.7-1.1.7-1.9 2 .1z"/><path d="M5.4 8.2l1.9 1.9 3.4-3.9"/>',
  'xmark.octagon': '<path d="M5.3 2h5.4L14 5.3v5.4L10.7 14H5.3L2 10.7V5.3z"/><path d="M6 6l4 4M10 6l-4 4"/>',
  'arrow.triangle.2.circlepath': '<path d="M3 7a5 5 0 0 1 9-2M13 9a5 5 0 0 1-9 2"/><path d="M12.4 2v3h-3M3.6 14v-3h3"/>',
  'flame.fill': '<path d="M8 1.4c.6 2.3 3.7 3.9 3.7 7.3a3.7 3.7 0 0 1-7.4 0c0-1.5.6-2.5 1.4-3.2.1 1 .6 1.6 1.2 1.8C7.2 5.9 7.1 3.6 8 1.4z"/>',
  'exclamationmark.octagon.fill': '<path d="M5.3 1.8h5.4l3.8 3.8v4.8l-3.8 3.8H5.3L1.5 10.4V5.6z"/><path class="cut" d="M8 4.8v3.8M8 10.9v.1"/>',
  'exclamationmark.octagon': '<path d="M5.3 2h5.4L14 5.3v5.4L10.7 14H5.3L2 10.7V5.3z"/><path d="M8 4.8v3.8M8 10.9v.1"/>',
  'minus.circle': '<circle cx="8" cy="8" r="6"/><path d="M5.2 8h5.6"/>',
  'doc.on.doc': '<rect x="5.5" y="5.5" width="8" height="8" rx="1.6"/><path d="M10.5 5.5V4a1.6 1.6 0 0 0-1.6-1.6H4A1.6 1.6 0 0 0 2.4 4v4.9A1.6 1.6 0 0 0 4 10.5h1.5"/>',
  'magnifyingglass': '<circle cx="7" cy="7" r="4.4"/><path d="M10.4 10.4L14 14"/>',
  'stop.fill': '<rect x="3.5" y="3.5" width="9" height="9" rx="1.6"/>',
  'chevron.right': '<path d="M6 3.5L10.5 8 6 12.5"/>', 'chevron.down': '<path d="M3.5 6L8 10.5 12.5 6"/>',
  'square.grid.2x2': '<rect x="2.4" y="2.4" width="4.8" height="4.8" rx="1.2"/><rect x="8.8" y="2.4" width="4.8" height="4.8" rx="1.2"/><rect x="2.4" y="8.8" width="4.8" height="4.8" rx="1.2"/><rect x="8.8" y="8.8" width="4.8" height="4.8" rx="1.2"/>',
  'shippingbox': '<path d="M8 1.8l5.6 2.8v6.8L8 14.2 2.4 11.4V4.6zM2.6 4.7L8 7.5l5.4-2.8M8 7.5v6.6"/>',
  'folder': '<path d="M1.8 4.4a1.4 1.4 0 0 1 1.4-1.4h2.9l1.4 1.6h5.3a1.4 1.4 0 0 1 1.4 1.4v5.6a1.4 1.4 0 0 1-1.4 1.4H3.2a1.4 1.4 0 0 1-1.4-1.4z"/>',
  'tray': '<path d="M2 9.2l1.7-5.6a1 1 0 0 1 1-.7h6.6a1 1 0 0 1 1 .7L14 9.2v3a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1zM2 9.2h3.6a2.4 2.4 0 0 0 4.8 0H14"/>',
  'antenna.radiowaves.left.and.right': '<path d="M8 8.5V14M6.5 14h3"/><circle cx="8" cy="6.6" r="1.3"/><path d="M5.4 4.2a3.7 3.7 0 0 0 0 4.8M10.6 4.2a3.7 3.7 0 0 1 0 4.8M3.4 2.6a6.2 6.2 0 0 0 0 8M12.6 2.6a6.2 6.2 0 0 1 0 8"/>',
  'clock.arrow.circlepath': '<path d="M2.8 8a5.2 5.2 0 1 0 1.6-3.7"/><path d="M2.6 2.6v3h3M8 5v3.2l2 1.3"/>',
  'gearshape': '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.8v1.7M8 12.5v1.7M1.8 8h1.7M12.5 8h1.7M3.6 3.6l1.2 1.2M11.2 11.2l1.2 1.2M12.4 3.6l-1.2 1.2M4.8 11.2l-1.2 1.2"/>',
  'power': '<path d="M8 2v5.4M4.6 4.4a5 5 0 1 0 6.8 0"/>',
  'macwindow': '<rect x="1.8" y="2.8" width="12.4" height="10.4" rx="1.8"/><path d="M1.8 5.8h12.4"/>',
  'wrench': '<path d="M10.2 2.4a3.2 3.2 0 0 0-3 4.3L2.6 11.3a1.4 1.4 0 0 0 2 2l4.6-4.6a3.2 3.2 0 0 0 4.3-3l-2 1.8-1.8-.4-.4-1.8z"/>',
};
function sf(name, cls) {
  const fill = name.endsWith('.fill');
  return `<svg class="sf ${fill ? 'fill' : ''} ${cls || ''}" viewBox="0 0 16 16" role="img" aria-label="${name}">${P[name] || ''}</svg>`;
}
const T = { // StatusBadge, as in #5
  'Up to date': ['green', 'checkmark.circle'], 'Update available': ['blue', 'arrow.up.circle'],
  'Vulnerable': ['red', 'exclamationmark.shield'], 'Unknown': ['gray', 'questionmark.circle'],
  'Error': ['orange', 'exclamationmark.triangle'], 'Pinned': ['gray', 'pin'], 'Manual update': ['gray', 'hand.raised'],
  'Known exploited': ['solid-red', 'flame.fill'], 'Malware': ['solid-red', 'exclamationmark.octagon.fill'],
  'Withdrawn': ['gray', 'minus.circle'], 'High': ['red', 'exclamationmark.triangle'], 'Critical': ['red', 'exclamationmark.octagon'],
  'Medium': ['orange', 'exclamationmark.triangle'], 'Low': ['gray', 'minus.circle'], 'Open': ['red', 'exclamationmark.shield'],
};
function badge(text, label) { const [c, s] = T[text]; return `<span class="badge ${c}">${sf(s)}${label || text}</span>`; }
function fillIcons(root) {
  (root || document).querySelectorAll('i[data-i]').forEach(e => { e.outerHTML = sf(e.dataset.i, e.className); });
  (root || document).querySelectorAll('b[data-badge]').forEach(e => { e.outerHTML = badge(e.dataset.badge, e.dataset.label); });
}
const q = new URLSearchParams(location.search);
if (q.get('theme') === 'dark') document.documentElement.classList.add('dark');
document.addEventListener('DOMContentLoaded', () => fillIcons());

// Sidebar, as in #5 and #12. Order and shortcuts are fixed.
const NAV = [
  ['Inventory', [['Apps', 'square.grid.2x2', 14, '⌘1'], ['Homebrew', 'shippingbox', 3, '⌘2'], ['Projects', 'folder', 9, '⌘3']]],
  ['Review', [['Findings', 'exclamationmark.shield', 4, '⌘4', 'hot'], ['Backlog', 'tray', 2, '⌘5'], ['Incidents', 'antenna.radiowaves.left.and.right', 4, '⌘6']]],
  ['History', [['Update Log', 'clock.arrow.circlepath', null, '⌘7']]],
];
function sidebarHTML(active) {
  let h = '<div class="lights"><i></i><i></i><i></i></div>';
  for (const [g, items] of NAV) {
    h += `<div class="side-h">${g}</div>`;
    for (const [n, s, c, k, hot] of items)
      h += `<div class="side-i ${n === active ? 'sel' : ''}">${sf(s)}<span>${n}</span>${c != null && q.get('state') !== 'never' ? `<span class="n ${hot || ''}">${c}</span>` : ''}<span class="k">${k}</span></div>`;
  }
  h += `<div style="margin-top:auto" class="side-i">${sf('gearshape')}<span>Settings…</span><span class="k">⌘,</span></div>`;
  return h;
}
// Refresh label states, as in #5.
function refreshLabel(state) {
  const L = {
    complete: ['', 'Last refresh: 2 h ago'], stale: ['orange', 'Stale: last refresh Oct 27, 09:14'],
    partial: ['orange', 'Partial: 2 of 5 sources failed'], failed: ['red', 'Refresh failed. Showing data from Oct 28, 18:02'],
    never: ['', 'Never refreshed. Click Refresh.'], running: ['', 'Refreshing… 3 of 5 sources'],
  }[state];
  const lead = state === 'running' ? '<span class="spin"></span>' : (state === 'stale' || state === 'partial') ? sf('exclamationmark.triangle') : state === 'failed' ? sf('xmark.octagon') : '';
  return `<span class="rlabel ${L[0]}">${lead}${L[1]}</span>`;
}
function refreshButton(state) {
  return state === 'running' ? `<span class="tbtn">${sf('stop.fill')}Stop <span class="kbd">⌘.</span></span>` : `<span class="tbtn">${sf('arrow.clockwise')}Refresh <span class="kbd">⌘R</span></span>`;
}

// Page shell: sidebar, toolbar and body. opts: {active, title, tool, body, wide}
function mount(o) {
  document.body.innerHTML = `<div class="stage"><div class="window ${o.wide ? 'wide' : ''}"><div class="sidebar">${sidebarHTML(o.active)}</div>
    <div class="main"><div class="toolbar"><span class="title">${o.title}</span>${o.tool || ''}</div><div style="display:flex;flex:1;min-height:0">${o.body}</div></div></div></div>`;
  fillIcons();
}
const SEARCH = `<span class="search"><i data-i="magnifyingglass"></i>Search <span class="kbd" style="margin-left:auto">⌘F</span></span>`;
const ICOCOL = { a: '#6b5ce7', b: '#0f766e', c: '#c2410c', d: '#1f7ae0', e: '#7c3aed', f: '#475569' };
