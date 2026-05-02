// ── Theme toggle ──
(function () {
  var saved = localStorage.getItem('nevelio-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  document.addEventListener('DOMContentLoaded', function () {
    updateBtn(saved);
  });
})();

function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme');
  var next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('nevelio-theme', next);
  updateBtn(next);
}

function updateBtn(theme) {
  var btn = document.getElementById('theme-btn');
  if (btn) btn.textContent = theme === 'dark' ? '☀ Light' : '🌙 Dark';
}

// ── Findings accordion ──
function toggle(header) {
  var body = header.nextElementSibling;
  var icon = header.querySelector('.toggle-icon');
  if (body.classList.contains('open')) {
    body.classList.remove('open');
    icon.style.transform = 'rotate(0deg)';
  } else {
    body.classList.add('open');
    icon.style.transform = 'rotate(180deg)';
  }
}

// ── Severity filter + search ──
var activeFilter = 'all';

function setFilter(f) {
  activeFilter = f;
  document.querySelectorAll('.btn').forEach(function (b) {
    b.classList.remove('active');
  });
  var btn = document.getElementById('btn-' + f);
  if (btn) btn.classList.add('active');
  applyFilters();
}

function applyFilters() {
  var q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.finding').forEach(function (el) {
    var matchSev = activeFilter === 'all' || el.dataset.severity === activeFilter;
    var matchQ = !q || (
      el.dataset.title.includes(q) ||
      el.dataset.endpoint.includes(q) ||
      el.dataset.module.includes(q)
    );
    el.classList.toggle('hidden', !(matchSev && matchQ));
  });
}
