// Replay tabs. Without JavaScript every panel stays visible.
(function () {
  document.documentElement.classList.remove('no-js');
  var tablist = document.querySelector('[role="tablist"]');
  if (!tablist) return;
  var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));

  function select(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
    });
    if (focus) tab.focus();
  }

  tabs.forEach(function (tab, i) {
    tab.addEventListener('click', function () { select(tab, false); });
    tab.addEventListener('keydown', function (e) {
      var next = null;
      if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
      if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
      if (e.key === 'Home') next = tabs[0];
      if (e.key === 'End') next = tabs[tabs.length - 1];
      if (next) { e.preventDefault(); select(next, true); }
    });
  });

  // Open the panel a link points at, e.g. #replay-elementary.
  function fromHash() {
    var id = location.hash.slice(1);
    var tab = tabs.filter(function (t) { return t.getAttribute('aria-controls') === id; })[0];
    if (tab) select(tab, false);
  }
  window.addEventListener('hashchange', fromHash);
  select(tabs[0], false);
  fromHash();
})();
