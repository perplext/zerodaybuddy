// ZeroDayBuddy dashboard JavaScript.
//
// Two responsibilities:
//   1. Show a "saved" flash after successful HTMX PATCH requests (T2-3 D7 / U6).
//   2. Wire up Copy-to-clipboard buttons for CLI command panels (T2-3 D5 / U5).
//
// Intentionally tiny. No external deps. Loaded after htmx.min.js and
// htmx-ext-json-enc.js. CSP-clean — no inline scripts anywhere; this file
// is loaded via <script src=...> from the layout.

(function () {
  'use strict';

  // -- HTMX after-request: success flash --
  document.body.addEventListener('htmx:afterRequest', function (evt) {
    var form = evt.target;
    if (!form || form.tagName !== 'FORM') {
      return;
    }
    var indicator = form.querySelector('.saved-indicator');
    if (!indicator) {
      return;
    }
    if (evt.detail.successful) {
      indicator.textContent = '✓ saved';
      indicator.classList.add('visible');
      indicator.classList.remove('banner-error');
      setTimeout(function () {
        indicator.classList.remove('visible');
      }, 2000);
    } else {
      indicator.textContent = '✗ ' + (evt.detail.xhr.statusText || 'error');
      indicator.classList.add('visible');
      indicator.classList.add('banner-error');
    }
  });

  // -- Copy-to-clipboard for CLI command panels --
  document.body.addEventListener('click', function (evt) {
    var btn = evt.target;
    if (!btn || btn.tagName !== 'BUTTON' || !btn.classList.contains('copy')) {
      return;
    }
    var cmd = btn.dataset.copy;
    if (!cmd) {
      return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(cmd).then(function () {
        var original = btn.textContent;
        btn.textContent = '✓ copied';
        setTimeout(function () {
          btn.textContent = original;
        }, 1500);
      }).catch(function (err) {
        console.error('Clipboard write failed:', err);
        btn.textContent = '✗ copy failed';
      });
    } else {
      btn.textContent = '✗ clipboard unavailable';
    }
  });
})();
