// ZeroDayBuddy dashboard JavaScript.
//
// Two responsibilities:
//   1. Show a "saved" flash after successful HTMX PATCH requests (T2-3 U6).
//   2. Wire up Copy-to-clipboard for CLI command panels (T2-3 U5).
//
// Intentionally tiny. No external deps. Loaded after htmx.min.js and
// json-enc.js. CSP-clean — no inline scripts anywhere; this file is loaded
// via <script src=...> from the layout.

(function () {
  'use strict';

  // -- HTMX after-request: triage flash --
  // Triage controls (see _finding_row.tmpl) are <select> elements that fire
  // PATCH /api/findings/{id}. The matching flash <span data-triage-flash>
  // sits as the next sibling. Update its text + class on success/failure.
  document.body.addEventListener('htmx:afterRequest', function (evt) {
    var el = evt.target;
    if (!el || !el.matches('[hx-patch], [data-hx-patch]')) {
      return;
    }
    // Look for the flash inside the same <td> the select lives in. Falls
    // back to nextElementSibling for layouts that put the flash next to
    // the control directly.
    var flash = (el.parentElement && el.parentElement.querySelector('[data-triage-flash]'))
      || el.nextElementSibling;
    if (!flash) {
      return;
    }
    if (evt.detail.successful) {
      flash.textContent = '✓ saved';
      flash.classList.add('triage-flash-ok');
      flash.classList.remove('triage-flash-err');
      setTimeout(function () {
        flash.textContent = '';
        flash.classList.remove('triage-flash-ok');
      }, 2000);
    } else {
      var code = evt.detail.xhr ? evt.detail.xhr.status : '?';
      flash.textContent = '✗ ' + code;
      flash.classList.add('triage-flash-err');
      flash.classList.remove('triage-flash-ok');
    }
  });

  // -- Copy-to-clipboard for CLI command panels --
  // CLI panels render as:
  //   <pre><code data-clipboard>$ zerodaybuddy ...</code></pre>
  //   <button type="button" data-clipboard-target="prev">Copy</button>
  // The "prev" target means: walk back to the nearest <code data-clipboard>.
  document.body.addEventListener('click', function (evt) {
    var btn = evt.target;
    if (!btn || btn.tagName !== 'BUTTON' || !btn.dataset.clipboardTarget) {
      return;
    }
    var source = findClipboardSource(btn);
    if (!source) {
      return;
    }
    var text = source.textContent || '';
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      btn.textContent = '✗ clipboard unavailable';
      return;
    }
    navigator.clipboard.writeText(text).then(function () {
      var original = btn.textContent;
      btn.textContent = '✓ copied';
      setTimeout(function () { btn.textContent = original; }, 1500);
    }).catch(function (err) {
      console.error('Clipboard write failed:', err);
      btn.textContent = '✗ copy failed';
    });
  });

  // findClipboardSource walks the DOM looking for the nearest
  // <code data-clipboard>. The "prev" strategy walks the button's previous
  // siblings (and into <pre> wrappers) — works for the usual <pre><code>+
  // <button> layout the templates ship.
  function findClipboardSource(btn) {
    var sibling = btn.previousElementSibling;
    while (sibling) {
      var match = sibling.matches('[data-clipboard]')
        ? sibling
        : sibling.querySelector && sibling.querySelector('[data-clipboard]');
      if (match) {
        return match;
      }
      sibling = sibling.previousElementSibling;
    }
    // Fallback: the panel/section the button sits in.
    var section = btn.closest('section, .cli-panel');
    return section ? section.querySelector('[data-clipboard]') : null;
  }
})();
