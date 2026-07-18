// ZeroDayBuddy dashboard JavaScript.
//
// Responsibilities:
//   1. Show a "saved" flash after successful HTMX PATCH requests (T2-3 U6).
//   2. Wire up Copy-to-clipboard for CLI command panels (T2-3 U5).
//   3. Parse scope YAML/JSON and transform manual project form (T3 follow-up).
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

  // -- Manual project form: scope file upload --
  // When a file is selected, read its contents into the textarea.
  document.body.addEventListener('change', function (evt) {
    var input = evt.target;
    if (!input || input.id !== 'scope-file-input') {
      return;
    }
    var file = input.files && input.files[0];
    if (!file) {
      return;
    }
    var textarea = document.getElementById('manual-scope');
    if (!textarea) {
      return;
    }
    var reader = new FileReader();
    reader.onload = function (e) {
      textarea.value = e.target.result;
    };
    reader.onerror = function () {
      showFormError('Failed to read file.');
    };
    reader.readAsText(file);
  });

  // -- Manual project form: parse scope before submit --
  // The form posts JSON to /api/projects. The _scope_raw field contains
  // YAML or JSON text. We parse it client-side (js-yaml is not loaded, so
  // we only support JSON here — for YAML we send raw and let server parse).
  // Actually, to keep it simple: we'll parse JSON if it looks like JSON,
  // otherwise assume YAML and encode the raw text for the server to parse.
  //
  // Better approach: htmx:configRequest to transform the body.
  document.body.addEventListener('htmx:configRequest', function (evt) {
    var form = evt.detail.elt;
    if (!form || form.id !== 'create-manual-form') {
      return;
    }
    var params = evt.detail.parameters;
    var scopeRaw = params._scope_raw;
    if (!scopeRaw) {
      return;
    }
    // Remove the raw field — we'll replace it with parsed scope
    delete params._scope_raw;

    // Try to parse as JSON first
    var scope = null;
    var trimmed = scopeRaw.trim();
    if (trimmed.startsWith('{')) {
      try {
        scope = JSON.parse(trimmed);
      } catch (e) {
        showFormError('Invalid JSON: ' + e.message);
        evt.preventDefault();
        return;
      }
    } else {
      // YAML: we need to parse it. Since we don't have a YAML library,
      // we'll send it to a server endpoint that parses and returns JSON,
      // OR we parse simple YAML ourselves for the common case.
      // For now: use a simple YAML parser for the subset we need.
      try {
        scope = parseSimpleYaml(trimmed);
      } catch (e) {
        showFormError('Invalid scope format: ' + e.message);
        evt.preventDefault();
        return;
      }
    }

    // Validate scope has in_scope
    if (!scope || !scope.in_scope || !Array.isArray(scope.in_scope) || scope.in_scope.length === 0) {
      showFormError('Scope must include at least one in_scope asset.');
      evt.preventDefault();
      return;
    }

    // Set the scope field
    params.scope = scope;
    // Ensure platform is set for manual projects
    params.platform = 'manual';
    hideFormError();
  });

  // -- HTMX success handling for manual form — redirect to new project --
  document.body.addEventListener('htmx:afterRequest', function (evt) {
    var form = evt.detail.elt;
    if (!form || form.id !== 'create-manual-form') {
      return;
    }
    if (evt.detail.successful) {
      var xhr = evt.detail.xhr;
      try {
        var project = JSON.parse(xhr.responseText);
        if (project && project.id) {
          window.location.href = '/projects/' + project.id;
          return;
        }
      } catch (e) {
        // Fall through to reload
      }
      // Fallback: reload the dashboard
      window.location.reload();
    }
  });

  // -- HTMX error handling for manual form --
  document.body.addEventListener('htmx:responseError', function (evt) {
    var form = evt.detail.elt;
    if (!form || form.id !== 'create-manual-form') {
      return;
    }
    var xhr = evt.detail.xhr;
    var msg = 'Request failed';
    if (xhr && xhr.responseText) {
      try {
        var resp = JSON.parse(xhr.responseText);
        msg = resp.error || resp.message || msg;
      } catch (e) {
        msg = xhr.responseText.substring(0, 200);
      }
    }
    showFormError(msg);
  });

  function showFormError(msg) {
    var el = document.getElementById('manual-form-error');
    if (el) {
      el.textContent = msg;
      el.style.display = 'block';
    }
  }

  function hideFormError() {
    var el = document.getElementById('manual-form-error');
    if (el) {
      el.style.display = 'none';
    }
  }

  // -- Simple YAML parser for scope documents --
  // Handles the subset of YAML we need: in_scope/out_of_scope arrays with
  // type/value objects. NOT a full YAML parser — just enough for scope files.
  function parseSimpleYaml(text) {
    var result = { in_scope: [], out_of_scope: [] };
    var lines = text.split('\n');
    var currentArray = null;
    var currentObj = null;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();

      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Top-level keys
      if (trimmed === 'in_scope:' || trimmed === 'in-scope:') {
        currentArray = result.in_scope;
        currentObj = null;
        continue;
      }
      if (trimmed === 'out_of_scope:' || trimmed === 'out-of-scope:') {
        currentArray = result.out_of_scope;
        currentObj = null;
        continue;
      }

      // Array item start
      if (trimmed.startsWith('- ')) {
        if (!currentArray) {
          throw new Error('Unexpected array item outside in_scope/out_of_scope');
        }
        currentObj = {};
        currentArray.push(currentObj);

        // Check for inline key: "- type: domain"
        var inlineContent = trimmed.substring(2).trim();
        if (inlineContent) {
          parseKeyValue(inlineContent, currentObj);
        }
        continue;
      }

      // Key-value pair inside current object
      if (currentObj && trimmed.includes(':')) {
        parseKeyValue(trimmed, currentObj);
      }
    }

    return result;
  }

  function parseKeyValue(line, obj) {
    var colonIdx = line.indexOf(':');
    if (colonIdx === -1) return;

    var key = line.substring(0, colonIdx).trim();
    var value = line.substring(colonIdx + 1).trim();

    // Remove quotes
    if ((value.startsWith("'") && value.endsWith("'")) ||
        (value.startsWith('"') && value.endsWith('"'))) {
      value = value.substring(1, value.length - 1);
    }

    obj[key] = value;
  }
})();
