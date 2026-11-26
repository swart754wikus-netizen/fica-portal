// No inline scripts: CSP is script-src 'self'.
document.addEventListener('DOMContentLoaded', () => {
  const toggle = (sel, show) => document.querySelectorAll(sel).forEach((el) => { el.hidden = !show; });
  const idType = () => document.querySelector('[name=idType]:checked')?.value;
  const pep = () => document.querySelector('[name=pepDeclared]:checked')?.value;
  document.querySelectorAll('[data-toggle-idtype]').forEach((r) => r.addEventListener('change', () => toggle('[data-passport-only]', idType() === 'passport')));
  document.querySelectorAll('[data-toggle-pep]').forEach((r) => r.addEventListener('change', () => toggle('[data-pep-only]', pep() === 'yes')));

  // Client type: show only the sections, options and documents for that type.
  const applyClientType = () => {
    const t = document.querySelector('[name=clientType]:checked')?.value || '';
    document.querySelectorAll('[data-for]').forEach((el) => {
      // Nothing chosen yet: preview the individual version; data-for="" hints show only then.
      const show = el.dataset.for === '' ? !t : el.dataset.for.split(' ').includes(t || 'individual');
      el.hidden = !show;
      if (el.tagName === 'OPTION') { el.disabled = !show; if (!show && el.selected) el.parentElement.value = ''; }
    });
    const title = document.querySelector('[data-entity-title]');
    if (title) title.textContent = { company: 'Company details', trust: 'Trust details', partnership: 'Partnership details' }[t] || 'Entity details';
    let n = 0;
    document.querySelectorAll('form fieldset').forEach((fs) => {
      const num = fs.querySelector('.step-num');
      if (num && !fs.hidden) num.textContent = ++n;
    });
  };
  document.querySelectorAll('[data-client-type]').forEach((r) => r.addEventListener('change', applyClientType));
  if (document.querySelector('[data-client-type]')) applyClientType();

  // "Add another person": clone the last row with the next index and empty values.
  document.querySelector('[data-add-related]')?.addEventListener('click', () => {
    const rows = document.querySelectorAll('[data-related-row]');
    if (rows.length >= 15) return;
    const clone = rows[rows.length - 1].cloneNode(true);
    const next = rows.length;
    clone.querySelectorAll('[name]').forEach((el) => {
      el.name = el.name.replace(/related\[\d+\]/, `related[${next}]`);
      if (el.type === 'checkbox') el.checked = false;
      else if (el.tagName === 'SELECT') el.selectedIndex = el.name.endsWith('[nationality]') ? [...el.options].findIndex((o) => o.value === 'ZA') : 0;
      else el.value = '';
      el.removeAttribute('aria-invalid');
    });
    clone.querySelectorAll('.field-error').forEach((e) => e.remove());
    rows[rows.length - 1].after(clone);
    clone.querySelector('input')?.focus();
  });

  document.querySelector('[data-focus]')?.focus();

  const form = document.querySelector('[data-submit]')?.form;
  const direct = form?.dataset.directUpload === '1';

  // Choosing a new file replaces any copy kept from an earlier attempt.
  form?.querySelectorAll('input[type=file]').forEach((input) => input.addEventListener('change', () => {
    form.querySelectorAll(`[data-kept="${input.name}"], [data-kept-note="${input.name}"]`).forEach((el) => el.remove());
  }));

  const showError = (msg) => {
    let box = form.querySelector('[data-upload-error]');
    if (!box) {
      box = Object.assign(document.createElement('div'), { className: 'callout error', role: 'alert' });
      box.dataset.uploadError = '';
      form.querySelector('.actions').before(box);
    }
    box.textContent = msg;
    box.scrollIntoView({ block: 'center' });
  };

  form?.addEventListener('submit', async (e) => {
    const b = form.querySelector('[data-submit]');
    if (!direct) { b.disabled = true; b.textContent = 'Verifying… please wait'; return; }
    // Production: upload each file straight to secure storage, then submit the form without them.
    e.preventDefault();
    const inputs = [...form.querySelectorAll('input[type=file]')].filter((i) => i.files.length && !i.closest('[hidden]'));
    const files = inputs.flatMap((input) => [...input.files].map((file) => ({ input, file })));
    const maxBytes = Number(form.dataset.maxMb) * 1024 * 1024;
    const bad = files.find(({ file }) => !['application/pdf', 'image/jpeg', 'image/png'].includes(file.type) || file.size > maxBytes);
    if (bad) return showError(`"${bad.file.name}" can't be used: only PDF, JPG or PNG files up to ${form.dataset.maxMb} MB are accepted.`);
    b.disabled = true;
    try {
      for (const [n, { input, file }] of files.entries()) {
        b.textContent = `Uploading ${n + 1} of ${files.length}…`;
        const r = await fetch(form.dataset.uploadUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ field: input.name, contentType: file.type, size: file.size }) });
        const slot = await r.json();
        if (!r.ok) throw new Error(slot.error || 'Upload could not start');
        const put = await fetch(slot.url, { method: 'PUT', headers: slot.headers, body: file });
        if (!put.ok) throw new Error(`Upload of "${file.name}" failed. Please check your connection and try again.`);
        form.append(Object.assign(document.createElement('input'), { type: 'hidden', name: `uploaded[${input.name}][]`, value: slot.uploadId }));
      }
      inputs.forEach((i) => { i.value = ''; });
      b.textContent = 'Verifying… please wait';
      HTMLFormElement.prototype.submit.call(form);
    } catch (err) {
      showError(err.message);
      b.disabled = false; b.textContent = 'Submit securely';
    }
  });

  document.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    const input = document.getElementById(b.dataset.copy);
    try { await navigator.clipboard.writeText(input.value); } catch { input.select(); document.execCommand('copy'); }
    b.textContent = 'Copied ✓';
  }));
  // Staff forms: lock buttons after the first submit so a double-click/Enter can't send twice.
  // (Deferred so the clicked button's name/value is still included in the submission.)
  document.querySelectorAll('form').forEach((f) => {
    if (f.dataset.directUpload !== undefined) return; // client form handles this itself
    f.addEventListener('submit', () => setTimeout(() => f.querySelectorAll('button').forEach((b) => { b.disabled = true; }), 0));
  });
  document.querySelector('[data-print]')?.addEventListener('click', () => window.print());

  // Generate a strong, easy-to-read temporary password (no look-alike characters).
  document.querySelectorAll('[data-generate-pw]').forEach((b) => b.addEventListener('click', () => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    const bytes = crypto.getRandomValues(new Uint32Array(15));
    const raw = Array.from(bytes, (n) => alphabet[n % alphabet.length]).join('');
    const input = b.closest('form').querySelector('[data-pw-target]');
    input.value = `${raw.slice(0, 5)}-${raw.slice(5, 10)}-${raw.slice(10)}`;
    input.select();
  }));
  document.querySelectorAll('[data-confirm]').forEach((b) => b.addEventListener('click', (e) => { if (!confirm(b.dataset.confirm)) e.preventDefault(); }));
});
