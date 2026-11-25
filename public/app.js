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
  form?.addEventListener('submit', () => {
    const b = form.querySelector('[data-submit]');
    b.disabled = true; b.textContent = 'Verifying… please wait';
  });

  document.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    const input = document.getElementById(b.dataset.copy);
    try { await navigator.clipboard.writeText(input.value); } catch { input.select(); document.execCommand('copy'); }
    b.textContent = 'Copied ✓';
  }));
  document.querySelector('[data-print]')?.addEventListener('click', () => window.print());
});
