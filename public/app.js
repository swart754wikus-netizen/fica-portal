// No inline scripts: CSP is script-src 'self'.
document.addEventListener('DOMContentLoaded', () => {
  const toggle = (sel, show) => document.querySelectorAll(sel).forEach((el) => { el.hidden = !show; });
  const idType = () => document.querySelector('[name=idType]:checked')?.value;
  const pep = () => document.querySelector('[name=pepDeclared]:checked')?.value;
  document.querySelectorAll('[data-toggle-idtype]').forEach((r) => r.addEventListener('change', () => toggle('[data-passport-only]', idType() === 'passport')));
  document.querySelectorAll('[data-toggle-pep]').forEach((r) => r.addEventListener('change', () => toggle('[data-pep-only]', pep() === 'yes')));

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
