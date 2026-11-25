const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Deliberately contains no personal information beyond the first name: email is not a secure channel.
export function inviteEmail({ firmName, clientName, reference, link, expiresAt }) {
  const first = String(clientName).split(' ')[0];
  const expires = new Date(expiresAt).toLocaleString('en-ZA', { dateStyle: 'long', timeStyle: 'short', timeZone: 'Africa/Johannesburg' });
  const subject = `${firmName}: please verify your identity (ref ${reference})`;
  const text = `Hi ${first},

As required by the Financial Intelligence Centre Act (FICA), ${firmName} must verify your identity before we can act for you.

Please complete your secure verification here (about 5 minutes):
${link}

You'll need your ID document or passport, and a proof of address not older than 3 months.

This link is personal to you, can be used once, and expires on ${expires}.

We will never ask for your banking PIN or passwords. If you weren't expecting this email, please contact us directly before clicking the link.

Reference: ${reference}
${firmName}`;

  const html = `<!doctype html><html><body style="margin:0;background:#f4f6fb;font-family:Segoe UI,Arial,sans-serif;color:#17203a">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#fff;border-radius:12px;border:1px solid #dfe4ef">
<tr><td style="background:#1b2a4e;color:#fff;padding:18px 24px;border-radius:12px 12px 0 0;font-weight:700">${esc(firmName)}</td></tr>
<tr><td style="padding:24px;font-size:16px;line-height:1.55">
<p style="margin-top:0">Hi ${esc(first)},</p>
<p>As required by the Financial Intelligence Centre Act (FICA), we must verify your identity before we can act for you. It takes about 5 minutes.</p>
<p style="text-align:center;margin:28px 0"><a href="${esc(link)}" style="background:#c62a3b;color:#fff;text-decoration:none;padding:14px 26px;border-radius:8px;font-weight:700;display:inline-block">Verify my identity</a></p>
<p style="font-size:14px;color:#5b6585">You'll need your ID document or passport, and a proof of address not older than 3 months.</p>
<p style="font-size:14px;color:#5b6585">This link is personal to you, can be used once, and expires on <strong>${esc(expires)}</strong>.</p>
<p style="font-size:13px;color:#5b6585;border-top:1px solid #dfe4ef;padding-top:16px;margin-bottom:0">We will never ask for your banking PIN or passwords. If you weren't expecting this email, contact us directly before clicking the link.<br>Reference: ${esc(reference)}</p>
</td></tr></table></td></tr></table></body></html>`;
  return { subject, text, html };
}
