const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Deliberately contains no personal information beyond the first name: email is not a secure channel.
export function inviteEmail({ firmName, clientName, reference, link, expiresAt, logoUrl }) {
  const first = String(clientName).split(' ')[0];
  const expires = new Date(expiresAt).toLocaleString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Johannesburg' });
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

  const html = `<!doctype html><html><body style="margin:0;background:#F5F5F3;font-family:Roboto,Arial,sans-serif;color:#000000">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#fff;border-radius:12px;border:1px solid #DEDEDA">
<tr><td style="background:#3D3D3D;color:#fff;padding:18px 24px;border-radius:12px 12px 0 0;border-bottom:3px solid #7ABD98;font-family:'League Spartan',Roboto,Arial,sans-serif;font-weight:700;font-size:17px">${logoUrl ? `<img src="${esc(logoUrl)}" alt="${esc(firmName)}" height="40" style="display:block;height:40px;width:auto;border:0">` : esc(firmName)}</td></tr>
<tr><td style="padding:24px;font-size:15px;line-height:1.5;color:#000000">
<p style="margin-top:0">Hi ${esc(first)},</p>
<p>As required by the Financial Intelligence Centre Act (FICA), we must verify your identity before we can act for you. It takes about 5 minutes.</p>
<p style="text-align:center;margin:28px 0"><a href="${esc(link)}" style="background:#2D6A50;color:#fff;text-decoration:none;padding:14px 26px;border-radius:8px;font-weight:700;display:inline-block">Verify my identity</a></p>
<p style="font-size:14px;color:#3D3D3D">You'll need your ID document or passport, and a proof of address not older than 3 months.</p>
<p style="font-size:14px;color:#3D3D3D">This link is personal to you, can be used once, and expires on <strong>${esc(expires)}</strong>.</p>
<p style="font-size:13px;color:#3D3D3D;border-top:1px solid #DEDEDA;padding-top:16px;margin-bottom:0">We will never ask for your banking PIN or passwords. If you weren't expecting this email, contact us directly before clicking the link.<br>Reference: ${esc(reference)}</p>
</td></tr></table></td></tr></table></body></html>`;
  return { subject, text, html };
}
