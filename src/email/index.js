import nodemailer from 'nodemailer';
import { inviteEmail } from './templates.js';

/**
 * Mailer contract: { delivers: boolean, async send({ to, subject, text, html }) }
 *  - "log":  development only. Prints to the server console; staff see the link on screen instead.
 *  - "smtp": any SMTP relay — Microsoft 365, Google Workspace, Amazon SES, Postmark, SendGrid, etc.
 */
export function getMailer(config) {
  const m = config.mail;
  switch (m.transport) {
    case 'log':
      return {
        delivers: false,
        async send(msg) { console.log(`[mail:log] to=${msg.to} subject="${msg.subject}"\n${msg.text}\n`); },
      };
    case 'smtp': {
      if (!m.host || !m.from) throw new Error('MAIL_TRANSPORT=smtp needs SMTP_HOST and MAIL_FROM');
      const transport = nodemailer.createTransport({
        host: m.host,
        port: m.port,
        secure: m.port === 465,          // implicit TLS on 465, STARTTLS otherwise
        requireTLS: m.port !== 465,      // never send client invites over plaintext
        auth: m.user ? { user: m.user, pass: m.pass } : undefined,
        tls: { minVersion: 'TLSv1.2' },
      });
      return { delivers: true, send: (msg) => transport.sendMail({ from: m.from, ...msg }) };
    }
    default:
      throw new Error(`Unknown MAIL_TRANSPORT "${m.transport}" (use "log" or "smtp")`);
  }
}

export async function sendInvite(mailer, config, { to, clientName, reference, link, expiresAt }) {
  return mailer.send({ to, ...inviteEmail({ firmName: config.firmName, clientName, reference, link, expiresAt }) });
}
