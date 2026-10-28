const DB_BINDING = "sos_db";

async function hashPassword(password) {
  if (!password) return null;

  const bytes = new TextEncoder().encode(password);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes
  );

  return Array.from(new Uint8Array(digest))
    .map(byte =>
      byte.toString(16).padStart(2, "0")
    )
    .join("");
}

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEY_BITS = 256;
const PBKDF2_SALT_BYTES = 16;

function bufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function derivePkdf2Key(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  return crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS
    },
    keyMaterial,
    PBKDF2_KEY_BITS
  );
}

async function hashPasswordPkdf2(password) {
  const salt = new Uint8Array(PBKDF2_SALT_BYTES);
  crypto.getRandomValues(salt);

  const hash = await derivePkdf2Key(password, salt);

  return [
    "pbkdf2",
    "SHA256",
    String(PBKDF2_ITERATIONS),
    bufferToBase64(salt),
    bufferToBase64(hash)
  ].join("$");
}

async function verifyPasswordPkdf2(password, encoded) {
  if (!encoded || typeof encoded !== "string") {
    return false;
  }

  if (!encoded.startsWith("pbkdf2$")) {
    return false;
  }

  const parts = encoded.split("$");

  if (parts.length !== 5 || parts[1] !== "SHA256") {
    return false;
  }

  const iterations = Number(parts[2]);

  if (!Number.isInteger(iterations) || iterations < 10000) {
    return false;
  }

  let salt;
  let expected;

  try {
    salt = base64ToBuffer(parts[3]);
    expected = base64ToBuffer(parts[4]);
  } catch {
    return false;
  }

  const hash = await derivePkdf2Key(password, salt);

  const expectedBytes = new Uint8Array(expected);
  const actualBytes = new Uint8Array(hash);

  if (expectedBytes.length !== actualBytes.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < actualBytes.length; i++) {
    diff |= actualBytes[i] ^ expectedBytes[i];
  }

  return diff === 0;
}


function getDb(env) {
  return env[DB_BINDING];
}


const AUTH_UNAUTHENTICATED = "AUTH_UNAUTHENTICATED";
const AUTH_FORBIDDEN = "AUTH_FORBIDDEN";
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours


async function extractBearerToken(request) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}


async function requireAdminAuth(request, db) {
  const token = await extractBearerToken(request);

  if (!token) {
    const error = new Error("Authentication required.");
    error.code = AUTH_UNAUTHENTICATED;
    throw error;
  }

  const session =
    await db.prepare(`
      SELECT
        s.id AS session_id,
        s.user_id,
        s.expires_at,
        u.role,
        u.status,
        u.email,
        u.full_name
      FROM admin_sessions s
      JOIN user_accounts u
        ON u.id = s.user_id
      WHERE s.token = ?
      LIMIT 1
    `)
    .bind(token)
    .first();

  if (!session) {
    const error = new Error("Authentication required.");
    error.code = AUTH_UNAUTHENTICATED;
    throw error;
  }

  if (new Date(session.expires_at).getTime() < Date.now()) {
    const error = new Error("Authentication required.");
    error.code = AUTH_UNAUTHENTICATED;
    throw error;
  }

  if (session.role !== "admin" || session.status !== "active") {
    const error = new Error("Access denied.");
    error.code = AUTH_FORBIDDEN;
    throw error;
  }

  return {
    session_id: session.session_id,
    id: session.user_id,
    role: session.role,
    email: session.email,
    full_name: session.full_name
  };
}


function json(data, headers, status = 200) {
  return Response.json(data, {
    status,
    headers
  });
}


function normalizeStatus(status) {

  const value =
    String(status || "").toLowerCase();

  if (
    ![
      "pending",
      "approved",
      "rejected"
    ].includes(value)
  ) {
    throw new Error("Invalid status");
  }

  return value;
}


function isValidPhone(phone) {

  return (
    !phone ||
    /^\+?[0-9\s().-]{7,20}$/.test(
      String(phone).trim()
    )
  );
}


function isValidEmail(email) {
  return /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(String(email || '').trim());
}

function getPasswordStrength(password) {
  if (!password) return 'none';
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const metCount = [hasLower, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;
  if (password.length >= 8 && metCount >= 4) return 'strong';
  if (password.length >= 8 && metCount >= 3) return 'medium';
  return 'weak';
}

function isValidPassword(password) {
  if (!password || password.length < 8) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[^A-Za-z0-9]/.test(password)) return false;
  return password.length <= 50;
}


function validateMessage(message) {

  if (!message || !message.trim()) return;

  const length =
    String(message || "").trim().length;

  if (length < 10) {
    throw new Error(
      "Message must be at least 10 characters."
    );
  }

  if (length > 1000) {
    throw new Error(
      "Message must be 1000 characters or fewer."
    );
  }
}


function amountToDollars(amount) {

  if (
    amount === undefined ||
    amount === null
  ) {
    throw new Error(
      "Donation amount is required."
    );
  }

  const text =
    String(amount).trim();

  if (!/^\d+(\.\d{1,2})?$/.test(text)) {
    throw new Error(
      "Donation amount must be a positive monetary value."
    );
  }

  const dollars =
    Number(text);

  if (!Number.isFinite(dollars) || dollars <= 0) {
    throw new Error(
      "Donation amount must be a positive monetary value."
    );
  }

  return dollars;
}


function isValidDonationName(fullName) {
  return (
    fullName.length >= 2 &&
    fullName.length <= 50 &&
    /^[\p{L}\p{M}][\p{L}\p{M}' -]*[\p{L}\p{M}]$/u.test(fullName)
  );
}


function isValidDonationEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}



function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}


async function sendDonationVerifiedEmail(env, donation) {
  const dollars = Number(donation.amount_dollars).toFixed(2);
  return sendResendEmail(env, {
    to: donation.email,
    subject: "Donation Verified — Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(donation.full_name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for your generous donation of <strong>$' + escapeHtml(dollars) + '</strong> to Seeds of Success!</p>',
      '<p style="color:#333;line-height:1.7">Phone Number: ' + escapeHtml(donation.phone_number || "Not provided") + '</p>',
      '<p style="color:#333;line-height:1.7">We have verified your payment and your donation has been recorded. Your support helps us connect Tamil-origin tutors with rural children in Tamil Nadu.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Seeds of Success is a U.S. 501(c)(3) nonprofit. EIN 41-3701713.</p>',
      '</div>'
    ].join('')
  });
}


async function sendDonationRejectedEmail(env, donation) {
  const dollars = Number(donation.amount_dollars).toFixed(2);
  return sendResendEmail(env, {
    to: donation.email,
    subject: "Donation Update — Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(donation.full_name) + ',</p>',
      '<p style="color:#333;line-height:1.7">We are writing regarding your donation of <strong>$' + escapeHtml(dollars) + '</strong> to Seeds of Success.</p>',
      '<p style="color:#333;line-height:1.7">Unfortunately, we were unable to verify the payment for this donation. If you believe this is an error, or if you would like to try again, please contact us at <a href="mailto:contact@soslearn.org">contact@soslearn.org</a>.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Seeds of Success is a U.S. 501(c)(3) nonprofit. EIN 41-3701713.</p>',
      '</div>'
    ].join('')
  });
}


async function sendDonationNotificationEmail(env, donation) {
  const recipient = env.DONATION_RECIPIENT_EMAIL;

  if (!recipient) {
    throw new Error("Donation notification recipient email not configured.");
  }

  const dollars = Number(donation.amount_dollars).toFixed(2);
  return sendResendEmail(env, {
    to: recipient,
    replyTo: donation.email,
    subject: "New Donation Submission — Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<h2 style="color:#0d6e4f">New Donation Submission</h2>',
      '<p style="color:#555;line-height:1.6">A new donation has been submitted to Seeds of Success.</p>',
      '<table style="width:100%;border-collapse:collapse">',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Full Name</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(donation.full_name) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(donation.email) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Phone Number</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(donation.phone_number || "Not provided") + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Amount</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">$' + escapeHtml(dollars) + '</td></tr>',
      '</table>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success donation form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendContactStoredEmail(env, { name, email, subject, message }) {
  const recipient = env.CONTACT_RECIPIENT_EMAIL;

  if (!recipient) {
    throw new Error("Contact recipient email not configured.");
  }

  return sendResendEmail(env, {
    to: recipient,
    replyTo: email,
    subject: "[Contact Form] " + subject,
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<h2 style="color:#0d6e4f">New Contact Form Submission</h2>',
      '<table style="width:100%;border-collapse:collapse">',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Name</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(name) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(email) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Subject</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(subject) + '</td></tr>',
      '</table>',
      '<h3 style="color:#0d6e4f;margin-top:24px">Message</h3>',
      '<p style="background:#f5faf8;padding:16px;border-radius:8px;line-height:1.7;white-space:pre-wrap">' + escapeHtml(message) + '</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success contact form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendResendEmail(
  env,
  { to, replyTo, subject, html }
) {
  const apiKey = env.RESEND_API_KEY;

  if (!apiKey) {
    throw new Error("Resend API key not configured.");
  }

const fromAddress =
  env.EMAIL_FROM_ADDRESS || "Seeds of Success <noreply@soslearn.org>";

const response = await fetch(
  "https://api.resend.com/emails",
  {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: fromAddress,
      to: Array.isArray(to) ? to : [to],
      reply_to: replyTo,
      subject,
      html
    })
  }
);

  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `Resend API error (${response.status}): ${body}`
    );
  }

  return response.json();
}


async function sendVolunteerNotificationEmail(env, application) {
  const recipient = env.VOLUNTEER_NOTIFICATION_EMAIL;

  if (!recipient) {
    throw new Error("Volunteer notification recipient email not configured.");
  }

  return sendResendEmail(env, {
    to: recipient,
    replyTo: application.email,
    subject: "New Volunteer Registration - Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<h2 style="color:#0d6e4f">New Volunteer Registration</h2>',
      '<p style="color:#555;line-height:1.6">A new volunteer has submitted an application to Seeds of Success.</p>',
      '<table style="width:100%;border-collapse:collapse">',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Full Name</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.full_name) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.email) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Phone</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.phone || "") + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Role of Interest</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.role || "") + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Skills / Languages</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.skills || "") + '</td></tr>',
      '</table>',
      '<h3 style="color:#0d6e4f;margin-top:24px">Why They Want to Volunteer</h3>',
      '<p style="background:#f5faf8;padding:16px;border-radius:8px;line-height:1.7;white-space:pre-wrap">' + escapeHtml(application.message) + '</p>',
'<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success volunteer registration form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendContactConfirmationEmail(env, { name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Thank You for Contacting Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for contacting Seeds of Success!</p>',
      '<p style="color:#333;line-height:1.7">We have successfully received your message. Our team will review it and get back to you as soon as possible.</p>',
      '<p style="color:#333;line-height:1.7">We appreciate you reaching out and your interest in Seeds of Success.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success contact form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendVolunteerConfirmationEmail(env, { name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Volunteer Registration Received \u2013 Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for registering as a volunteer with Seeds of Success!</p>',
      '<p style="color:#333;line-height:1.7">We have successfully received your volunteer application. Our team will review your application and get back to you if any further information is required.</p>',
      '<p style="color:#333;line-height:1.7">We appreciate your interest in supporting Seeds of Success and making a difference.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success volunteer registration form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendVolunteerApprovalEmail(env, { full_name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Volunteer Application Approved — Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(full_name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Great news! Your volunteer application to Seeds of Success has been <strong>approved</strong>.</p>',
      '<p style="color:#333;line-height:1.7">We are thrilled to have you join our team. You can now log in to the volunteer dashboard to get started.</p>',
      '<p style="color:#333;line-height:1.7">If you have any questions, please don\'t hesitate to reach out to us at <a href="mailto:contact@soslearn.org">contact@soslearn.org</a>.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success volunteer registration form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendVolunteerRejectionEmail(env, { full_name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Volunteer Application Update — Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(full_name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for applying to volunteer with Seeds of Success. We appreciate your interest in our mission.</p>',
      '<p style="color:#333;line-height:1.7">After careful review, we regret to inform you that we are unable to move forward with your application at this time. We encourage you to apply again in the future.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success volunteer registration form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendTutorNotificationEmail(env, application) {
  const recipient = env.VOLUNTEER_NOTIFICATION_EMAIL;

  if (!recipient) {
    throw new Error("Tutor notification recipient email not configured.");
  }

  return sendResendEmail(env, {
    to: recipient,
    replyTo: application.email,
    subject: "New Tutor Application - Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<h2 style="color:#0d6e4f">New Tutor Application</h2>',
      '<p style="color:#555;line-height:1.6">A new tutor has submitted an application to Seeds of Success.</p>',
      '<table style="width:100%;border-collapse:collapse">',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Full Name</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.full_name) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.email) + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Phone</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.phone || "") + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Skills / Languages</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.skills || "") + '</td></tr>',
      '<tr><td style="padding:8px 12px;font-weight:600;color:#0d6e4f;border-bottom:1px solid #e6efeb">Availability</td><td style="padding:8px 12px;border-bottom:1px solid #e6efeb">' + escapeHtml(application.availability || "") + '</td></tr>',
      '</table>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success tutor application form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendTutorConfirmationEmail(env, { name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Tutor Application Received \u2013 Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for applying as a tutor with Seeds of Success!</p>',
      '<p style="color:#333;line-height:1.7">We have successfully received your tutor application. Our team will review your application and contact you regarding next steps.</p>',
      '<p style="color:#333;line-height:1.7">We appreciate your interest in supporting Seeds of Success and making a difference.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success tutor application form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendTutorApprovalEmail(env, { full_name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Tutor Application Approved — Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(full_name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Great news! Your tutor application to Seeds of Success has been <strong>approved</strong>.</p>',
      '<p style="color:#333;line-height:1.7">We are excited to have you on our team. You can now log in to the tutor dashboard to get started.</p>',
      '<p style="color:#333;line-height:1.7">If you have any questions, please don\'t hesitate to reach out to us at <a href="mailto:contact@soslearn.org">contact@soslearn.org</a>.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success tutor application form.</p>',
      '</div>'
    ].join('')
  });
}


async function sendTutorRejectionEmail(env, { full_name, email }) {
  return sendResendEmail(env, {
    to: email,
    subject: "Tutor Application Update — Seeds of Success",
    html: [
      '<div style="font-family:sans-serif;max-width:600px">',
      '<p style="color:#333;line-height:1.7">Hi ' + escapeHtml(full_name) + ',</p>',
      '<p style="color:#333;line-height:1.7">Thank you for applying to be a tutor with Seeds of Success. We appreciate your interest in supporting our mission.</p>',
      '<p style="color:#333;line-height:1.7">After careful review, we regret to inform you that we are unable to move forward with your application at this time. We encourage you to apply again in the future.</p>',
      '<p style="color:#333;line-height:1.7">Best regards,</p>',
      '<p style="color:#0d6e4f;font-weight:600">Seeds of Success Team</p>',
      '<hr style="border:none;border-top:1px solid #e6efeb;margin-top:24px">',
      '<p style="font-size:12px;color:#888">Sent via the Seeds of Success tutor application form.</p>',
      '</div>'
    ].join('')
  });
}


/* =========================================================
   STUDENT MAPPING
========================================================= */
function mapStudent(row) {

  const topics =
    row.topic_names
      ? row.topic_names
          .split("||")
          .filter(Boolean)
      : [];


  const topicScores =
    row.topic_scores
      ? row.topic_scores
          .split("||")
          .map(Number)
          .filter(Number.isFinite)
      : [];


  const completedTopics =
    Number(row.completed_topics || 0);


  const totalTopics =
    Number(row.total_topics || 0);


  const progress =
    totalTopics
      ? Math.round(
          (completedTopics / totalTopics) * 100
        )
      : 0;


  const averageMarks =
    topicScores.length
      ? Math.round(
          topicScores.reduce(
            (sum, score) => sum + score,
            0
          ) / topicScores.length
        )
      : 0;


  return {

    id: row.id,

    full_name: row.full_name,

    grade: row.grade,

    school: row.school,

    status: row.status,

    tutor_id: row.tutor_id,

    tutor_name: row.tutor_name,

    completed_sessions:
      Number(row.completed_sessions || 0),

    total_topics:
      totalTopics,

    completed_topics:
      completedTopics,

    progress,

    average_marks:
      averageMarks,

    completed_topic_names:
      topics,

    topic_scores:
      topicScores
  };
}



/* =========================================================
   GET STUDENTS
========================================================= */

async function getStudents(db) {

  const result =
    await db.prepare(`
      SELECT

        s.id,
        s.full_name,
        s.grade,
        s.school,
        s.status,

        ua.id AS tutor_id,
        ua.full_name AS tutor_name,

        COUNT(
          DISTINCT CASE
            WHEN ts.status = 'completed'
            THEN ts.id
          END
        ) AS completed_sessions,

        COUNT(
          DISTINCT st.id
        ) AS total_topics,

        COUNT(
          DISTINCT CASE
            WHEN st.completed_at IS NOT NULL
            THEN st.id
          END
        ) AS completed_topics,

        GROUP_CONCAT(
          CASE
            WHEN st.completed_at IS NOT NULL
            THEN st.topic_name
          END,
          '||'
        ) AS topic_names,

        GROUP_CONCAT(
          CASE
            WHEN st.completed_at IS NOT NULL
            THEN st.score
          END,
          '||'
        ) AS topic_scores

      FROM students s

      LEFT JOIN student_assignments sa
        ON sa.student_id = s.id
        AND sa.status = 'active'

      LEFT JOIN user_accounts ua
        ON ua.id = sa.tutor_id

      LEFT JOIN student_topics st
        ON st.student_id = s.id

      LEFT JOIN tutoring_sessions ts
        ON ts.student_id = s.id

      GROUP BY s.id

      ORDER BY s.full_name
    `).all();


  return (result.results || [])
    .map(mapStudent);
}



/* =========================================================
   GET TUTORS
========================================================= */

async function getTutors(db) {

  const result =
    await db.prepare(`
      SELECT

        ua.id,
        ua.full_name,
        ua.email,
        ua.phone,
        ua.status,

        COUNT(
          sa.student_id
        ) AS assigned_students

      FROM user_accounts ua

      LEFT JOIN student_assignments sa

        ON sa.tutor_id = ua.id

        AND sa.status = 'active'

      WHERE ua.role = 'tutor'

      GROUP BY ua.id

      ORDER BY ua.full_name
    `).all();


  return (result.results || []).map(row => ({

    id: row.id,

    full_name: row.full_name,

    email: row.email,

    phone: row.phone,

    status: row.status,

    assigned_students:
      Number(row.assigned_students || 0)

  }));
}



/* =========================================================
   GET VOLUNTEERS
========================================================= */

async function getVolunteers(db) {

  const result =
    await db.prepare(`
      SELECT

        ua.id,
        ua.full_name,
        ua.email,
        ua.phone,
        ua.status,
        ua.notification_message,

        vt.task_title AS current_task

      FROM user_accounts ua

      LEFT JOIN volunteer_tasks vt

        ON vt.volunteer_id = ua.id

        AND vt.status = 'open'

      WHERE ua.role = 'volunteer'

      ORDER BY ua.full_name
    `).all();


  return result.results || [];
}



/* =========================================================
   REPORTS
========================================================= */

async function getReports(db) {

  const students =
    await getStudents(db);


  const completedSessions =
    students.reduce(
      (sum, student) =>
        sum + student.completed_sessions,
      0
    );


  const averageProgress =
    students.length

      ? Math.round(

          students.reduce(
            (sum, student) =>
              sum + student.progress,
            0
          ) / students.length

        )

      : 0;


  const scoredStudents =
    students.filter(
      student =>
        student.average_marks > 0
    );


  const averageMarks =
    scoredStudents.length

      ? Math.round(

          scoredStudents.reduce(
            (sum, student) =>
              sum + student.average_marks,
            0
          ) / scoredStudents.length

        )

      : 0;


  const activePairs =
    students.filter(
      student =>
        student.tutor_id
    ).length;


  return {

    total_completed_sessions:
      completedSessions,

    average_student_progress:
      averageProgress,

    average_marks:
      averageMarks,

    active_tutor_student_pairs:
      activePairs,

    unassigned_students:
      students.length - activePairs,

    students
  };
}



/* =========================================================
   CREATE USER AFTER APPROVAL
========================================================= */

async function createOrUpdateUserFromApplication(
  db,
  application,
  role,
  statusMessage,
  now
) {

  const existingUser =

    await db.prepare(`
      SELECT id

      FROM user_accounts

      WHERE email = ?
    `)

    .bind(application.email)

    .first();


  if (existingUser?.id) {

    await db.prepare(`
      UPDATE user_accounts

      SET

        full_name = ?,

        phone = ?,

        role = ?,

        status = ?,

        notification_message = ?,

        updated_at = ?

      WHERE id = ?
    `)

    .bind(

      application.full_name,

      application.phone || "",

      role,

      "active",

      statusMessage,

      now,

      existingUser.id

    )

    .run();


    return existingUser.id;
  }


  const userId =
    crypto.randomUUID();


  await db.prepare(`
    INSERT INTO user_accounts (

      id,

      full_name,

      email,

      phone,

      role,

      password_hash,

      status,

      notification_message,

      created_at,

      updated_at

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

  `)

  .bind(

    userId,

    application.full_name,

    application.email,

    application.phone || "",

    role,

    application.password_hash || null,

    "active",

    statusMessage,

    now,

    now

  )

  .run();


  return userId;
}



/* =========================================================
   CLOUDFLARE WORKER
========================================================= */

export default {

  async fetch(request, env) {


    const corsHeaders = {

      "Access-Control-Allow-Origin": "*",

      "Access-Control-Allow-Methods":
        "GET, POST, PATCH, DELETE, OPTIONS",

      "Access-Control-Allow-Headers":
        "Content-Type, Authorization"
    };


    if (request.method === "OPTIONS") {

      return new Response(
        null,
        {
          headers: corsHeaders
        }
      );
    }


    const url =
      new URL(request.url);


    const db =
      getDb(env);



    try {


      /* =====================================================
         ADMIN LOGIN
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/login"

        &&

        request.method === "POST"

      ) {

        const data =
          await request.json();

        const email =
          String(data.email || "").trim()
            .toLowerCase();

        const password =
          String(data.password || "");

        if (!email || !password) {

          return json(

            {

              success: false,

              error:
                "Invalid email or password."

            },

            corsHeaders,

            401
          );
        }

        const account =

          await db.prepare(`
            SELECT
              id,
              full_name,
              email,
              role,
              status,
              password_hash
            FROM user_accounts
            WHERE email = ?
            LIMIT 1
          `)

          .bind(email)

          .first();

        if (
          !account
          ||
          account.role !== "admin"
          ||
          account.status !== "active"
        ) {

          return json(

            {

              success: false,

              error:
                "Invalid email or password."

            },

            corsHeaders,

            401
          );
        }

        const valid =

          await verifyPasswordPkdf2(
            password,
            account.password_hash
          );

        if (!valid) {

          return json(

            {

              success: false,

              error:
                "Invalid email or password."

            },

            corsHeaders,

            401
          );
        }

        const token =
          crypto.randomUUID();

        const sessionId =
          crypto.randomUUID();

        const now =
          new Date().toISOString();

        const expiresAt =
          new Date(
            Date.now() + SESSION_TTL_MS
          ).toISOString();

        await db.prepare(`
          INSERT INTO admin_sessions (
            id,
            user_id,
            token,
            created_at,
            expires_at
          )
          VALUES (?, ?, ?, ?, ?)
        `)

        .bind(
          sessionId,
          account.id,
          token,
          now,
          expiresAt
        )

        .run();

        return json(

          {

            success: true,

            token,

            admin: {

              id: account.id,

              full_name: account.full_name,

              email: account.email

            },

            expires_at: expiresAt

          },

          corsHeaders
        );
      }


      /* =====================================================
         ADMIN LOGOUT
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/logout"

        &&

        request.method === "POST"

      ) {

        const admin =

          await requireAdminAuth(
            request,
            db
          );

        const token =
          await extractBearerToken(request);

        await db.prepare(`
          DELETE FROM admin_sessions
          WHERE token = ?
            AND user_id = ?
        `)

        .bind(
          token || "",
          admin.id
        )

        .run();

        return json(

          {

            success: true,

            message:
              "Logged out successfully."

          },

          corsHeaders
        );
      }


      /* =====================================================
         APPLICATION COUNT
      ===================================================== */

      if (

        url.pathname ===
          "/api/applications-count"

        &&

        request.method === "GET"

      ) {

        const result =

          await db

            .prepare(`
              SELECT COUNT(*) as count

              FROM volunteer_applications
            `)

            .first();


        return json(

          {

            success: true,

            applications:
              result.count

          },

          corsHeaders
        );
      }



      /* =====================================================
         VOLUNTEER APPLICATION SUBMISSION
      ===================================================== */

      if (

        url.pathname ===
          "/api/application"

        &&

        request.method === "POST"

      ) {

        const data =
          await request.json();

        const fullName =
          String(data.full_name || "").trim();

        const email =
          String(data.email || "").trim();

        if (
          fullName.length < 2
          ||
          fullName.length > 50
        ) {

          return json(

            {

              success: false,

              error:
                "Full name must be between 2 and 50 characters."

            },

            corsHeaders,

            400
          );
        }

        if (
          !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
            .test(email)
        ) {

          return json(

            {

              success: false,

              error:
                "Please enter a valid email address."

            },

            corsHeaders,

            400
          );
        }

        if (!isValidPhone(data.phone)) {

          return json(

            {

              success: false,

              error:
                "Phone number format is invalid."

            },

            corsHeaders,

            400
          );
        }


        validateMessage(
          data.message
        );

        if (!isValidPassword(data.password)) {
          return json({ success: false, error: "Password must be at least 8 characters and include uppercase, lowercase, number, and special character." }, corsHeaders, 400);
        }

        const existingVolunteer =
          await db.prepare(`SELECT id FROM volunteer_applications WHERE email = ? LIMIT 1`).bind(data.email).first();


        if (existingVolunteer) {

          return json(

            {

              success: false,

              error:
                "An application with this email already exists. Please sign in or use a different email address."

            },

            corsHeaders,

            409
          );
        }


        await db.prepare(`
          INSERT INTO volunteer_applications (

            id,

            full_name,

            email,

            phone,

            role,

            skills,

            message,

            password_hash,

            status,

            created_at

          )

          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        `)

        .bind(

          crypto.randomUUID(),

          data.full_name,

          data.email,

          data.phone || "",

          data.role,

          data.skills || "",

          data.message,

          await hashPassword(
            data.password || ""
          ),

          "pending",

          new Date().toISOString()

        )

        .run();

        try {

          await sendVolunteerNotificationEmail(
            env,
            {
              full_name: fullName,
              email,
              phone: data.phone ? String(data.phone) : "",
              role: data.role || "",
              skills: data.skills || "",
              message: data.message
            }
          );

        } catch (emailError) {

          console.error(
            "Volunteer notification email failed:",
            emailError
          );
        }

        try {

          await sendVolunteerConfirmationEmail(
            env,
            {
              name: fullName,
              email
            }
          );

        } catch (emailError) {

          console.error(
            "Volunteer confirmation email failed:",
            emailError
          );
        }


        return json(

          {

            success: true,

            message:
              "Application submitted successfully"

          },

          corsHeaders
        );
      }



/* =====================================================
          CHECK EMAIL EXISTENCE
       ===================================================== */

      if (
        url.pathname === "/api/check-email"
        && request.method === "POST"
      ) {
        const data = await request.json();
        const email = String(data.email || '').trim().toLowerCase();

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ exists: false }, corsHeaders, 400);
        }

        const existing = await db.prepare(`SELECT id FROM user_accounts WHERE email = ? LIMIT 1`).bind(email).first();
        if (existing) {
          return json({ exists: true }, corsHeaders, 200);
        }

        const existingApp = await db.prepare(`SELECT id FROM tutor_applications WHERE email = ? LIMIT 1`).bind(email).first();
        if (existingApp) {
          return json({ exists: true }, corsHeaders, 200);
        }

        const existingVolunteer = await db.prepare(`SELECT id FROM volunteer_applications WHERE email = ? LIMIT 1`).bind(email).first();
        if (existingVolunteer) {
          return json({ exists: true }, corsHeaders, 200);
        }

        return json({ exists: false }, corsHeaders, 200);
      }


      /* =====================================================
          TUTOR SIGNUP
       ===================================================== */

      if (

        url.pathname ===
          "/api/tutor-signup"

        &&

        request.method === "POST"

      ) {

        const data =
          await request.json();

        const fullName = String(data.full_name || '').trim();
        const email = String(data.email || '').trim();

        if (!fullName || fullName.length < 2 || fullName.length > 50) {
          return json({ success: false, error: "Full name must be between 2 and 50 characters." }, corsHeaders, 400);
        }

        if (!isValidEmail(email)) {
          return json({ success: false, error: "Please enter a valid email address." }, corsHeaders, 400);
        }

        if (!isValidPassword(data.password)) {
          return json({ success: false, error: "Password must be at least 8 characters and include uppercase, lowercase, number, and special character." }, corsHeaders, 400);
        }

        if (!isValidPhone(data.phone)) {
          return json({ success: false, error: "Phone number format is invalid." }, corsHeaders, 400);
        }


        const existingTutor =
          await db.prepare(`SELECT id FROM tutor_applications WHERE email = ? LIMIT 1`).bind(data.email).first();


        if (existingTutor) {

          return json(

            {

              success: false,

              error:
                "A tutor application with this email already exists. Please sign in or use a different email address."

            },

            corsHeaders,

            409
          );
        }


        await db.prepare(`
          INSERT INTO tutor_applications (

            id,

            full_name,

            email,

            phone,

            skills,

            availability,

            password_hash,

            status,

            created_at

          )

          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

        `)

        .bind(

          crypto.randomUUID(),

          data.full_name,

          data.email,

          data.phone || "",

          data.skills || "",

          data.availability || "",

          await hashPassword(
            data.password || ""
          ),

          "pending",

          new Date().toISOString()

        )

        .run();


        const tutorApplication = {

          full_name: data.full_name,

          email: data.email,

          phone: data.phone || "",

          skills: data.skills || "",

          availability: data.availability || ""

        };


        try {

          await sendTutorNotificationEmail(
            env,
            tutorApplication
          );

        } catch (notificationError) {

          console.error(
            "Tutor notification email failed:",
            notificationError
          );

        }


        try {

          await sendTutorConfirmationEmail(
            env,
            {
              name: data.full_name,
              email: data.email
            }
          );

        } catch (confirmationError) {

          console.error(
            "Tutor confirmation email failed:",
            confirmationError
          );

        }


        return json(

          {

            success: true,

            message:
              "Tutor application submitted"

          },

          corsHeaders
        );
      }



      /* =====================================================
         ADMIN STATISTICS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/stats"

        &&

        request.method === "GET"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        const [

          tutors,

          students,

          pendingVolunteers,

          pendingTutors,

          sessions

        ] = await Promise.all([


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM user_accounts

            WHERE role = 'tutor'
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM students
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM volunteer_applications

            WHERE status = 'pending'
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM tutor_applications

            WHERE status = 'pending'
          `).first(),


          db.prepare(`
            SELECT COUNT(*) AS count

            FROM tutoring_sessions

            WHERE status = 'completed'
          `).first()

        ]);


        return json(

          {

            success: true,

            stats: {

              total_tutors:
                tutors.count || 0,

              total_students:
                students.count || 0,

              pending_applications:

                (pendingVolunteers.count || 0)

                +

                (pendingTutors.count || 0),

              completed_sessions:
                sessions.count || 0

            }

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET VOLUNTEER APPLICATIONS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/volunteer-applications"

        &&

        request.method === "GET"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        const search =
          url.searchParams.get("search") || "";
        const filterStatus =
          url.searchParams.get("status") || "";

        let where = "";
        const bindings = [];

        if (search) {
          const like = "%" + search + "%";
          where = ` WHERE (full_name LIKE ? OR email LIKE ? OR phone LIKE ?) `;
          bindings.push(like, like, like);
        }

        if (
          filterStatus &&
          ["pending", "approved", "rejected"].includes(filterStatus)
        ) {
          where += where
            ? ` AND status = ? `
            : ` WHERE status = ? `;
          bindings.push(filterStatus);
        }

        const result =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              role,

              skills,

              message,

              status,

              created_at,

              reviewed_at

            FROM volunteer_applications

            ${where}

            ORDER BY

              CASE status

                WHEN 'pending' THEN 0

                WHEN 'approved' THEN 1

                ELSE 2

              END,

              created_at DESC
          `)

          .bind(...bindings)

          .all();


        return json(

          {

            success: true,

            applications:
              result.results || []

          },

          corsHeaders
        );
      }



      /* =====================================================
         VOLUNTEER APPROVE / REJECT
      ===================================================== */

      const volunteerStatusMatch =

        url.pathname.match(

          /^\/api\/admin\/volunteer-applications\/([^/]+)\/status$/

        );


      if (

        volunteerStatusMatch

        &&

        request.method === "PATCH"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        const applicationId =

          decodeURIComponent(
            volunteerStatusMatch[1]
          );


        let requestData = {};
        try {
          requestData = await request.json();
        } catch (e) {
          requestData = {};
        }
        const { status } = requestData;
        const displayAtTeam = requestData.display_at_team === 1 || requestData.display_at_team === '1' ? 1 : 0;


        const normalizedStatus =
          normalizeStatus(status);


        const reviewedAt =
          new Date().toISOString();


        await db.prepare(`
          UPDATE volunteer_applications

          SET

            status = ?,

            reviewed_at = ?

          WHERE id = ?
        `)

        .bind(

          normalizedStatus,

          reviewedAt,

          applicationId

        )

        .run();


        const application =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              role,

              skills,

              message,

              password_hash,

              status,

              created_at,

              reviewed_at

            FROM volunteer_applications

            WHERE id = ?
          `)

          .bind(applicationId)

          .first();


        if (!application) {

          return json(

            {

              success: false,

              error:
                "Application not found"

            },

            corsHeaders,

            404
          );
        }


        let userId = null;


        if (
          normalizedStatus === "approved"
        ) {

          userId =

            await createOrUpdateUserFromApplication(

              db,

              application,

              "volunteer",

              "Your volunteer application has been approved.",

              reviewedAt
            );
        }


        let volunteerEmailError = null;

        if (
          normalizedStatus === "approved"
        ) {

          try {

            await sendVolunteerApprovalEmail(
              env,
              {
                full_name:
                  application.full_name,
                email:
                  application.email
              }
            );

          } catch (emailError) {

            volunteerEmailError =
              emailError.message;
            console.error(
              "Volunteer approval email failed:",
              emailError
            );
          }

        } else if (
          normalizedStatus === "rejected"
        ) {

          try {

            await sendVolunteerRejectionEmail(
              env,
              {
                full_name:
                  application.full_name,
                email:
                  application.email
              }
            );

          } catch (emailError) {

            volunteerEmailError =
              emailError.message;
            console.error(
              "Volunteer rejection email failed:",
              emailError
            );
          }

        }


        if (
          normalizedStatus === "approved"
        ) {
          try {
            const now = reviewedAt || new Date().toISOString();
            const existing = await db.prepare(
              `SELECT id, display_at_team FROM our_team WHERE source_application_id = ? AND source_application_type = ?`
            )
              .bind(application.id, "volunteer")
              .first();
            if (!existing) {
              const memberId = crypto.randomUUID();
              await db.prepare(
                `INSERT INTO our_team (id, source_application_id, source_application_type, name, role, bio, image_url, display_at_team, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
              )
                .bind(
                  memberId,
                  application.id,
                  "volunteer",
                  application.full_name,
                  application.role || application.skills || null,
                  application.message || null,
                  null,
                  displayAtTeam,
                  now,
                  now
                )
                .run();
            } else if (displayAtTeam === 1 && existing.display_at_team !== 1) {
              await db.prepare(`UPDATE our_team SET display_at_team = 1, updated_at = ? WHERE id = ?`)
                .bind(now, existing.id)
                .run();
            } else if (displayAtTeam === 0 && existing.display_at_team !== 0) {
              await db.prepare(`UPDATE our_team SET display_at_team = 0, updated_at = ? WHERE id = ?`)
                .bind(now, existing.id)
                .run();
            }
          } catch (e) {
            console.error("Failed to create/update our_team entry for volunteer:", e);
          }
        }

        const volunteerResponse = {
          success: true,
          application
        };

        if (volunteerEmailError) {
          volunteerResponse.email_warning =
            "Status updated but email notification failed: "
            + volunteerEmailError;
        }

        return json(
 
          volunteerResponse,

          corsHeaders
        );
      }



      /* =====================================================
         GET TUTOR APPLICATIONS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/tutor-applications"

        &&

        request.method === "GET"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        const search =
          url.searchParams.get("search") || "";
        const filterStatus =
          url.searchParams.get("status") || "";

        let where = "";
        const bindings = [];

        if (search) {
          const like = "%" + search + "%";
          where = ` WHERE (full_name LIKE ? OR email LIKE ? OR phone LIKE ?) `;
          bindings.push(like, like, like);
        }

        if (
          filterStatus &&
          ["pending", "approved", "rejected"].includes(filterStatus)
        ) {
          where += where
            ? ` AND status = ? `
            : ` WHERE status = ? `;
          bindings.push(filterStatus);
        }

        const result =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              skills,

              availability,

              status,

              created_at,

              reviewed_at

            FROM tutor_applications

            ${where}

            ORDER BY

              CASE status

                WHEN 'pending' THEN 0

                WHEN 'approved' THEN 1

                ELSE 2

              END,

              created_at DESC
          `)

          .bind(...bindings)

          .all();


        return json(

          {

            success: true,

            applications:
              result.results || []

          },

          corsHeaders
        );
      }



      /* =====================================================
         TUTOR APPROVE / REJECT
      ===================================================== */

      const tutorStatusMatch =

        url.pathname.match(

          /^\/api\/admin\/tutor-applications\/([^/]+)\/status$/

        );


      if (

        tutorStatusMatch

        &&

        request.method === "PATCH"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        const applicationId =

          decodeURIComponent(
            tutorStatusMatch[1]
          );


        let requestData = {};
        try {
          requestData = await request.json();
        } catch (e) {
          requestData = {};
        }
        const { status } = requestData;
        const displayAtTeam = requestData.display_at_team === 1 || requestData.display_at_team === '1' ? 1 : 0;


        const normalizedStatus =
          normalizeStatus(status);


        const reviewedAt =
          new Date().toISOString();


        await db.prepare(`
          UPDATE tutor_applications

          SET

            status = ?,

            reviewed_at = ?

          WHERE id = ?
        `)

        .bind(

          normalizedStatus,

          reviewedAt,

          applicationId

        )

        .run();


        const application =

          await db.prepare(`
            SELECT

              id,

              full_name,

              email,

              phone,

              skills,

              availability,

              password_hash,

              status,

              created_at,

              reviewed_at

            FROM tutor_applications

            WHERE id = ?
          `)

          .bind(applicationId)

          .first();


        if (!application) {

          return json(

            {

              success: false,

              error:
                "Tutor application not found"

            },

            corsHeaders,

            404
          );
        }


        let userId = null;


        if (
          normalizedStatus === "approved"
        ) {

          userId =

            await createOrUpdateUserFromApplication(

              db,

              application,

              "tutor",

              "Your tutor application has been approved.",

              reviewedAt
            );
        }


        let tutorEmailError = null;

        if (
          normalizedStatus === "approved"
        ) {

          try {

            await sendTutorApprovalEmail(
              env,
              {
                full_name:
                  application.full_name,
                email:
                  application.email
              }
            );

          } catch (emailError) {

            tutorEmailError =
              emailError.message;
            console.error(
              "Tutor approval email failed:",
              emailError
            );
          }

        } else if (
          normalizedStatus === "rejected"
        ) {

          try {

            await sendTutorRejectionEmail(
              env,
              {
                full_name:
                  application.full_name,
                email:
                  application.email
              }
            );

          } catch (emailError) {

            tutorEmailError =
              emailError.message;
            console.error(
              "Tutor rejection email failed:",
              emailError
            );
          }

        }


        if (
          normalizedStatus === "approved"
        ) {
          try {
            const now = reviewedAt || new Date().toISOString();
            const existing = await db.prepare(
              `SELECT id, display_at_team FROM our_team WHERE source_application_id = ? AND source_application_type = ?`
            )
              .bind(application.id, "tutor")
              .first();
            if (!existing) {
              const memberId = crypto.randomUUID();
              await db.prepare(
                `INSERT INTO our_team (id, source_application_id, source_application_type, name, role, bio, image_url, display_at_team, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
              )
                .bind(
                  memberId,
                  application.id,
                  "tutor",
                  application.full_name,
                  application.skills || null,
                  null,
                  null,
                  displayAtTeam,
                  now,
                  now
                )
                .run();
            } else if (displayAtTeam === 1 && existing.display_at_team !== 1) {
              await db.prepare(`UPDATE our_team SET display_at_team = 1, updated_at = ? WHERE id = ?`)
                .bind(now, existing.id)
                .run();
            } else if (displayAtTeam === 0 && existing.display_at_team !== 0) {
              await db.prepare(`UPDATE our_team SET display_at_team = 0, updated_at = ? WHERE id = ?`)
                .bind(now, existing.id)
                .run();
            }
          } catch (e) {
            console.error("Failed to create/update our_team entry for tutor:", e);
          }
        }

        const tutorResponse = {
          success: true,
          application
        };

        if (tutorEmailError) {
          tutorResponse.email_warning =
            "Status updated but email notification failed: "
            + tutorEmailError;
        }

        return json(
 
          tutorResponse,

          corsHeaders
        );
      }



      /* =====================================================
         GET APPROVED TUTORS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/tutors"

        &&

        request.method === "GET"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        return json(

          {

            success: true,

            tutors:
              await getTutors(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET APPROVED VOLUNTEERS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/volunteers"

        &&

        request.method === "GET"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        return json(

          {

            success: true,

            volunteers:
              await getVolunteers(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         GET STUDENTS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/students"

        &&

        request.method === "GET"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        return json(

          {

            success: true,

            students:
              await getStudents(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         ASSIGN TUTOR TO STUDENT
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/assign-tutor"

        &&

        request.method === "POST"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        const {

          student_id,

          tutor_id,

          assigned_by_admin_id

        } = await request.json();


        if (!student_id) {

          return json(

            {

              success: false,

              error:
                "student_id is required"

            },

            corsHeaders,

            400
          );
        }


        const now =
          new Date().toISOString();


        await db.prepare(`
          UPDATE student_assignments

          SET

            status = 'reassigned',

            updated_at = ?

          WHERE

            student_id = ?

            AND status = 'active'
        `)

        .bind(

          now,

          student_id

        )

        .run();


        if (tutor_id) {

          await db.prepare(`
            INSERT INTO student_assignments (

              id,

              student_id,

              tutor_id,

              assigned_by_admin_id,

              status,

              created_at,

              updated_at

            )

            VALUES (?, ?, ?, ?, ?, ?, ?)

          `)

          .bind(

            crypto.randomUUID(),

            student_id,

            tutor_id,

            assigned_by_admin_id || null,

            "active",

            now,

            now

          )

          .run();
        }


        return json(

          {

            success: true,

            students:
              await getStudents(db),

            tutors:
              await getTutors(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         REPORTS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/reports"

        &&

        request.method === "GET"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        return json(

          {

            success: true,

            reports:
              await getReports(db)

          },

          corsHeaders
        );
      }



      /* =====================================================
         VOLUNTEER TASKS
      ===================================================== */

      if (

        url.pathname ===
          "/api/admin/volunteer-tasks"

        &&

        request.method === "POST"

      ) {

        await requireAdminAuth(
          request,
          db
        );

        const data =
          await request.json();


        if (

          !data.volunteer_id

          ||

          !data.task_title

        ) {

          return json(

            {

              success: false,

              error:
                "volunteer_id and task_title are required"

            },

            corsHeaders,

            400
          );
        }


        const now =
          new Date().toISOString();


        const taskId =
          crypto.randomUUID();


        await db.prepare(`
          INSERT INTO volunteer_tasks (

            id,

            volunteer_id,

            assigned_by_admin_id,

            task_title,

            task_notes,

            due_at,

            status,

            created_at,

            updated_at

          )

          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

        `)

        .bind(

          taskId,

          data.volunteer_id,

          data.assigned_by_admin_id || null,

          data.task_title,

          data.task_notes || null,

          data.due_at || null,

          "open",

          now,

          now

        )

        .run();


        const task =

          await db.prepare(`
            SELECT

              vt.id,

              vt.volunteer_id,

              ua.full_name
                AS volunteer_name,

              ua.email
                AS recipient_email,

              vt.task_title,

              vt.task_notes,

              vt.due_at,

              vt.status,

              vt.created_at

            FROM volunteer_tasks vt

            JOIN user_accounts ua

              ON ua.id =
                 vt.volunteer_id

            WHERE vt.id = ?
          `)

          .bind(taskId)

          .first();


        return json(

          {

            success: true,

            task

          },

          corsHeaders,

          201
        );
      }






      /* =====================================================
         CONTACT FORM SUBMISSION
      ===================================================== */

      if (
        url.pathname ===
          "/api/contact"
        &&
        request.method === "POST"
      ) {

        const data =
          await request.json();

        if (
          !data.full_name ||
          String(data.full_name).trim().length < 2
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter your full name (at least 2 characters)."
            },
            corsHeaders,
            400
          );
        }

        if (
          !data.email ||
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
            .test(
              String(data.email).trim()
            )
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter a valid email address."
            },
            corsHeaders,
            400
          );
        }

        if (
          !data.subject ||
          String(data.subject).trim().length < 2
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter a subject (at least 2 characters)."
            },
            corsHeaders,
            400
          );
        }

        if (
          !data.message ||
          String(data.message).trim().length < 10
        ) {

          return json(

            {
              success: false,
              error:
                "Please enter a message (at least 10 characters)."
            },
            corsHeaders,
            400
          );
        }

        const contactId =
          crypto.randomUUID();

        const contactNow =
          new Date().toISOString();

        await db.prepare(`
          INSERT INTO contacts (
            id,
            full_name,
            email,
            subject,
            message,
            created_at
          )
          VALUES (?, ?, ?, ?, ?, ?)
        `)
        .bind(
          contactId,
          data.full_name.trim(),
          data.email.trim(),
          data.subject.trim(),
          data.message.trim(),
          contactNow
        )
        .run();

        try {

          await sendContactStoredEmail(
            env,
            {
              name:
                data.full_name.trim(),
              email:
                data.email.trim(),
              subject:
                data.subject.trim(),
              message:
                data.message.trim()
            }
          );

        } catch (emailError) {

          console.error(
            "Contact notification email failed:",
            emailError
          );
        }

        try {

          await sendContactConfirmationEmail(
            env,
            {
              name:
                data.full_name.trim(),
              email:
                data.email.trim()
            }
          );

        } catch (emailError) {

          console.error(
            "Contact confirmation email failed:",
            emailError
          );
        }

        return json(

          {
            success: true,
            message:
              "Thank you for your message! We'll get back to you soon."
          },
          corsHeaders
        );
      }


      /* =====================================================
         DONATION SUBMISSION
      ===================================================== */

      if (
        url.pathname ===
          "/api/donations"
        &&
        request.method === "POST"
      ) {

        const data =
          await request.json();

        const fullName =
          String(data.full_name || "").trim();

        const email =
          String(data.email || "").trim();

        const phoneNumber =
          String(data.phone_number || "").trim() || null;

        let amountDollars;

        if (
          !isValidDonationName(fullName)
        ) {

          return json(

            {

              success: false,

              error:
                "Please enter a valid full name using letters, spaces, apostrophes, or hyphens."

            },

            corsHeaders,

            400
          );
        }

        if (
          !isValidDonationEmail(email)
        ) {

          return json(

            {

              success: false,

              error:
                "Please enter a valid email address."

            },

            corsHeaders,

            400
          );
        }

        try {

          amountDollars =
            amountToDollars(data.amount);

        } catch (amountError) {

          const message =
            amountError.message ||
            "Donation amount is invalid.";

          if (message.includes("greater than zero")) {

            return json(

              {

                success: false,

                error: message

              },

              corsHeaders,

              400
            );
          }

          return json(

            {

              success: false,

              error: message

            },

            corsHeaders,

            400
          );
        }

        const donationId =
          crypto.randomUUID();

        await db.prepare(`
          INSERT INTO donations (

            id,

            full_name,

            email,

            phone_number,

            amount_dollars,

            created_at

          )

          VALUES (?, ?, ?, ?, ?, ?)
        `)

        .bind(

          donationId,

          fullName,

          email,

          phoneNumber,

          amountDollars,

          new Date().toISOString()

        )

.run();

        try {
          await sendDonationNotificationEmail(
            env,
            {
              full_name: fullName,
              email,
              phone_number: phoneNumber,
              amount_dollars: amountDollars
            }
          );
        } catch (emailError) {
          console.error("Donation notification email failed:", emailError);
        }

       return json(
   {
     success: true,
     message:
       "Donation submission recorded successfully.",
     donation_id: donationId
   },
   corsHeaders,
   201
 );
       }



      /* =====================================================
         ADMIN DONATIONS LIST
      ===================================================== */

      if (
        url.pathname ===
          "/api/admin/donations"
        &&
        request.method === "GET"
      ) {

        await requireAdminAuth(request, db);

        const search =
          url.searchParams.get("search") || "";
        const filterStatus =
          url.searchParams.get("status") || "";

        let where = "";
        const bindings = [];

        if (search) {
          const like = "%" + search + "%";
          where = ` WHERE (full_name LIKE ? OR email LIKE ?) `;
          bindings.push(like, like);
        }

        if (
          filterStatus &&
          ["pending", "verified", "rejected"].includes(filterStatus)
        ) {
          where += where
            ? ` AND COALESCE(status, 'pending') = ? `
            : ` WHERE COALESCE(status, 'pending') = ? `;
          bindings.push(filterStatus);
        }

        const result = await db.prepare(`
          SELECT
            id,
            full_name,
            email,
            phone_number,
            amount_dollars,
            COALESCE(status, 'pending') AS status,
            verified_at,
            verified_by,
            created_at
          FROM donations
          ${where}
          ORDER BY
            CASE COALESCE(status, 'pending')
              WHEN 'pending' THEN 0
              WHEN 'verified' THEN 1
              ELSE 2
            END,
            created_at DESC
        `)
        .bind(...bindings)
        .all();

        return json(
          {
            success: true,
            donations: result.results || []
          },
          corsHeaders
        );
      }


      /* =====================================================
         ADMIN DONATION STATUS UPDATE
      ===================================================== */

      const donationStatusMatch =
        url.pathname.match(
          /^\/api\/admin\/donations\/([^/]+)\/status$/
        );

      if (
        donationStatusMatch
        &&
        request.method === "PATCH"
      ) {

        const admin =
          await requireAdminAuth(request, db);

        const donationId =
          decodeURIComponent(donationStatusMatch[1]);

        const { status } =
          await request.json();

        const value =
          String(status || "").toLowerCase();

        if (
          !["verified", "rejected"].includes(value)
        ) {
          return json(
            {
              success: false,
              error: "Invalid status. Must be 'verified' or 'rejected'."
            },
            corsHeaders,
            400
          );
        }

        const donation =
          await db.prepare(`
            SELECT
              id,
              full_name,
              email,
              phone_number,
              amount_dollars,
              COALESCE(status, 'pending') AS status
            FROM donations
            WHERE id = ?
            LIMIT 1
          `)
          .bind(donationId)
          .first();

        if (!donation) {
          return json(
            {
              success: false,
              error: "Donation not found."
            },
            corsHeaders,
            404
          );
        }

        if (donation.status === value) {
          return json(
            {
              success: false,
              error: "Donation is already " + value + "."
            },
            corsHeaders,
            409
          );
        }

        const now =
          new Date().toISOString();

        if (value === "verified") {

          await db.prepare(`
            UPDATE donations
            SET
              status = ?,
              verified_at = ?,
              verified_by = ?
            WHERE id = ?
          `)
          .bind(
            "verified",
            now,
            admin.email || admin.id,
            donationId
          )
          .run();

        } else {

          await db.prepare(`
            UPDATE donations
            SET
              status = ?,
              verified_at = NULL,
              verified_by = NULL
            WHERE id = ?
          `)
          .bind(
            "rejected",
            donationId
          )
          .run();
        }

        let donationEmailError = null;

        if (value === "verified") {

          try {

            await sendDonationVerifiedEmail(
              env,
              {
                full_name:
                  donation.full_name,
                email:
                  donation.email,
                phone_number:
                  donation.phone_number,
                amount_dollars:
                  donation.amount_dollars
              }
            );

          } catch (emailError) {

            donationEmailError =
              emailError.message;
            console.error(
              "Donation verified email failed:",
              emailError
            );
          }

        } else {

          try {

            await sendDonationRejectedEmail(
              env,
              {
                full_name:
                  donation.full_name,
                email:
                  donation.email,
                amount_dollars:
                  donation.amount_dollars
              }
            );

          } catch (emailError) {

            donationEmailError =
              emailError.message;
            console.error(
              "Donation rejected email failed:",
              emailError
            );
          }
        }

        const donationResponse = {
          success: true,
          donation: {
            id: donationId,
            status: value
          }
        };

        if (donationEmailError) {
          donationResponse.email_warning =
            "Status updated but email notification failed: "
            + donationEmailError;
        }

        return json(
          donationResponse,
          corsHeaders
        );
      }


      /* =====================================================
         ADMIN CONTACTS LIST
      ===================================================== */

      if (
        url.pathname ===
          "/api/admin/contacts"
        &&
        request.method === "GET"
      ) {

        await requireAdminAuth(request, db);

        const search =
          url.searchParams.get("search") || "";

        let where = "";
        const bindings = [];

        if (search) {
          const like = "%" + search + "%";
          where = ` WHERE (full_name LIKE ? OR email LIKE ? OR subject LIKE ?) `;
          bindings.push(like, like, like);
        }

        const result = await db.prepare(`
          SELECT
            id,
            full_name,
            email,
            subject,
            message,
            created_at
          FROM contacts
          ${where}
          ORDER BY created_at DESC
        `)
        .bind(...bindings)
        .all();

        return json(
          {
            success: true,
            contacts: result.results || []
          },
          corsHeaders
        );
      }


      /* =====================================================
         ADMIN DASHBOARD SUMMARY
      ===================================================== */

      if (
        url.pathname ===
          "/api/admin/dashboard-summary"
        &&
        request.method === "GET"
      ) {

        await requireAdminAuth(request, db);

        const [

          pendingTutors,
          pendingVolunteers,
          pendingDonations,
          verifiedDonations,
          contacts

        ] = await Promise.all([

          db.prepare(`
            SELECT COUNT(*) AS count
            FROM tutor_applications
            WHERE status = 'pending'
          `).first(),

          db.prepare(`
            SELECT COUNT(*) AS count
            FROM volunteer_applications
            WHERE status = 'pending'
          `).first(),

          db.prepare(`
            SELECT COUNT(*) AS count
            FROM donations
            WHERE COALESCE(status, 'pending') = 'pending'
          `).first(),

          db.prepare(`
            SELECT COUNT(*) AS count
            FROM donations
            WHERE status = 'verified'
          `).first(),

          db.prepare(`
            SELECT COUNT(*) AS count
            FROM contacts
          `).first()

        ]);

        return json(
          {
            success: true,
            summary: {
              pending_tutors:
                pendingTutors.count || 0,
              pending_volunteers:
                pendingVolunteers.count || 0,
              pending_donations:
                pendingDonations.count || 0,
              verified_donations:
                verifiedDonations.count || 0,
              total_contacts:
                contacts.count || 0
            }
          },
          corsHeaders
        );
      }


      /* =====================================================
         PUBLIC OUR TEAM
      ===================================================== */
      if (
        url.pathname === "/api/our-team"
        &&
        request.method === "GET"
      ) {
        try {
          const result = await db.prepare(
            `SELECT id, name, role, bio, image_url, display_at_team, source_application_type, created_at
             FROM our_team
             WHERE display_at_team = 1
             ORDER BY created_at ASC, id ASC`
          ).all();
          const members = (result.results || []).map(function(m) {
            return {
              id: m.id,
              name: m.name,
              role: m.role,
              bio: m.bio,
              image_url: m.image_url,
              display_at_team: m.display_at_team,
              source_application_type: m.source_application_type,
              created_at: m.created_at
            };
          });
          return json(
            {
              success: true,
              members: members
            },
            corsHeaders
          );
        } catch (e) {
          return json(
            {
              success: true,
              members: []
            },
            corsHeaders
          );
        }
      }

      if (
        url.pathname === "/api/admin/our-team/backfill"
        &&
        request.method === "POST"
      ) {
        try {
          await requireAdminAuth(request, db);
          const originalMembers = [
            { id: "ot_orig_mithra", name: "Mithra Venkatesan", role: "Founder, Program Coordinator, Tutor", bio: "Mithra is a junior at South Lakes High School in Herndon, Virginia. She is a gymnast, cheerleader, tennis player, and aspires to pursue a career in medicine. Mithra had the unique privilege of studying for a few years in Tamil Nadu during her formative years, so she is naturally well-versed in the Tamil language and culture.\n\nWitnessing firsthand the economic and educational doors that English fluency opened for her peers, especially in rural areas, instilled in her a deep understanding of the need for bilingualism and a sense of responsibility to the underprivileged by starting Seeds of Success.", image_url: "Images/Mithra_Pic.avif" },
            { id: "ot_orig_nila", name: "Nila Loganathan", role: "Founder, Program Coordinator, Tutor", bio: "Nila is a rising sophomore at Freedom High School in Chantilly, Virginia. She is a dedicated gymnast and is notably fluent in Tamil, possessing strong skills in speaking, reading, and writing the language. Nila particularly excels at public speaking in both Tamil and English, a skill she uses to connect with and motivate students.\n\nThe opportunity to work with and assist underprivileged students is what motivated her to co-start Seeds of Success. Nila recognizes the program's meaningful cause and is confident her involvement will positively impact the kids while maximizing the program's reach.", image_url: "Images/Nila_pic.avif" },
            { id: "ot_orig_kavin", name: "Kavin Loganathan", role: "Founder, Technology Innovator", bio: "Kavin is an eighth-grader at J. Michael Lunsford Middle School in Chantilly, Virginia. He is a well-versed debater, an enthusiastic public speaker, and an athlete who plays lacrosse and volleyball. As an avid technologist who enjoys solving complex problems, Kavin has taken on the vital role of providing technological support for Seeds of Success.\n\nHis responsibilities include building and maintaining the organization's digital solutions. Furthermore, he plays a key part in digitalizing the curriculum and ensuring the technical framework is in place to help the organization scale its operations and reach.", image_url: "Images/Kavin_Pic.avif" },
            { id: "ot_orig_prakash", name: "Prakash Swaminathan", role: "Curriculum Developer, Tutor", bio: null, image_url: "Images/Prakash.avif" },
            { id: "ot_orig_thangamani", name: "Thangamani R.", role: "Curriculum Developer", bio: null, image_url: "Images/SeedsOfSuccess_pic.jpeg" },
            { id: "ot_orig_ananya", name: "Ananya Rajasekaran", role: "Tutor", bio: null, image_url: "Images/Ananya_Pic.avif" },
            { id: "ot_orig_abhimanyuu", name: "Abhimanyuu Rajkumar", role: "Digital Learning & Social Media Coordinator", bio: "Abhimanyuu Rajkumar is a 9th grader at Oakton High School in Vienna, Virginia, and lives in Herndon, Virginia. He is a skilled technology enthusiast, a dedicated student, and a competitive athlete who plays both baseball and basketball. Passionate about making a meaningful difference in the lives of others, he took the initiative to join Seeds of Success as the organization's Social Media Coordinator, where he combines his creativity and technical skills to expand the organization's reach and impact.\n\nAs the Social Media Coordinator, he is responsible for creating engaging posters, videos, and other digital content that promote the organization's mission and fundraising efforts. He also ensures that supporters have the information they need to get involved, whether through volunteering, donating, or spreading awareness. Through strategic communication and creative outreach, he helps connect more people with the mission of Seeds of Success and supports the organization's continued growth.", image_url: "Images/Abhimanyuu Rajkumar_Pic.jpeg" },
            { id: "ot_orig_praneetha", name: "Praneetha", role: "Tutor", bio: "Praneetha is a rising sophomore at John Champe High School in Aldie, Virginia. Outside of school in her own time she involves herself in activies such as swim, and runs our own nail business from home. She has been a fluent tamil speaker since birth, and overtime has improved her writing and reading skills.\n\nWith her variety of skills she is very much involved in her community helping in ways she can. To extend her aid across the globe she grabbed on the opportunity to participate in Seeds of Sucess. Praneetha appreciates and is thrilled to be a part of a community that has such a meaningful impact on eager individuals who want to grow their skills", image_url: "Images/Praneetha.png" },
            { id: "ot_orig_dhanyashree", name: "Dhanyashree Dineshkumar", role: "Tutor", bio: "Dhanyashree is an incoming freshman at Skyview High School in Herndon, Virginia. Outside of school, music plays a huge role in her life, where she enjoys singing, playing the guitar, and playing a traditional instrument called the veena. She is also a fluent speaker in both Tamil and English.\n\nDhanyashree is excited to join Seeds of Success and teach English to kids who are learning the language. She looks forward to helping her students build a key skill that will support them for years to come.", image_url: "Images/Dhanyashree_Pic.jpeg" },
            { id: "ot_orig_thara", name: "Thara Venkatesan", role: "Tutor", bio: "Thara is a second-year student at the College of William & Mary in Williamsburg, Virginia. She serves as the key mentor to Seeds of Success founders. Drawing on her own leadership experience, she provides guidance and strategic support to the emerging organization.\n\nHaving attended Tamil school for 12 years, she is fluent in the language and proficient in speaking, reading, and writing. With a passion for teaching children and a goal to teach English abroad, she is excited to give back to her community of origin and help guide the next generation of program leaders.", image_url: "Images/Thara_Pic.avif" },
            { id: "ot_orig_kayal", name: "Kayal Sadasivam", role: "Tutor", bio: null, image_url: "Images/Kayal_Pic.avif" },
            { id: "ot_orig_senthiru", name: "Senthiru Priya. B", role: "Tutor", bio: null, image_url: "Images/Senthiru_Pic.avif" },
            { id: "ot_orig_vasanthi", name: "Vasanthi Sekar", role: "Tutor", bio: null, image_url: "Images/Vasanthi_Pic.avif" }
          ];
          const now = new Date().toISOString();
          let inserted = 0;
          for (let i = 0; i < originalMembers.length; i++) {
            const m = originalMembers[i];
            try {
              const existing = await db.prepare(`SELECT id FROM our_team WHERE id = ? OR (source_application_id IS NOT NULL AND source_application_id = ? AND source_application_type = ?)`).bind(m.id, m.id, 'original').first();
              if (existing) continue;
              await db.prepare(`INSERT INTO our_team (id, source_application_id, source_application_type, name, role, bio, image_url, display_at_team, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`).bind(m.id, null, 'original', m.name, m.role, m.bio, m.image_url, now, now).run();
              inserted++;
            } catch (e) {
              // continue
            }
          }
          return json({ success: true, inserted, total: originalMembers.length }, corsHeaders);
        } catch (e) {
          return json({ success: false, error: e.message || "Failed to backfill" }, corsHeaders, 500);
        }
      }

      /* =====================================================
         ADMIN OUR TEAM CRUD
      ===================================================== */
      if (
        url.pathname === "/api/admin/our-team"
        &&
        request.method === "GET"
      ) {
        await requireAdminAuth(request, db);
        const search = url.searchParams.get("search") || "";
        let where = "";
        const bindings = [];
        if (search) {
          const like = "%" + search + "%";
          where = ` WHERE (name LIKE ? OR role LIKE ? OR bio LIKE ?) `;
          bindings.push(like, like, like);
        }
        const result = await db.prepare(
          `SELECT id, source_application_id, source_application_type, name, role, bio, image_url, display_at_team, created_at, updated_at
           FROM our_team
           ${where}
           ORDER BY created_at ASC, id ASC`
        )
          .bind(...bindings)
          .all();
        return json(
          {
            success: true,
            members: result.results || []
          },
          corsHeaders
        );
      }

      if (
        url.pathname === "/api/admin/our-team"
        &&
        request.method === "POST"
      ) {
        await requireAdminAuth(request, db);
        const data = await request.json();
        const name = String(data.name || "").trim();
        if (!name) {
          return json({ success: false, error: "Name is required." }, corsHeaders, 400);
        }
        const id = crypto.randomUUID();
        const now = new Date().toISOString();
        await db.prepare(
          `INSERT INTO our_team (id, source_application_id, source_application_type, name, role, bio, image_url, display_at_team, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            id,
            data.source_application_id || null,
            data.source_application_type || null,
            name,
            data.role || null,
            data.bio || null,
            data.image_url || null,
            data.display_at_team == 1 ? 1 : 0,
            now,
            now
          )
          .run();
        return json({ success: true, id }, corsHeaders);
      }

      const ourTeamIdMatch = url.pathname.match(/^\/api\/admin\/our-team\/([^/]+)$/);
      if (ourTeamIdMatch && request.method === "PATCH") {
        await requireAdminAuth(request, db);
        const memberId = decodeURIComponent(ourTeamIdMatch[1]);
        const data = await request.json();
        const now = new Date().toISOString();
        const updates = [];
        const bindings = [];
        if (data.name !== undefined) { updates.push("name = ?"); bindings.push(String(data.name || "").trim()); }
        if (data.role !== undefined) { updates.push("role = ?"); bindings.push(data.role || null); }
        if (data.bio !== undefined) { updates.push("bio = ?"); bindings.push(data.bio || null); }
        if (data.image_url !== undefined) { updates.push("image_url = ?"); bindings.push(data.image_url || null); }
        if (data.display_at_team !== undefined) { updates.push("display_at_team = ?"); bindings.push(data.display_at_team == 1 ? 1 : 0); }
        if (updates.length === 0) {
          return json({ success: true }, corsHeaders);
        }
        updates.push("updated_at = ?");
        bindings.push(now);
        bindings.push(memberId);
        await db.prepare(`UPDATE our_team SET ${updates.join(", ")} WHERE id = ?`).bind(...bindings).run();
        return json({ success: true }, corsHeaders);
      }
      if (ourTeamIdMatch && request.method === "DELETE") {
        await requireAdminAuth(request, db);
        const memberId = decodeURIComponent(ourTeamIdMatch[1]);
        await db.prepare(`DELETE FROM our_team WHERE id = ?`).bind(memberId).run();
        return json({ success: true }, corsHeaders);
      }

      /* =====================================================
         DEFAULT API RESPONSE
      ===================================================== */

      return json(

        {

          success: true,

          message:
            "Seeds of Success API"

        },

        corsHeaders
      );


    }

    catch (error) {


      const message =
        error.message || "";


      console.error(
        "Worker error:",
        error
      );


      if (
        error.code === AUTH_UNAUTHENTICATED
      ) {

        return json(

          {

            success: false,

            error:
              "Authentication required. Please log in."

          },

          corsHeaders,

          401
        );
      }


      if (
        error.code === AUTH_FORBIDDEN
      ) {

        return json(

          {

            success: false,

            error:
              "Access denied."

          },

          corsHeaders,

          403
        );
      }


      if (

        message.includes("UNIQUE")

        ||

        message.includes(
          "user_accounts.email"
        )

      ) {

        return json(

          {

            success: false,

            error:
              "An account with this email already exists. Please sign in or use a different email address."

          },

          corsHeaders,

          409
        );
      }


      if (
        message.includes("Message must")
      ) {

        return json(

          {

            success: false,

            error: message

          },

          corsHeaders,

          400
        );
      }


      return json(

        {

          success: false,

          error:
            "Something went wrong. Please try again later."

        },

        corsHeaders,

        500
      );
    }
  }
};
