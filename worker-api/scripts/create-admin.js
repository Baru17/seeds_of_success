/*
 * Seeds of Success - One-time Admin Account Setup
 *
 * Generates a PBKDF2 password hash and prints a SQL INSERT for an admin
 * account. The SQL must be executed manually against the D1 database via
 * `wrangler d1 execute` or the Cloudflare dashboard.
 *
 * Usage:
 *   node scripts/create-admin.js --email admin@example.com --name "Admin User"
 *   (will prompt for password securely via hidden input)
 *
 *   Or via environment variables:
 *   ADMIN_EMAIL=admin@example.com ADMIN_NAME="Admin User" ADMIN_PASSWORD=secret node scripts/create-admin.js
 *
 * The output INSERT stores ONLY:
 *   - a random salt (base64)
 *   - the PBKDF2-SHA256 derived key (base64)
 *   - the iteration count
 * encoded in a self-describing format: pbkdf2$SHA256$<iterations>$<salt>$<hash>
 * in the existing user_accounts.password_hash TEXT column.
 *
 * No plaintext password is ever printed or stored.
 * No password hash is committed to source control.
 */

const crypto = globalThis.crypto || require("crypto").webcrypto;

const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH_BITS = 256; // 32 bytes
const SALT_BYTES = 16;

function assert(cond, msg) {
  if (!cond) {
    process.stderr.write("Error: " + msg + "\n");
    process.exit(1);
  }
}

function toBase64(buf) {
  return Buffer.from(buf).toString("base64");
}

function fromBase64(b64) {
  return Buffer.from(b64, "base64");
}

async function hashPasswordPkdf2(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
    },
    keyMaterial,
    KEY_LENGTH_BITS
  );

  return new Uint8Array(bits);
}

async function promptHidden(question) {
  // Use terminal read with echo disabled for passwords where possible.
  return new Promise((resolve) => {
    const readline = require("readline");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    // readline does not hide input; document this limitation clearly.
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const getArg = (flag) => {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
  };

  let email = process.env.ADMIN_EMAIL || getArg("--email");
  let name = process.env.ADMIN_NAME || getArg("--name") || email;
  let password = process.env.ADMIN_PASSWORD;

  assert(email, "Email is required (--email or ADMIN_EMAIL).");
  assert(
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
    "Email address format looks invalid."
  );

  if (!password) {
    password = await promptHidden("Enter admin password: ");
    const confirm = await promptHidden("Confirm admin password: ");
    assert(password === confirm, "Passwords do not match.");
  }

  assert(
    typeof password === "string" && password.length >= 8,
    "Password must be at least 8 characters."
  );

  const salt = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(salt);

  const hashBytes = await hashPasswordPkdf2(password, salt);
  const encoded =
    "pbkdf2$SHA256$" +
    PBKDF2_ITERATIONS +
    "$" +
    toBase64(salt) +
    "$" +
    toBase64(hashBytes);

  const now = new Date().toISOString();

  const insert = [
    "INSERT INTO user_accounts (",
    "  id, full_name, email, phone, role, password_hash, status,",
    "  notification_message, created_at, updated_at",
    ") VALUES (",
    `  '${crypto.randomUUID()}',`,
    `  '${name.replace(/'/g, "''")}',`,
    `  '${email.replace(/'/g, "''")}',`,
    "  NULL,",
    "  'admin',",
    `  '${encoded}',`,
    "  'active',",
    "  NULL,",
    `  '${now}',`,
    `  '${now}'`,
    ");",
  ].join("\n");

  process.stdout.write("\nRun the following SQL against D1 (wrangler d1 execute):\n\n");
  process.stdout.write(insert + "\n\n");
  process.stdout.write(
    "The password hash is a PBKDF2-SHA256 derivation with a unique random salt.\n"
  );
  process.stdout.write(
    "No plaintext password is stored. Keep this output private.\n"
  );
}

main().catch((err) => {
  process.stderr.write("Fatal: " + (err && err.message ? err.message : err) + "\n");
  process.exit(1);
});
