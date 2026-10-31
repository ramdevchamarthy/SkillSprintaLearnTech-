# SkillSprinta LearnTech API (prototype backend)

No dependencies. Needs Node 22+ (uses the built-in `node:sqlite`).

## Run
    SESSION_SECRET=<at least 16 random characters> PORT=8787 node server.js
Then open http://localhost:8787 . The server serves the app (public/index.html and public/sprintmap.html) and the API from one origin.

When you change the app, copy the updated files from ../sm/ into public/ (index.html and sprintmap.html).

## Test
    node --test server.test.js      # 26 API and security tests
    node --test e2e.test.js         # 8 browser tests (needs Playwright with Chromium): two devices, limits, conflicts

## Environment
- SESSION_SECRET (required): signs OTP codes and must be kept private.
- DB_PATH: SQLite file path (default ./data.sqlite).
- SMS_PROVIDER: `demo` (default outside production). The demo SMS shows the sign-in code on screen and sends nothing. In the demo, anyone who can reach the server can sign in to any number, so it is for prototype testing only. Refused when NODE_ENV=production. Real providers (for example MSG91 for India) are not connected yet; they would go in `sendSms()`.
- DEMO_OTP=1: same as the demo provider (kept for older setups). Also refused in production.
- NODE_ENV=production: turns off the demo SMS. Sign-in codes then fail until a real provider is connected.
- SECURE_COOKIES=1: marks the session cookie Secure (use behind HTTPS).

## What the server enforces
- One-time codes: 6 digits, stored as HMAC hashes, expire in 5 minutes, locked after 5 wrong tries, single use, max 3 requests per 10 minutes per number.
- Sessions: random tokens stored as SHA-256 hashes, HttpOnly SameSite=Lax cookies, 14-day expiry, revoked on sign-out.
- Per-user data: state and profile are only readable and writable by their owner.
- Free upload limit: 5 PDF or PPTX files, counted in the database in a single transaction. Deleting a file does not return its slot. TXT and DOCX are not counted.
- Requests that mutate data must be JSON, which blocks simple cross-site form posts.

## Endpoints
POST /api/auth/otp/request  {country, phone}
POST /api/auth/otp/verify   {country, phone, code}
POST /api/auth/logout
GET  /api/me
PUT  /api/profile           (object)
GET  /api/state  /  PUT /api/state   (object, up to 2 MB)
GET  /api/uploads           list plus used/limit
POST /api/uploads           {name, ext, size, text}
GET  /api/uploads/:id       returns extracted text
DELETE /api/uploads/:id     soft delete, clears text, slot not refunded
POST /api/account/delete

## How the app syncs (when signed in)
- The app still works on its own. Everything is kept in the browser first, and signing in is optional (Sign in to sync, on the welcome screen or in Profile).
- Your profile, progress and uploads are sent to your account after each change (about one second later). Each sync sends the whole saved state, so the last change wins.
- Signing in on a new device loads the saved state. If both the account and the device have different progress, the app asks which copy to keep.
- Uploads are checked on the server before they are accepted. Uploads made on a device before signing in are counted on the account too.
- The extracted text of uploaded files is part of your saved progress, so it is synced to your account and available on your other devices. The uploads record on the server stores only the name, type, size and time.
- Device settings are not synced: theme, splash screen and the tour-completed flag.

## Admin
- Set ADMIN_PHONES (comma-separated, for example +919876543210). Those accounts get admin access after normal sign-in.
- Open http://localhost:8787/admin (sign in on the Sync page first). Admins see counts, masked phone numbers, plan changes and an audit log.
- Admins cannot see profiles, progress or uploaded text.

## Limits and deletion
- The free upload allowance is kept per phone number, so deleting an account does not reset it.
- Delete all my data clears the profile, progress and uploads from this browser and, when signed in, from your account. The upload count is kept.

## OCR, AI tutor and contact form
- OCR (POST /api/ocr): when a signed-in user uploads a PDF with no readable text, the app sends it to the server, which renders pages with pdftoppm and reads them with tesseract (English, first 20 pages). Limit 10 PDFs a day per user. Needs `poppler-utils` and `tesseract-ocr` on the server (the Dockerfile installs them).
- AI tutor (POST /api/tutor/ask): answers only from the notes of one uploaded file, using the Anthropic Messages API. Set ANTHROPIC_API_KEY (and optionally AI_MODEL, default claude-haiku-5-5). Without a key it reports "not connected". Limit 20 questions a day per user. The key is never sent to the browser.
- Contact form (POST /api/contact): sends the message through the Resend email API. Set RESEND_API_KEY, MAIL_FROM and CONTACT_TO. Limit 5 messages a day per network address.
- TRUST_PROXY=1: when the server sits behind a reverse proxy, use the visitor address from X-Forwarded-For for the limits. The Docker setup turns this on.

## Deployment (HTTPS)
- Dockerfile: Node 22 with tesseract and poppler. docker-compose.yml runs the app with Caddy, which gets the HTTPS certificate for your domain.
- Steps: copy .env.example to .env and fill it in; set the domain in Caddyfile; point DNS to the server; run `docker compose up -d --build`.
- Not verified here: the Docker build could not run in this sandbox (no Docker daemon). Test it on your server first.
- Sign-in does not work on a live server until a real SMS provider is connected (see sendSms). The demo SMS is refused in production by default.
- For private testing only: set ALLOW_DEMO_SMS_IN_PRODUCTION=1 to allow demo codes on the live site. The server then logs a warning. Anyone who can reach the site can sign in as any phone number, so do not use this on a public address.
- Status: deployment has not been run. The sandbox used to build this could not reach AWS or the Docker daemon. Run the steps above on your own server.

## Not built yet
- Real SMS delivery for sign-in (needs a provider account and a choice of provider).
- Push notifications (needs a service worker and browser push keys; not built in this pass).
- Email notifications other than the contact form.
- Payments (plan changes are manual through the admin page).
- The AI tutor and email are tested with fake providers only; they need your keys to run for real.
- Deleting the server copy of data is available through Delete all my data (when signed in); a full account-deletion screen is not built.
