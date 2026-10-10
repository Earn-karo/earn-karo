# Earn Bro — production-oriented starter

This is a **starter codebase**, not a launched or audited production service. It includes a responsive mobile-first UI, server-side account records, bcrypt password hashes, server sessions, SQLite persistence, admin-only routes, reward activity endpoints, and Razorpay Standard Checkout order/signature verification.

## Important boundaries
- **Do not launch with real users until reviewed and hardened.** The default SQLite/session setup is suitable for a small demo, not horizontal scaling. Use managed PostgreSQL, a persistent database, a production session store, backups, monitoring, and security testing before launch.
- Razorpay keys are server-side environment variables only. Never commit `.env`, publish a Key Secret, or put secrets in `public/`.
- UPI payments are collected by Razorpay Checkout; the browser callback is verified server-side. Configure the Razorpay webhook URL `/api/payments/webhook` and webhook secret. Test webhook delivery and idempotency in the dashboard.
- This starter supports **wallet top-ups** after verified payment. Withdrawal requests are stored for **manual review** only. It does not perform real payouts or transfer money to a UPI ID.
- Reward points currently have a simple demo rule: each listed game/task can be claimed once per account. Before money-equivalent rewards, implement abuse prevention, server-side gameplay validation, rate limiting, device/risk checks, dispute handling, terms, privacy policy, refund rules, and audit logs.
- This app is not gambling software and contains no paid-entry prize game. If you plan cash-convertible rewards, contests, entry fees, chance-based prizes, or payouts, get Indian legal, tax, and payment-provider approval advice before enabling them.

## Run locally
1. Install Node.js 20 or later.
2. Copy `.env.example` to `.env`.
3. Set a long random `SESSION_SECRET`, an `ADMIN_EMAIL`, and a strong `ADMIN_PASSWORD`.
4. Add Razorpay **Test Mode** keys to `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET`.
5. Run `npm install`, then `npm start`.
6. Open `http://localhost:3000`.

The initial admin account is created from the environment variables only when no admin account exists. Keep the credentials private and change the admin password flow before public launch.

## Razorpay setup
1. Create/verify your merchant account at Razorpay and finish any business/KYC checks required by the provider.
2. In the dashboard, use **Test Mode** API keys first. Put the Key ID and Key Secret in server environment variables.
3. Configure the checkout and make test payments. Confirm the server creates an order for every payment and verifies the returned signature.
4. Add a webhook endpoint at `https://YOUR-DOMAIN/api/payments/webhook`, subscribe to `payment.captured`, and copy the webhook secret into `RAZORPAY_WEBHOOK_SECRET`.
5. Test success, failure, duplicate webhook delivery, abandoned checkout, refunds, and reconciliation.
6. Before live mode, switch to Live keys only after the website is deployed over HTTPS, secrets are in the host's secret manager, security review is done, and the business is approved for the payment methods you need.

Official references:
- Razorpay server integration and signature verification: https://razorpay.com/docs/server-integration/
- Razorpay security checklist: https://razorpay.com/security/checklist/

## Deploy checklist
- Buy/connect a domain and configure HTTPS.
- Deploy to a Node.js host with a persistent database (prefer managed PostgreSQL in production).
- Set environment variables in the host dashboard, not in source files.
- Set `NODE_ENV=production`, `APP_BASE_URL=https://your-domain`, a strong session secret, Razorpay keys, and webhook secret.
- Configure secure session storage, CSRF tokens, email verification, password reset, admin 2FA, account deletion, rate limits, audit logging, backups, monitoring, privacy policy, terms, and support contact.
- Review local law, tax, consumer-protection, age restrictions, and Razorpay's acceptable-use/payment-method policies for the exact reward model.
- Run penetration/security tests and a small monitored live transaction before opening to the public.
