# Wix App Install Webhook -> Google Sheets

This Node.js API receives Wix install webhooks from **multiple apps** on a single endpoint and stores each event in Google Sheets, including `appId` for separation.

## Features

- Single endpoint: `POST /webhooks/wix/install`
- Multi-app support using `appId`
- App allow-list and signature verification per app (`x-wix-signature`)
- Shared static webhook token gate (`x-webhook-token`)
- Security headers via `helmet`
- Minimal health endpoint: `GET /healthz`

## 1) Setup Google Sheet

1. Create a Google Sheet with tab name `Installs` (or update `GOOGLE_SHEET_NAME`).
2. Add header row:
   - `receivedAt`
   - `eventName`
   - `appId`
   - `siteId`
   - `instanceId`
   - `userEmail`
   - `userId`
   - `region`
   - `rawPayload`
3. Create a Google Cloud service account and enable Sheets API.
4. Share the sheet with the service account email as **Editor**.

## 2) Configure environment

Copy `.env.example` to `.env` and fill values:

```bash
cp .env.example .env
```

Key fields:
- `WEBHOOK_TOKEN`: Static secret expected in `x-webhook-token` header.
- `WIX_APP_SECRETS_JSON`: JSON map of `appId -> appSecret` for signature checks.

## 3) Install & run

```bash
npm install
npm start
```

## 4) Configure Wix webhook

Point Wix webhook URL to:

```text
https://your-domain.com/webhooks/wix/install
```

Each request should include:
- `x-webhook-token`: your static token
- `x-wix-signature`: HMAC SHA256 of raw JSON body with app secret
- `appId` in payload (`appId` or `app_id`)

## Example request

```bash
curl -X POST http://localhost:3000/webhooks/wix/install \
  -H "content-type: application/json" \
  -H "x-webhook-token: replace-with-long-random-token" \
  -H "x-wix-signature: <computed-hmac-hex>" \
  -d '{
    "appId": "app_abc",
    "eventType": "APP_INSTALLED",
    "siteId": "site_001",
    "instanceId": "inst_001",
    "user": { "id": "u1", "email": "owner@domain.com" },
    "region": "US"
  }'
```

## Free hosting options

1. **Render (Free web service)**
   - Easy deploy from GitHub and supports env vars.
   - Good beginner experience.
2. **Railway (free trial credits / hobby-friendly)**
   - Very easy Node deployments.
3. **Fly.io (free allowance may vary)**
   - Good for lightweight always-on apps.
4. **Deta Space / similar serverless options**
   - Useful for low traffic webhook ingestion.

> Free plans and limits change frequently. Confirm current quota, sleep behavior, and egress policy before production.

## Basic security checklist

- Use a long random `WEBHOOK_TOKEN` and rotate periodically.
- Keep app secrets in env vars only (`WIX_APP_SECRETS_JSON`).
- Verify raw-body HMAC signature (implemented).
- Keep request body limit low (`100kb`, implemented).
- Store only needed PII and restrict spreadsheet sharing.
- Add IP allow-list at hosting provider if Wix source IP ranges are available.
- Add alerting on repeated 401/403 responses.
- Use HTTPS only (terminate TLS at hosting provider).
