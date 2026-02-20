# Wix App Install Webhook -> Google Sheets

This Node.js API receives Wix install webhooks from **multiple apps** and stores data in one spreadsheet with **2 tabs**:

- `Installs` (successful install events)
- `WebhookLogs` (every incoming request: success + failure)

## Key change for your requirement

Yes — each app can have its own random secret in webhook URL path.

The endpoint pattern is:

```text
/webhooks/wix/install/:webhookSecret
```

Each `webhookSecret` maps to one `appId` in `WIX_APPS_JSON`, so only configured secret URLs are accepted.

## Features

- Single webhook base path with app-specific secret segment
- Multi-app support using one Wix SDK client per `appId`
- Wix signature verification handled by Wix SDK via app `publicKey`
- Unknown secret URLs are rejected with `403`
- Every webhook request logged (success and failure) in `WebhookLogs`
- Successful install events written to `Installs`
- Security headers via `helmet`
- Health endpoint: `GET /healthz`

## 1) Setup Google Sheet (2 tabs)

Create one spreadsheet with two tabs.

### Tab A: `Installs`
Header row:

1. `requestId` (numeric sequence shared with `WebhookLogs`)
2. `receivedAt`
3. `eventName`
4. `appId`
5. `siteId`
6. `instanceId`
7. `userEmail`
8. `userName`
9. `userId` (memberId)
10. `memberDetails` (full JSON)
11. `region`
12. `rawPayload`

### Tab B: `WebhookLogs`
Header row:

1. `requestId`
2. `receivedAt`
3. `status` (`SUCCESS` / `FAILED`)
4. `matchedAppId`
5. `httpStatus`
6. `failureStep`
7. `errorMessage`
8. `errorLine`
9. `errorStack`
10. `requestPath`
11. `webhookSecret`
12. `requestBody`

## 2) Get Google credentials and spreadsheet ID

1. Open [Google Cloud Console](https://console.cloud.google.com/) and create/select a project.
2. Enable **Google Sheets API**.
3. Create service account and download JSON key.
4. Use from JSON:
   - `client_email` -> `GOOGLE_SERVICE_ACCOUNT_EMAIL`
   - `private_key` -> `GOOGLE_PRIVATE_KEY`
5. Put private key in `.env` with escaped new lines:

```env
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nABC...\n-----END PRIVATE KEY-----\n"
```

6. Spreadsheet ID from URL:

```text
https://docs.google.com/spreadsheets/d/SPREADSHEET_ID/edit#gid=0
```

7. Share spreadsheet with service account email as **Editor**.

## 3) Configure environment

```bash
cp .env.example .env
```

Set:

- `GOOGLE_SPREADSHEET_ID`
- `GOOGLE_INSTALLS_SHEET_NAME` (default `Installs`)
- `GOOGLE_LOGS_SHEET_NAME` (default `WebhookLogs`)
- `WEBHOOK_BASE_PATH` (default `/webhooks/wix/install`)
- `WEBHOOK_PATH` (legacy fallback if `WEBHOOK_BASE_PATH` is not set)
- `WIX_APPS_JSON`

Example `WIX_APPS_JSON`:

```env
WIX_APPS_JSON={"11c28482-01cc-4a0d-b1d5-0651e0fc0119":{"publicKey":"-----BEGIN PUBLIC KEY-----\\nMIIB...\\n-----END PUBLIC KEY-----","webhookSecret":"a6f9b2d7c1e843e7a10489cc"},"another-app-id":{"publicKey":"-----BEGIN PUBLIC KEY-----\\nMIIC...\\n-----END PUBLIC KEY-----","webhookSecret":"e4f2cc911f4c49ff9d10a9d3"}}
```

## 4) Configure Wix webhook URLs

For each app, configure its own URL using its mapped secret:

```text
https://your-domain.com/webhooks/wix/install/a6f9b2d7c1e843e7a10489cc
https://your-domain.com/webhooks/wix/install/e4f2cc911f4c49ff9d10a9d3
```

## 5) Run

```bash
npm install
npm start
```

## Failure handling behavior

- Unknown secret -> `403`, logged in `WebhookLogs`
- Known secret but invalid Wix signature/payload -> `401`, logged in `WebhookLogs` with `failureStep`, `errorLine`, and `errorStack`
- Valid payload -> `200`, logged in `WebhookLogs` and install event stored in `Installs`

So every request is captured in logs, and only valid install events go to installs tab.

## Debugging notes

- `requestId` is generated as incrementing numeric ID from `WebhookLogs` last row and reused in `Installs` for same webhook request.
- `failureStep` tells which part failed (`resolve_secret`, `wix_webhook_process`, etc.).
- `errorLine` stores the first stack location (`at ...:line:column`) for quick tracing.
- `errorStack` stores a truncated stack trace for deeper debugging.
- Control characters in request/error text are sanitized before writing to Sheets to reduce "invalid character" write issues.

## Public key formatting fix (for `InvalidCharacterError`)

If you see errors like:

```text
InvalidCharacterError: Invalid character
at atob (...)
```

it usually means the Wix `publicKey` value is not in the expected format. This server now normalizes keys by:

- converting escaped `\n` sequences to real newlines
- preserving valid SPKI PEM input (required by current Wix SDK/jose)
- converting base64/base64url key bodies into SPKI PEM format
- normalizing base64url keys (`-`,`_`) to standard base64 with proper padding

You can provide either full PEM or base64-style key in `WIX_APPS_JSON`; the server normalizes both to SPKI PEM.


## Startup public-key self-check

On startup, the server validates each normalized app public key and logs a summary:

- `valid` boolean
- `reason` if invalid
- key `fingerprint` (short SHA-256 prefix)

The same `publicKeyChecks` summary is exposed in `GET /healthz` for quick diagnostics.

## Exact `.env` JSON example with your app/key


> **Render tip:** In Render dashboard, set key as `WIX_APPS_JSON` and value as only JSON content.
> Do **not** paste `WIX_APPS_JSON=...` into the value field, or parsing will fail.

Use this exact value for `WIX_APPS_JSON` (single line):

```env
WIX_APPS_JSON={"11c28482-01cc-4a0d-b1d5-0651e0fc0119":{"publicKey":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAprpllCqDfTtE29CKhrTL\n75fMSDzS49m+1ixnsJu3Pp0eukbOByR10Dqea5+lmSHKBpcOjSIfRUTbv4QU8yzp\nMwLIIo4UBaS8hdonscz8QJEmJuVoXJ9MSJmC0ZTdig5JFkxfbhJHo36aHOwPDOg/\nwCIwtR3iLnIdSt50G/8XNjzRHUmpBF+rVHgtWdcQLv+m3ajRl3IOL1kv9Hq2w7R7\ndYHCAQh9A2P20C4Bevpc++V9pzMACAXdezNGslpfrAIDTJpLTFaIQP/zkwAVE1DS\nF+CeiqxRqp624NkDOyGIkO3NgQz29uWOv372S/JOth3TiokXAu/KjSX1Vuom1VeZ\n7QIDAQAB\n-----END PUBLIC KEY-----","webhookSecret":"a6f9b2d7c1e843e7a10489cc"}}
```


## Member enrichment

The server handles both identity types from webhook metadata:

- `MEMBER`: tries Wix Members SDK lookup (`getMember` + query fallback)
- `WIX_USER`: stores Wix user identity details directly and uses event-origin email/name fallback when available

Stored fields:

- `userEmail` (owner/member email if available)
- `userName`
- `userId` (`memberId` or `wixUserId`)
- `memberDetails` (full member/identity JSON)

If lookup fails, install row is still written with available event fields.


## Google private key format troubleshooting

If you see OpenSSL errors like:

```text
Error: error:1E08010C:DECODER routines::unsupported
```

it usually means `GOOGLE_PRIVATE_KEY` is malformed in env config. This server now normalizes private keys by:

- removing wrapping quotes if present
- converting escaped `\n` to real newlines
- accepting base64/base64url key body and converting to PEM
- validating key at startup using `crypto.createPrivateKey`

**Render tip:** set env key as `GOOGLE_PRIVATE_KEY`, and value only as key content (do not prefix with `GOOGLE_PRIVATE_KEY=` in value field).


## RequestId correlation behavior

- Primary mapping uses webhook payload hints (`instanceId`, `originInstanceId`, `memberId`) to attach same numeric `requestId` in both sheets.
- If event arrives without a match, service generates a fallback numeric `requestId` so `Installs` is never blank.
