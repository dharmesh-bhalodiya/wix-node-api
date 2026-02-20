require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const { google } = require('googleapis');

const app = express();
const port = Number(process.env.PORT || 3000);

const webhookToken = process.env.WEBHOOK_TOKEN;
const spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID;
const sheetName = process.env.GOOGLE_SHEET_NAME || 'Installs';
const appSecrets = JSON.parse(process.env.WIX_APP_SECRETS_JSON || '{}');

if (!webhookToken) {
  throw new Error('Missing WEBHOOK_TOKEN');
}
if (!spreadsheetId) {
  throw new Error('Missing GOOGLE_SPREADSHEET_ID');
}

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({
  limit: '100kb',
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

function timingSafeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function extractAppId(req) {
  return (
    req.body?.appId ||
    req.body?.app_id ||
    req.headers['x-app-id'] ||
    req.query.appId ||
    null
  );
}

function verifyStaticToken(req, res, next) {
  const headerToken = req.headers['x-webhook-token'];
  if (!timingSafeEqual(headerToken, webhookToken)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  return next();
}

function verifyWixSignature(req, res, next) {
  const appId = extractAppId(req);
  if (!appId) {
    return res.status(400).json({ error: 'appId is required' });
  }

  const appSecret = appSecrets[appId];
  if (!appSecret) {
    return res.status(403).json({ error: `App ${appId} is not allowed` });
  }

  const wixSignature = req.headers['x-wix-signature'];
  if (!wixSignature) {
    return res.status(401).json({ error: 'Missing x-wix-signature' });
  }

  const expected = crypto
    .createHmac('sha256', appSecret)
    .update(req.rawBody || '')
    .digest('hex');

  if (!timingSafeEqual(expected, wixSignature)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  req.appId = appId;
  return next();
}

function toGooglePrivateKey(rawKey) {
  if (!rawKey) return rawKey;
  return rawKey.replace(/\\n/g, '\n');
}

async function appendInstallRow(entry) {
  const auth = new google.auth.GoogleAuth({
    credentials: {
      client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
      private_key: toGooglePrivateKey(process.env.GOOGLE_PRIVATE_KEY)
    },
    scopes: ['https://www.googleapis.com/auth/spreadsheets']
  });

  const sheets = google.sheets({ version: 'v4', auth });

  const row = [
    entry.receivedAt,
    entry.eventName,
    entry.appId,
    entry.siteId,
    entry.instanceId,
    entry.userEmail,
    entry.userId,
    entry.region,
    entry.rawPayload
  ];

  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${sheetName}!A:I`,
    valueInputOption: 'USER_ENTERED',
    requestBody: {
      values: [row]
    }
  });
}

app.get('/healthz', (_req, res) => {
  res.json({ ok: true });
});

app.post('/webhooks/wix/install', verifyStaticToken, verifyWixSignature, async (req, res) => {
  try {
    const payload = req.body || {};

    const entry = {
      receivedAt: new Date().toISOString(),
      eventName: payload.eventType || payload.eventName || 'unknown',
      appId: req.appId,
      siteId: payload.siteId || payload.site_id || '',
      instanceId: payload.instanceId || payload.instance_id || '',
      userEmail: payload.user?.email || payload.email || '',
      userId: payload.user?.id || payload.userId || '',
      region: payload.region || '',
      rawPayload: JSON.stringify(payload)
    };

    await appendInstallRow(entry);
    return res.status(202).json({ accepted: true });
  } catch (error) {
    console.error('Failed to process webhook', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Webhook API listening on port ${port}`);
});
