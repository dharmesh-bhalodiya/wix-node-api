require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const axios = require('axios');
const { google } = require('googleapis');
const { createClient, AppStrategy } = require('@wix/sdk');
const { appInstances } = require('@wix/app-management');

const app = express();
const port = Number(process.env.PORT || 3000);

const webhookBasePath =
  process.env.WEBHOOK_BASE_PATH ||
  process.env.WEBHOOK_PATH ||
  '/webhooks/wix/install';

const spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID;
const installsSheetName =
  process.env.GOOGLE_INSTALLS_SHEET_NAME || 'Installs';
const logsSheetName =
  process.env.GOOGLE_LOGS_SHEET_NAME || 'WebhookLogs';

if (!spreadsheetId) {
  throw new Error('Missing GOOGLE_SPREADSHEET_ID');
}

/* =========================
   WIX APPS CONFIG
========================= */

function parseWixAppsConfig(rawValue) {
  const value = String(rawValue || '').trim();
  if (!value) {
    throw new Error('Missing WIX_APPS_JSON configuration');
  }
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('WIX_APPS_JSON must be JSON object keyed by appId');
  }
  return parsed;
}

const wixApps = parseWixAppsConfig(process.env.WIX_APPS_JSON);

/* =========================
   GOOGLE SHEETS
========================= */

function normalizeGooglePrivateKey(rawKey) {
  return String(rawKey || '').replace(/\\n/g, '\n');
}

const auth = new google.auth.GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    private_key: normalizeGooglePrivateKey(process.env.GOOGLE_PRIVATE_KEY)
  },
  scopes: ['https://www.googleapis.com/auth/spreadsheets']
});

const sheets = google.sheets({ version: 'v4', auth });

function sanitize(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,
    ' '
  );
}

async function appendRow(sheetName, row) {
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${sheetName}!A:Z`,
    valueInputOption: 'USER_ENTERED',
    requestBody: {
      values: [row.map((c) => sanitize(c))]
    }
  });
}

/* =========================
   REQUEST COUNTER
========================= */

let requestCounter = null;
let counterQueue = Promise.resolve();

async function initializeRequestCounter() {
  if (requestCounter !== null) return;

  const result = await sheets.spreadsheets.values.get({
    spreadsheetId,
    range: `${logsSheetName}!A:A`
  });

  const values = result.data.values || [];
  let max = 0;

  for (const row of values) {
    const num = Number.parseInt(String(row?.[0] || ''), 10);
    if (!Number.isNaN(num) && num > max) {
      max = num;
    }
  }

  requestCounter = max;
}

function getNextRequestId() {
  const next = counterQueue.then(async () => {
    await initializeRequestCounter();
    requestCounter += 1;
    return String(requestCounter);
  });

  counterQueue = next.then(() => undefined, () => undefined);
  return next;
}

/* =========================
   OAUTH TOKEN CACHE
========================= */

const oauthCache = new Map();

async function getOAuthToken(appId, appSecret, instanceId) {
  const cacheKey = `${appId}:${instanceId}`;
  const cached = oauthCache.get(cacheKey);

  if (cached && cached.expiresAt > Date.now()) {
    return cached.token;
  }

  const response = await axios.post(
    'https://www.wixapis.com/oauth2/token',
    {
      grant_type: 'client_credentials',
      client_id: appId,
      client_secret: appSecret,
      instance_id: instanceId
    },
    {
      headers: { 'Content-Type': 'application/json' },
      timeout: 8000
    }
  );

  const token = response.data.access_token;
  const expiresIn = response.data.expires_in || 3600;

  oauthCache.set(cacheKey, {
    token,
    expiresAt: Date.now() + (expiresIn - 60) * 1000
  });

  return token;
}

async function getAppInstance(appId, appSecret, instanceId) {
  const token = await getOAuthToken(appId, appSecret, instanceId);

  const response = await axios.get(
    `https://www.wixapis.com/apps/v1/app-instances/${instanceId}`,
    {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 8000
    }
  );

  return response.data;
}

/* =========================
   MULTI APP INIT
========================= */

const secretMap = {};

for (const [appId, config] of Object.entries(wixApps)) {
  const client = createClient({
    auth: AppStrategy({
      appId,
      publicKey: config.publicKey
    }),
    modules: { appInstances }
  });

  secretMap[config.webhookSecret] = {
    appId,
    appSecret: config.appSecret,
    client
  };
}

/* =========================
   SERVER
========================= */

app.disable('x-powered-by');
app.use(helmet());

app.get('/healthz', (_req, res) => {
  res.json({ ok: true });
});

app.post(
  `${webhookBasePath}/:webhookSecret`,
  express.text({ type: '*/*', limit: '100kb' }),
  async (req, res) => {
    const requestId = await getNextRequestId();
    const timestamp = new Date().toISOString();
    const rawBody = req.body || '';
    const webhookSecret = req.params.webhookSecret;

    let status = 'FAILED';
    let statusCode = 500;
    let errorStep = '';
    let errorMessage = '';
    let appId = '';
    let instanceId = '';

    try {
      const configured = secretMap[webhookSecret];

      if (!configured) {
        statusCode = 403;
        errorStep = 'resolve_secret';
        errorMessage = 'Unknown webhook secret';
        return res.status(403).json({ error: errorMessage });
      }

      appId = configured.appId;

      // THIS LINE IS YOUR ORIGINAL WORKING FLOW
      const webhookData = await configured.client.webhooks.process(rawBody);

      instanceId = webhookData?.data?.instanceId || '';

      let ownerEmail = '';
      let ownerName = '';
      let websiteDomain = '';
      let rawInstancePayload = '';

      if (instanceId) {
        try {
          const appInstance = await getAppInstance(
            configured.appId,
            configured.appSecret,
            instanceId
          );

          ownerEmail = appInstance?.site?.ownerInfo?.email || '';
          ownerName = appInstance?.site?.ownerInfo?.name || '';
          websiteDomain = appInstance?.site?.domain || '';
          rawInstancePayload = JSON.stringify(appInstance);
        } catch (oauthErr) {
          errorStep = 'oauth_get_app_instance';
          errorMessage = oauthErr.message;
        }
      }

      await appendRow(installsSheetName, [
        requestId,
        timestamp,
        'APP_INSTANCE_INSTALLED',
        appId,
        '',
        instanceId,
        ownerEmail,
        ownerName,
        '',
        rawInstancePayload,
        '',
        websiteDomain,
        rawBody
      ]);

      status = 'SUCCESS';
      statusCode = 200;

      return res.status(200).send();
    } catch (err) {
      statusCode = 401;
      errorStep = errorStep || 'webhook_processing';
      errorMessage = err.message;
      return res.status(statusCode).json({ error: 'Webhook failed' });
    } finally {
      try {
        await appendRow(logsSheetName, [
          requestId,
          timestamp,
          status,
          appId,
          statusCode,
          errorStep,
          errorMessage,
          '',
          '',
          req.originalUrl,
          webhookSecret,
          rawBody
        ]);
      } catch (logErr) {
        console.error('Logging failed', logErr.message);
      }
    }
  }
);

app.listen(port, () => {
  console.log(
    `Webhook server running on port ${port} (${webhookBasePath}/:webhookSecret)`
  );
});
