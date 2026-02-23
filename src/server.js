require('dotenv').config();

const crypto = require('crypto');
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

/* ============================================================
   WIX APPS CONFIG
============================================================ */

function parseWixAppsConfig(rawValue) {
  const value = String(rawValue || '').trim();
  if (!value) throw new Error('Missing WIX_APPS_JSON');

  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid JSON structure');
    }
    return parsed;
  } catch (err) {
    throw new Error('Invalid WIX_APPS_JSON format');
  }
}

const wixApps = parseWixAppsConfig(process.env.WIX_APPS_JSON);

if (!Object.keys(wixApps).length) {
  throw new Error('WIX_APPS_JSON must contain at least one app');
}

/* ============================================================
   GOOGLE SHEETS
============================================================ */

function normalizePrivateKey(key) {
  return key.replace(/\\n/g, '\n');
}

const auth = new google.auth.GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    private_key: normalizePrivateKey(process.env.GOOGLE_PRIVATE_KEY)
  },
  scopes: ['https://www.googleapis.com/auth/spreadsheets']
});

const sheets = google.sheets({ version: 'v4', auth });

async function appendRow(sheetName, row) {
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${sheetName}!A:Z`,
    valueInputOption: 'USER_ENTERED',
    requestBody: { values: [row] }
  });
}

/* ============================================================
   OAUTH TOKEN CACHE (Production Optimized)
============================================================ */

const oauthTokenCache = new Map();

async function getOAuthAccessToken(appId, appSecret, instanceId) {
  const cacheKey = `${appId}:${instanceId}`;
  const cached = oauthTokenCache.get(cacheKey);

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

  oauthTokenCache.set(cacheKey, {
    token,
    expiresAt: Date.now() + (expiresIn - 60) * 1000
  });

  return token;
}

async function getAppInstanceViaOAuth(appId, appSecret, instanceId) {
  const token = await getOAuthAccessToken(appId, appSecret, instanceId);

  const response = await axios.get(
    `https://www.wixapis.com/apps/v1/app-instances/${instanceId}`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      },
      timeout: 8000
    }
  );

  return response.data;
}

/* ============================================================
   WIX CLIENT CREATION
============================================================ */

function createWixClient(appId, publicKey) {
  const client = createClient({
    auth: AppStrategy({ appId, publicKey }),
    modules: { appInstances }
  });

  return client;
}

/* ============================================================
   MULTI APP INITIALIZATION
============================================================ */

const secretToClientMap = {};

for (const [appId, config] of Object.entries(wixApps)) {
  if (!config.publicKey) {
    throw new Error(`Missing publicKey for app ${appId}`);
  }
  if (!config.webhookSecret) {
    throw new Error(`Missing webhookSecret for app ${appId}`);
  }
  if (!config.appSecret) {
    throw new Error(`Missing appSecret for app ${appId}`);
  }

  secretToClientMap[config.webhookSecret] = {
    appId,
    appSecret: config.appSecret,
    client: createWixClient(appId, config.publicKey)
  };
}

/* ============================================================
   SERVER SETUP
============================================================ */

app.disable('x-powered-by');
app.use(helmet());

app.get('/healthz', (_req, res) => {
  res.json({
    ok: true,
    configuredApps: Object.keys(secretToClientMap).length
  });
});

/* ============================================================
   WEBHOOK HANDLER
============================================================ */

app.post(
  `${webhookBasePath}/:webhookSecret`,
  express.text({ type: '*/*', limit: '100kb' }),
  async (req, res) => {
    const rawBody = req.body || '';
    const webhookSecret = req.params.webhookSecret;

    const configured = secretToClientMap[webhookSecret];

    if (!configured) {
      return res.status(403).json({ error: 'Unknown webhook secret' });
    }

    const { appId, appSecret, client } = configured;

    try {
      await client.webhooks.process(rawBody);

      const payload = JSON.parse(
        Buffer.from(rawBody.split('.')[1], 'base64url').toString()
      );

      const instanceId =
        payload?.data?.instanceId ||
        payload?.metadata?.instanceId ||
        '';

      let ownerEmail = '';
      let ownerName = '';
      let websiteDomain = '';
      let rawInstance = '';

      if (instanceId) {
        try {
          const appInstance = await getAppInstanceViaOAuth(
            appId,
            appSecret,
            instanceId
          );

          ownerEmail = appInstance?.site?.ownerInfo?.email || '';
          ownerName = appInstance?.site?.ownerInfo?.name || '';
          websiteDomain = appInstance?.site?.domain || '';
          rawInstance = JSON.stringify(appInstance);
        } catch (oauthErr) {
          console.error('OAuth failure:', oauthErr.message);
        }
      }

      await appendRow(installsSheetName, [
        new Date().toISOString(),
        appId,
        instanceId,
        ownerEmail,
        ownerName,
        websiteDomain,
        rawInstance
      ]);

      return res.status(200).send();
    } catch (err) {
      await appendRow(logsSheetName, [
        new Date().toISOString(),
        appId,
        err.message,
        rawBody
      ]);

      return res.status(401).json({ error: 'Invalid webhook payload' });
    }
  }
);

app.listen(port, () => {
  console.log(
    `Webhook server running on port ${port} at ${webhookBasePath}/:webhookSecret`
  );
});
