require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const { google } = require('googleapis');
const { createClient, AppStrategy } = require('@wix/sdk');
const { appInstances } = require('@wix/app-management');

const app = express();
const port = Number(process.env.PORT || 3000);
const webhookBasePath = process.env.WEBHOOK_BASE_PATH || process.env.WEBHOOK_PATH || '/webhooks/wix/install';

const spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID;
const installsSheetName = process.env.GOOGLE_INSTALLS_SHEET_NAME || 'Installs';
const logsSheetName = process.env.GOOGLE_LOGS_SHEET_NAME || 'WebhookLogs';
const wixApps = JSON.parse(process.env.WIX_APPS_JSON || '{}');

if (!spreadsheetId) {
  throw new Error('Missing GOOGLE_SPREADSHEET_ID');
}
if (!Object.keys(wixApps).length) {
  throw new Error('Missing WIX_APPS_JSON configuration');
}

app.disable('x-powered-by');
app.use(helmet());

function toGooglePrivateKey(rawKey) {
  if (!rawKey) return rawKey;
  return rawKey.replace(/\\n/g, '\n');
}

const auth = new google.auth.GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    private_key: toGooglePrivateKey(process.env.GOOGLE_PRIVATE_KEY)
  },
  scopes: ['https://www.googleapis.com/auth/spreadsheets']
});

const sheets = google.sheets({ version: 'v4', auth });

async function appendRow(sheetName, row) {
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${sheetName}!A:Z`,
    valueInputOption: 'USER_ENTERED',
    requestBody: {
      values: [row]
    }
  });
}

async function appendInstallRow(entry) {
  await appendRow(installsSheetName, [
    entry.requestId,
    entry.receivedAt,
    entry.eventName,
    entry.appId,
    entry.siteId,
    entry.instanceId,
    entry.userEmail,
    entry.userId,
    entry.region,
    entry.rawPayload
  ]);
}

async function appendWebhookLog(entry) {
  await appendRow(logsSheetName, [
    entry.requestId,
    entry.receivedAt,
    entry.status,
    entry.matchedAppId,
    entry.httpStatus,
    entry.errorMessage,
    entry.requestPath,
    entry.webhookSecret,
    entry.requestBody
  ]);
}

function createWixClient(appId, publicKey) {
  const client = createClient({
    auth: AppStrategy({
      appId,
      publicKey
    }),
    modules: { appInstances }
  });

  client.appInstances.onAppInstanceInstalled(async (event) => {
    const entry = {
      requestId: event?.metadata?.eventId || '',
      receivedAt: new Date().toISOString(),
      eventName: 'APP_INSTANCE_INSTALLED',
      appId,
      siteId: event?.metadata?.siteId || '',
      instanceId: event?.metadata?.instanceId || '',
      userEmail: event?.originatedFrom?.userEmail || event?.metadata?.userEmail || '',
      userId: event?.originatedFrom?.userId || event?.metadata?.userId || '',
      region: event?.originatedFrom?.metaSiteRegion || '',
      rawPayload: JSON.stringify(event)
    };

    try {
      await appendInstallRow(entry);
      console.log('Stored install event', { appId, instanceId: entry.instanceId });
    } catch (error) {
      console.error('Failed to append install row', { appId, error });
    }
  });

  return client;
}

const secretToClientMap = Object.entries(wixApps).reduce((acc, [appId, config]) => {
  const appConfig = typeof config === 'string' ? { publicKey: config } : config;
  const publicKey = appConfig.publicKey;
  const webhookSecret = appConfig.webhookSecret;

  if (!publicKey) {
    throw new Error(`Missing publicKey for app ${appId} in WIX_APPS_JSON`);
  }
  if (!webhookSecret) {
    throw new Error(`Missing webhookSecret for app ${appId} in WIX_APPS_JSON`);
  }
  if (acc[webhookSecret]) {
    throw new Error(`Duplicate webhookSecret found in WIX_APPS_JSON for app ${appId}`);
  }

  acc[webhookSecret] = {
    appId,
    client: createWixClient(appId, publicKey)
  };

  return acc;
}, {});

app.get('/healthz', (_req, res) => {
  res.json({
    ok: true,
    configuredApps: Object.keys(secretToClientMap).length,
    webhookPathPattern: `${webhookBasePath}/:webhookSecret`,
    installsSheetName,
    logsSheetName
  });
});

app.post(`${webhookBasePath}/:webhookSecret`, express.text({ type: '*/*', limit: '100kb' }), async (req, res) => {
  const requestId = crypto.randomUUID();
  const rawBody = req.body || '';
  const webhookSecret = req.params.webhookSecret || '';

  let matchedAppId = '';
  let httpStatus = 401;
  let status = 'FAILED';
  let errorMessage = 'Invalid webhook payload';

  try {
    const configured = secretToClientMap[webhookSecret];
    if (!configured) {
      httpStatus = 403;
      errorMessage = 'Unknown webhook secret';
      return res.status(403).json({ error: 'Unknown webhook secret' });
    }

    const { appId, client } = configured;

    try {
      await client.webhooks.process(rawBody);
      matchedAppId = appId;
      status = 'SUCCESS';
      httpStatus = 200;
      errorMessage = '';
      return res.status(200).send();
    } catch (error) {
      matchedAppId = appId;
      httpStatus = 401;
      errorMessage = error instanceof Error ? error.message : 'Invalid webhook payload';
      return res.status(401).json({ error: 'Invalid webhook payload for app' });
    }
  } catch (error) {
    status = 'FAILED';
    httpStatus = 500;
    errorMessage = error instanceof Error ? error.message : 'Internal server error';
    console.error('Webhook error', error);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    try {
      await appendWebhookLog({
        requestId,
        receivedAt: new Date().toISOString(),
        status,
        matchedAppId,
        httpStatus,
        errorMessage,
        requestPath: req.originalUrl,
        webhookSecret,
        requestBody: rawBody
      });
    } catch (logError) {
      console.error('Failed to append webhook log row', logError);
    }
  }
});

app.listen(port, () => {
  console.log(`Webhook API listening on port ${port} path pattern ${webhookBasePath}/:webhookSecret`);
});
