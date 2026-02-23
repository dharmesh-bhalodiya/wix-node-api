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

const wixApps = JSON.parse(process.env.WIX_APPS_JSON);

if (!spreadsheetId) {
  throw new Error('Missing GOOGLE_SPREADSHEET_ID');
}

const pendingRequestIds = new Map();

/* ============================================================
   GOOGLE PRIVATE KEY NORMALIZATION
============================================================ */

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

/* ============================================================
   SANITIZER
============================================================ */

function sanitizeForSheet(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .trim();
}

/* ============================================================
   REQUEST COUNTER
============================================================ */

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
    const value = Number.parseInt(String(row?.[0] || '').trim(), 10);
    if (!Number.isNaN(value) && value > max) {
      max = value;
    }
  }

  requestCounter = max;
}

function getNextRequestId() {
  const nextTask = counterQueue.then(async () => {
    await initializeRequestCounter();
    requestCounter += 1;
    return String(requestCounter);
  });

  counterQueue = nextTask.then(() => undefined, () => undefined);
  return nextTask;
}

/* ============================================================
   APPEND HELPERS
============================================================ */

async function appendRow(sheetName, row) {
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${sheetName}!A:Z`,
    valueInputOption: 'USER_ENTERED',
    requestBody: {
      values: [row.map((cell) => sanitizeForSheet(cell))]
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
    entry.userName,
    entry.userId,
    entry.memberDetails,
    entry.region,
    entry.websiteDomain,
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
    entry.errorStack,
    entry.requestPath,
    entry.webhookSecret,
    entry.requestBody
  ]);
}

/* ============================================================
   ✅ FIXED OAUTH OWNER FETCH (Correct Endpoint)
============================================================ */

async function fetchOwnerFromOAuth(appId, appSecret, instanceId) {
  try {
    const tokenResponse = await axios.post(
      'https://www.wixapis.com/oauth2/token',
      {
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: appSecret,
        instance_id: instanceId
      },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const accessToken = tokenResponse.data?.access_token;

    if (!accessToken) {
      throw new Error('OAuth token not returned');
    }

    const instanceResponse = await axios.get(
      'https://www.wixapis.com/apps/v1/instance',
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const appInstance = instanceResponse.data;

    return {
      email: appInstance?.site?.ownerInfo?.email || '',
      name: appInstance?.site?.ownerInfo?.name || '',
      websiteDomain: appInstance?.site?.domain || '',
      raw: JSON.stringify(appInstance)
    };
  } catch (error) {
    console.error(
      'Owner fetch error:',
      error.response?.data || error.message
    );

    return {
      email: '',
      name: '',
      websiteDomain: '',
      raw: JSON.stringify({
        error: error.response?.data || error.message
      })
    };
  }
}

/* ============================================================
   IDENTITY DETAILS (ONLY OWNER LOGIC)
============================================================ */

async function fetchIdentityDetails(client, identity, appId) {
  try {
    const instanceId =
      identity?.instanceId ||
      identity?.originInstanceId ||
      '';

    const appConfig = wixApps[appId];
    const appSecret = appConfig?.appSecret;

    if (!instanceId || !appSecret) {
      throw new Error('Missing instanceId or appSecret');
    }

    const owner = await fetchOwnerFromOAuth(
      appId,
      appSecret,
      instanceId
    );

    return {
      email: owner.email,
      name: owner.name,
      userId: '',
      websiteDomain: owner.websiteDomain,
      raw: owner.raw
    };
  } catch (error) {
    console.error('Identity fetch error:', error.message);

    return {
      email: '',
      name: '',
      userId: '',
      websiteDomain: '',
      raw: JSON.stringify({ error: error.message })
    };
  }
}

/* ============================================================
   WIX CLIENT INITIALIZATION
============================================================ */

function createWixClient(appId, publicKey) {
  const client = createClient({
    auth: AppStrategy({ appId, publicKey }),
    modules: { appInstances }
  });

  client.appInstances.onAppInstanceInstalled(async (event, context) => {
    const identity = {
      instanceId:
        event?.metadata?.instanceId ||
        event?.instanceId ||
        '',
      originInstanceId:
        event?.data?.originInstanceId ||
        '',
      websiteDomain:
        event?.metadata?.siteDomain ||
        ''
    };

    const memberDetails = await fetchIdentityDetails(
      client,
      identity,
      appId
    );

    
    const entry = {
      requestId: pendingRequestIds.get(event?.metadata?.id) || await getNextRequestId(),
      receivedAt: new Date().toISOString(),
      eventName: 'APP_INSTANCE_INSTALLED',
      appId,
      siteId: event?.metadata?.siteId || '',
      instanceId: identity.instanceId,
      userEmail: memberDetails.email,
      userName: memberDetails.name,
      userId: '',
      memberDetails: memberDetails.raw,
      region: event?.originatedFrom?.metaSiteRegion || '',
      websiteDomain: memberDetails.websiteDomain,
      rawPayload: JSON.stringify(event)
    };

    await appendInstallRow(entry);
  });

  return client;
}

/* ============================================================
   SECRET MAP
============================================================ */

const secretToClientMap = Object.entries(wixApps).reduce(
  (acc, [appId, config]) => {
    acc[config.webhookSecret] = {
      appId,
      client: createWixClient(appId, config.publicKey)
    };
    return acc;
  },
  {}
);

/* ============================================================
   WEBHOOK ROUTE (FIXED matchedAppId logging)
============================================================ */

app.disable('x-powered-by');
app.use(helmet());

app.post(
  `${webhookBasePath}/:webhookSecret`,
  express.text({ type: '*/*', limit: '100kb' }),
  async (req, res) => {
    const requestId = await getNextRequestId();
    const rawBody = req.body || '';
    const webhookSecret = req.params.webhookSecret || '';

    let status = 'FAILED';
    let httpStatus = '';
    let errorMessage = '';
    let errorStack = '';
    let matchedAppId = '';

    try {
      const configured = secretToClientMap[webhookSecret];

      if (!configured) {
        httpStatus = 403;
        throw new Error('Unknown webhook secret');
      }

      matchedAppId = configured.appId;

      pendingRequestIds.set(req.headers['x-wix-event-id'], requestId);
      await configured.client.webhooks.process(rawBody);
      pendingRequestIds.delete(req.headers['x-wix-event-id']);
      
      
      status = 'SUCCESS';
      httpStatus = 200;

      return res.status(200).send();
    } catch (error) {
      httpStatus = 500;
      errorMessage = error.message;
      errorStack = error.stack;
      return res.status(httpStatus).json({ error: errorMessage });
    } finally {
      await appendWebhookLog({
        requestId,
        receivedAt: new Date().toISOString(),
        status,
        matchedAppId,
        httpStatus,
        errorMessage,
        errorStack,
        requestPath: req.originalUrl,
        webhookSecret,
        requestBody: rawBody
      });
    }
  }
);

app.get('/healthz', (_req, res) => {
  res.json({
    ok: true,
    configuredApps: Object.keys(secretToClientMap).length,
    webhookPathPattern: `${webhookBasePath}/:webhookSecret`,
    installsSheetName,
    logsSheetName
  });
});

app.listen(port, () => {
  console.log(
    `Webhook API listening on port ${port} path pattern ${webhookBasePath}/:webhookSecret`
  );
});
