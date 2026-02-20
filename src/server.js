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

function sanitizeForSheet(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .trim();
}


function toBase64FromPem(value) {
  return value
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s+/g, '');
}

function normalizePublicKey(rawKey) {
  let value = String(rawKey || '').trim();
  if (!value) return '';

  // Handle accidental JSON-stringified value, e.g. ""-----BEGIN...""
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }

  value = value.replace(/\\n/g, '\n').trim();

  // Wix SDK helper may attempt atob() on provided key; passing PEM directly can fail.
  // Convert PEM to plain base64 body so atob() always gets valid characters.
  if (value.includes('BEGIN PUBLIC KEY')) {
    return toBase64FromPem(value);
  }

  // If it's base64url, convert to base64 before passing to SDK.
  if (/^[A-Za-z0-9_-]+$/.test(value) && (value.includes('-') || value.includes('_'))) {
    value = value.replace(/-/g, '+').replace(/_/g, '/');
  }

  // Add padding if missing.
  const mod = value.length % 4;
  if (mod) {
    value = value + '='.repeat(4 - mod);
  }

  return value;
}


function toPemFromBase64(value) {
  const chunks = value.match(/.{1,64}/g) || [];
  return '-----BEGIN PUBLIC KEY-----\n' + chunks.join('\n') + '\n-----END PUBLIC KEY-----';
}

function validateNormalizedPublicKey(publicKey) {
  if (!publicKey) {
    return { valid: false, reason: 'empty_public_key', fingerprint: '' };
  }

  if (!/^[A-Za-z0-9+/=]+$/.test(publicKey)) {
    return { valid: false, reason: 'non_base64_characters', fingerprint: '' };
  }

  try {
    const decoded = Buffer.from(publicKey, 'base64');
    if (!decoded.length) {
      return { valid: false, reason: 'decoded_key_is_empty', fingerprint: '' };
    }

    // Validate key structure with Node crypto parser for early startup feedback.
    const pem = toPemFromBase64(publicKey);
    crypto.createPublicKey(pem);

    return {
      valid: true,
      reason: '',
      fingerprint: crypto.createHash('sha256').update(publicKey).digest('hex').slice(0, 16)
    };
  } catch (error) {
    return {
      valid: false,
      reason: sanitizeForSheet(error instanceof Error ? error.message : String(error)),
      fingerprint: ''
    };
  }
}

function parseErrorContext(error) {
  if (!(error instanceof Error)) {
    return {
      errorMessage: sanitizeForSheet(String(error || 'Unknown error')),
      errorLine: '',
      errorStack: ''
    };
  }

  const stack = error.stack || '';
  const firstCodeLine = stack
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith('at '));

  return {
    errorMessage: sanitizeForSheet(error.message || 'Unknown error'),
    errorLine: sanitizeForSheet(firstCodeLine || ''),
    errorStack: sanitizeForSheet(stack.slice(0, 4000))
  };
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
    entry.failureStep,
    entry.errorMessage,
    entry.errorLine,
    entry.errorStack,
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
      const errorContext = parseErrorContext(error);
      console.error('Failed to append install row', { appId, ...errorContext });
    }
  });

  return client;
}

const publicKeyChecks = [];

const secretToClientMap = Object.entries(wixApps).reduce((acc, [appId, config]) => {
  const appConfig = typeof config === 'string' ? { publicKey: config } : config;
  const publicKey = normalizePublicKey(appConfig.publicKey);
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

  const keyValidation = validateNormalizedPublicKey(publicKey);
  publicKeyChecks.push({
    appId,
    valid: keyValidation.valid,
    reason: keyValidation.reason,
    fingerprint: keyValidation.fingerprint
  });

  if (!keyValidation.valid) {
    throw new Error(`Invalid publicKey for app ${appId}: ${keyValidation.reason}`);
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
    logsSheetName,
    publicKeyChecks
  });
});

app.post(`${webhookBasePath}/:webhookSecret`, express.text({ type: '*/*', limit: '100kb' }), async (req, res) => {
  const requestId = crypto.randomUUID();
  const rawBody = req.body || '';
  const webhookSecret = req.params.webhookSecret || '';

  let matchedAppId = '';
  let httpStatus = 401;
  let status = 'FAILED';
  let failureStep = 'init';
  let errorMessage = 'Invalid webhook payload';
  let errorLine = '';
  let errorStack = '';

  try {
    failureStep = 'resolve_secret';
    const configured = secretToClientMap[webhookSecret];
    if (!configured) {
      httpStatus = 403;
      errorMessage = 'Unknown webhook secret';
      return res.status(403).json({ error: 'Unknown webhook secret' });
    }

    const { appId, client } = configured;

    try {
      failureStep = 'wix_webhook_process';
      await client.webhooks.process(rawBody);
      matchedAppId = appId;
      status = 'SUCCESS';
      httpStatus = 200;
      failureStep = '';
      errorMessage = '';
      return res.status(200).send();
    } catch (error) {
      const errorContext = parseErrorContext(error);
      matchedAppId = appId;
      httpStatus = 401;
      errorMessage = errorContext.errorMessage;
      errorLine = errorContext.errorLine;
      errorStack = errorContext.errorStack;
      console.error('Webhook verification failed', {
        requestId,
        appId,
        failureStep,
        errorMessage,
        errorLine
      });
      return res.status(401).json({ error: 'Invalid webhook payload for app' });
    }
  } catch (error) {
    const errorContext = parseErrorContext(error);
    status = 'FAILED';
    httpStatus = 500;
    failureStep = failureStep || 'unexpected_error';
    errorMessage = errorContext.errorMessage;
    errorLine = errorContext.errorLine;
    errorStack = errorContext.errorStack;
    console.error('Webhook error', {
      requestId,
      failureStep,
      errorMessage,
      errorLine
    });
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    try {
      await appendWebhookLog({
        requestId,
        receivedAt: new Date().toISOString(),
        status,
        matchedAppId,
        httpStatus,
        failureStep,
        errorMessage,
        errorLine,
        errorStack,
        requestPath: req.originalUrl,
        webhookSecret,
        requestBody: rawBody
      });
    } catch (logError) {
      const logErrorContext = parseErrorContext(logError);
      console.error('Failed to append webhook log row', {
        requestId,
        errorMessage: logErrorContext.errorMessage,
        errorLine: logErrorContext.errorLine
      });
    }
  }
});

app.listen(port, () => {
  console.log(`Webhook API listening on port ${port} path pattern ${webhookBasePath}/:webhookSecret`);
  console.log('Public key validation summary', publicKeyChecks);
});
