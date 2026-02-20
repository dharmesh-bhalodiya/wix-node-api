require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const { google } = require('googleapis');
const { createClient, AppStrategy } = require('@wix/sdk');
const { appInstances } = require('@wix/app-management');
const { members } = require('@wix/members');
const { contacts } = require('@wix/crm');

const app = express();
const port = Number(process.env.PORT || 3000);
const webhookBasePath = process.env.WEBHOOK_BASE_PATH || process.env.WEBHOOK_PATH || '/webhooks/wix/install';

const spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID;
const installsSheetName = process.env.GOOGLE_INSTALLS_SHEET_NAME || 'Installs';
const logsSheetName = process.env.GOOGLE_LOGS_SHEET_NAME || 'WebhookLogs';
const wixApps = parseWixAppsConfig(process.env.WIX_APPS_JSON);

if (!spreadsheetId) {
  throw new Error('Missing GOOGLE_SPREADSHEET_ID');
}
if (!Object.keys(wixApps).length) {
  throw new Error('WIX_APPS_JSON must include at least 1 app configuration');
}

function parseWixAppsConfig(rawValue) {
  const value = String(rawValue || '').trim();

  if (!value) {
    throw new Error('Missing WIX_APPS_JSON configuration');
  }

  const jsonCandidate = value.startsWith('WIX_APPS_JSON=')
    ? value.slice('WIX_APPS_JSON='.length).trim()
    : value;

  try {
    const parsed = JSON.parse(jsonCandidate);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('WIX_APPS_JSON must be a JSON object keyed by appId');
    }
    return parsed;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid WIX_APPS_JSON value. Ensure env contains only raw JSON object (not prefixed with WIX_APPS_JSON=). Parse error: ${reason}`);
  }
}

app.disable('x-powered-by');
app.use(helmet());

function toPemFromBase64PrivateKey(value) {
  const chunks = value.match(/.{1,64}/g) || [];
  return '-----BEGIN PRIVATE KEY-----\n' + chunks.join('\n') + '\n-----END PRIVATE KEY-----';
}

function normalizeGooglePrivateKey(rawKey) {
  let value = String(rawKey || '').trim();
  if (!value) return '';

  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }

  value = value.replace(/\\n/g, '\n').trim();


  if (value.includes('BEGIN PRIVATE KEY')) {
    return value;
  }

  if (/^[A-Za-z0-9_-]+$/.test(value) && (value.includes('-') || value.includes('_'))) {
    value = value.replace(/-/g, '+').replace(/_/g, '/');
  }

  const mod = value.length % 4;
  if (mod) {
    value = value + '='.repeat(4 - mod);
  }

  if (/^[A-Za-z0-9+/=]+$/.test(value)) {
    return toPemFromBase64PrivateKey(value);
  }

  return value;
}

function validateGooglePrivateKey(privateKeyPem) {
  if (!privateKeyPem) {
    throw new Error('Missing GOOGLE_PRIVATE_KEY');
  }

  try {
    crypto.createPrivateKey(privateKeyPem);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid GOOGLE_PRIVATE_KEY format. Ensure it is a PKCS8 PEM key (or base64 body) with proper newline escaping. Parse error: ${reason}`);
  }
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

function toPemFromBase64(value) {
  const chunks = value.match(/.{1,64}/g) || [];
  return '-----BEGIN PUBLIC KEY-----\n' + chunks.join('\n') + '\n-----END PUBLIC KEY-----';
}

function normalizePublicKey(rawKey) {
  let value = String(rawKey || '').trim();
  if (!value) return '';

  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }

  value = value.replace(/\\n/g, '\n').trim();

  value = value.replace(/\\n/g, '\n').trim();

  if (value.includes('BEGIN PUBLIC KEY')) {
    return value;
  }

  if (/^[A-Za-z0-9_-]+$/.test(value) && (value.includes('-') || value.includes('_'))) {
    value = value.replace(/-/g, '+').replace(/_/g, '/');
  }

  const mod = value.length % 4;
  if (mod) {
    value = value + '='.repeat(4 - mod);
  }

  if (/^[A-Za-z0-9+/=]+$/.test(value)) {
    return toPemFromBase64(value);
  }

  return value;
}

function validateNormalizedPublicKey(publicKey) {
  if (!publicKey) {
    return { valid: false, reason: 'empty_public_key', fingerprint: '' };
  }

  try {
    const normalizedPem = publicKey.includes('BEGIN PUBLIC KEY')
      ? publicKey
      : toPemFromBase64(toBase64FromPem(publicKey));

    crypto.createPublicKey(normalizedPem);

    return {
      valid: true,
      reason: '',
      fingerprint: crypto.createHash('sha256').update(normalizedPem).digest('hex').slice(0, 16)
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

function decodeJwtPayload(rawBody) {
  try {
    const [, payloadPart] = String(rawBody || '').split('.');
    if (!payloadPart) return null;
    const payloadText = Buffer.from(payloadPart, 'base64url').toString('utf8');
    return JSON.parse(payloadText);
  } catch (_error) {
    return null;
  }
}

function tryParseJson(value) {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch (_error) {
    return value;
  }
}

function extractRequestHints(rawBody) {
  const payload = decodeJwtPayload(rawBody);
  let envelope = payload?.data;

  if (!envelope) {
    try {
      envelope = JSON.parse(String(rawBody || '{}'));
    } catch (_error) {
      envelope = {};
    }
  }

  envelope = tryParseJson(envelope) || {};

  const metadata = tryParseJson(envelope.metadata) || {};
  const identity = tryParseJson(metadata.identity) || tryParseJson(envelope.identity) || {};
  const dataSection = tryParseJson(envelope.data) || {};

  return {
    instanceId: metadata.instanceId || envelope.instanceId || dataSection.instanceId || '',
    originInstanceId: dataSection.originInstanceId || metadata.originInstanceId || '',
    identityType: identity.identityType || '',
    memberId: identity.memberId || '',
    wixUserId: identity.wixUserId || '',
    appId: dataSection.appId || envelope.appId || ''
  };
}

const auth = new google.auth.GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    private_key: normalizeGooglePrivateKey(process.env.GOOGLE_PRIVATE_KEY)
  },
  scopes: ['https://www.googleapis.com/auth/spreadsheets']
});

validateGooglePrivateKey(normalizeGooglePrivateKey(process.env.GOOGLE_PRIVATE_KEY));

const sheets = google.sheets({ version: 'v4', auth });

let requestCounter = null;
let counterQueue = Promise.resolve();
const pendingRequestsByKey = new Map();

async function initializeRequestCounter() {
  if (requestCounter !== null) {
    return;
  }

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


function setPendingRequest(hints, requestId) {
  const record = {
    requestId,
    memberId: hints.memberId || '',
    wixUserId: hints.wixUserId || '',
    identityType: hints.identityType || '',
    appId: hints.appId || '',
    createdAt: Date.now()
  };

  const keys = [hints.instanceId, hints.originInstanceId, hints.memberId, hints.wixUserId].filter(Boolean);
  for (const key of keys) {
    pendingRequestsByKey.set(key, record);
  }
}

function getPendingRequest(event) {
  const keys = [
    event?.metadata?.instanceId,
    event?.instanceId,
    event?.data?.originInstanceId,
    event?.metadata?.originInstanceId,
    event?.metadata?.identity?.memberId,
    event?.identity?.memberId,
    event?.metadata?.identity?.wixUserId,
    event?.identity?.wixUserId
  ].filter(Boolean);

  for (const key of keys) {
    if (pendingRequestsByKey.has(key)) {
      return pendingRequestsByKey.get(key);
    }
  }

  return null;
}

function clearPendingRequest(event) {
  const keys = [
    event?.metadata?.instanceId,
    event?.instanceId,
    event?.data?.originInstanceId,
    event?.metadata?.originInstanceId,
    event?.metadata?.identity?.memberId,
    event?.identity?.memberId,
    event?.metadata?.identity?.wixUserId,
    event?.identity?.wixUserId
  ].filter(Boolean);

  for (const key of keys) {
    pendingRequestsByKey.delete(key);
  }
}

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

async function extractContactDetails(contactLike) {
  if (!contactLike) return null;
  const contact = contactLike.contact || contactLike;
  const info = contact.info || {};

  const email =
    contact?.primaryInfo?.email ||
    info?.emails?.items?.[0]?.email ||
    info?.emails?.[0]?.email ||
    contact?.emails?.[0]?.email ||
    '';

  const name =
    contact?.primaryInfo?.name ||
    [info?.name?.first, info?.name?.last].filter(Boolean).join(' ').trim() ||
    contact?.name ||
    '';

  if (!email && !name) return null;

  return {
    email,
    name,
    raw: JSON.stringify(contact)
  };
}

async function queryContactByIdentity(client, identity) {
  const wixUserId = identity?.wixUserId || '';
  const memberId = identity?.memberId || '';

  const candidateQueries = [
    async () => {
      const q = client.contacts?.queryContacts?.();
      if (!q?.eq) return null;
      const res = await q.eq('info.extendedFields.wixUserId', wixUserId).find();
      return res?.items?.[0] || null;
    },
    async () => {
      const q = client.contacts?.queryContacts?.();
      if (!q?.eq) return null;
      const res = await q.eq('info.extendedFields.memberId', memberId).find();
      return res?.items?.[0] || null;
    },
    async () => {
      const q = client.contacts?.queryContacts?.();
      if (!q?.hasSome || !memberId) return null;
      const res = await q.hasSome('info.extendedFields.memberId', [memberId]).find();
      return res?.items?.[0] || null;
    }
  ];

  for (const runQuery of candidateQueries) {
    try {
      const contact = await runQuery();
      const details = await extractContactDetails(contact);
      if (details?.email) {
        return details;
      }
    } catch (_error) {
      // continue
    }
  }

  return null;
}

async function fetchIdentityDetails(client, identity) {
  const identityType = identity?.identityType || '';
  const memberId = identity?.memberId || '';
  const wixUserId = identity?.wixUserId || '';

  const contactDetails = await queryContactByIdentity(client, identity);
  if (contactDetails?.email) {
    return {
      email: contactDetails.email,
      name: contactDetails.name || identity?.originatedName || '',
      userId: memberId || wixUserId,
      raw: contactDetails.raw
    };
  }

  if (identityType === 'WIX_USER') {
    return {
      email: identity?.originatedEmail || '',
      name: identity?.originatedName || '',
      userId: wixUserId,
      raw: JSON.stringify({ identityType, wixUserId, lookup: 'wix_user_no_contact_email' })
    };
  }

  if (!memberId) {
    return {
      email: identity?.originatedEmail || '',
      name: identity?.originatedName || '',
      userId: wixUserId || memberId,
      raw: JSON.stringify({ identityType, memberId, wixUserId, lookup: 'no_member_id' })
    };
  }

  const candidates = [
    async () => client.members?.getMember?.(memberId),
    async () => client.members?.getMember?.({ memberId }),
    async () => client.members?.getMember?.({ id: memberId }),
    async () => {
      const q = client.members?.queryMembers?.();
      if (!q?.hasSome) return null;
      const result = await q.hasSome('id', [memberId]).find();
      return result?.items?.[0] || null;
    }
  ];

  for (const tryCall of candidates) {
    try {
      const response = await tryCall();
      if (!response) continue;
      const member = response.member || response;
      const profile = member.profile || member.contact || member.info || {};
      const privacy = member.privacyStatus || member.privacy || {};

      const emails = [
        profile.email,
        member.loginEmail,
        member.primaryEmail,
        member?.contactDetails?.emails?.[0]?.email,
        member?.contact?.emails?.[0]?.email,
        privacy?.email,
        identity?.originatedEmail
      ].filter(Boolean);

      const names = [
        profile.nickname,
        profile.name,
        [profile.firstName, profile.lastName].filter(Boolean).join(' ').trim(),
        member.name,
        member?.contact?.name,
        identity?.originatedName
      ].filter(Boolean);

      return {
        email: emails[0] || '',
        name: names[0] || '',
        userId: memberId,
        raw: JSON.stringify(member)
      };
    } catch (_error) {
      // continue
    }
  }

  return {
    email: identity?.originatedEmail || '',
    name: identity?.originatedName || '',
    userId: memberId,
    raw: JSON.stringify({ identityType, memberId, wixUserId, lookup: 'member_not_found' })
  };
}

function createWixClient(appId, publicKey) {
  const client = createClient({
    auth: AppStrategy({
      appId,
      publicKey
    }),
    modules: { appInstances, members, contacts }
  });

  client.appInstances.onAppInstanceInstalled(async (event) => {
    const instanceId = event?.metadata?.instanceId || event?.instanceId || '';
    const pending = getPendingRequest(event);

    const identity = {
      identityType:
        event?.metadata?.identity?.identityType ||
        event?.identity?.identityType ||
        pending?.identityType ||
        '',
      memberId:
        event?.metadata?.identity?.memberId ||
        event?.identity?.memberId ||
        pending?.memberId ||
        '',
      wixUserId:
        event?.metadata?.identity?.wixUserId ||
        event?.identity?.wixUserId ||
        pending?.wixUserId ||
        '',
      originatedEmail: event?.originatedFrom?.userEmail || event?.metadata?.userEmail || '',
      originatedName: event?.originatedFrom?.userName || ''
    };

    const memberDetails = await fetchIdentityDetails(client, identity);

    const entry = {
      requestId: pending?.requestId || await getNextRequestId(),
      receivedAt: new Date().toISOString(),
      eventName: 'APP_INSTANCE_INSTALLED',
      appId,
      siteId: event?.metadata?.siteId || '',
      instanceId,
      userEmail: memberDetails.email || event?.originatedFrom?.userEmail || event?.metadata?.userEmail || '',
      userName: memberDetails.name || '',
      userId: memberDetails.userId || event?.originatedFrom?.userId || event?.metadata?.userId || '',
      memberDetails: memberDetails.raw,
      region: event?.originatedFrom?.metaSiteRegion || '',
      rawPayload: JSON.stringify(event)
    };

    try {
      await appendInstallRow(entry);
      console.log('Stored install event', { appId, instanceId: entry.instanceId, requestId: entry.requestId });
    } catch (error) {
      const errorContext = parseErrorContext(error);
      console.error('Failed to append install row', { appId, ...errorContext });
    } finally {
      clearPendingRequest(event);
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
  const requestId = await getNextRequestId();
  const rawBody = req.body || '';
  const webhookSecret = req.params.webhookSecret || '';
  const hints = extractRequestHints(rawBody);

  setPendingRequest(hints, requestId);

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
