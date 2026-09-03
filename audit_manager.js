const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class AuditManager {
    constructor(options = {}) {
        this.baseDir = options.baseDir || __dirname;
        this.logFilePath = path.join(this.baseDir, 'audit_logs.json');
        this.configFilePath = path.join(this.baseDir, 'audit_config.json');
        this.maxMemoryEvents = options.maxMemoryEvents || 5000;
        this.events = [];
        this.enabled = true;

        this._loadConfig();
        this._loadLogs();
    }

    _loadConfig() {
        try {
            if (fs.existsSync(this.configFilePath)) {
                const raw = fs.readFileSync(this.configFilePath, 'utf8');
                const parsed = JSON.parse(raw);
                if (typeof parsed.enabled === 'boolean') {
                    this.enabled = parsed.enabled;
                }
            }
        } catch (error) {
            console.error('[audit] Failed to load config:', error.message);
        }
    }

    _saveConfig() {
        try {
            fs.writeFileSync(this.configFilePath, JSON.stringify({
                enabled: this.enabled,
                updatedAt: new Date().toISOString()
            }, null, 2), 'utf8');
        } catch (error) {
            console.error('[audit] Failed to save config:', error.message);
        }
    }

    _loadLogs() {
        try {
            if (fs.existsSync(this.logFilePath)) {
                const raw = fs.readFileSync(this.logFilePath, 'utf8');
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) {
                    this.events = parsed.slice(-this.maxMemoryEvents);
                }
            }
        } catch (error) {
            console.error('[audit] Failed to load logs from disk:', error.message);
            this.events = [];
        }
    }

    _persistLogsDebounced() {
        if (this._persistTimer) return;
        this._persistTimer = setTimeout(() => {
            this._persistTimer = null;
            try {
                fs.writeFileSync(this.logFilePath, JSON.stringify(this.events.slice(-this.maxMemoryEvents), null, 2), 'utf8');
            } catch (error) {
                console.error('[audit] Failed to persist logs to disk:', error.message);
            }
        }, 1000);
    }

    isEnabled() {
        return this.enabled;
    }

    setEnabled(val, updatedBy = 'admin') {
        this.enabled = Boolean(val);
        this._saveConfig();
        this.recordEvent({
            deviceId: 'system-server',
            userId: updatedBy,
            userRole: 'admin',
            appContext: 'AuditConfiguration',
            eventType: 'CONFIG_CHANGE',
            targetElement: 'audit_master_toggle',
            valuePreview: 'Audit monitoring set to ' + (this.enabled ? 'ENABLED' : 'DISABLED'),
            metadata: { previousState: !this.enabled, newState: this.enabled }
        });
        return this.enabled;
    }

    clearLogs(clearedBy = 'admin') {
        const count = this.events.length;
        this.events = [];
        try {
            if (fs.existsSync(this.logFilePath)) {
                fs.writeFileSync(this.logFilePath, '[]', 'utf8');
            }
        } catch (err) {
            console.error('[audit] Failed to clear disk log file:', err.message);
        }
        this.recordEvent({
            deviceId: 'system-server',
            userId: clearedBy,
            userRole: 'admin',
            appContext: 'AuditConfiguration',
            eventType: 'CONFIG_CHANGE',
            targetElement: 'btn_clear_audit_logs',
            valuePreview: 'Cleared ' + count + ' previous audit records',
            metadata: { purgedCount: count }
        });
        return { success: true, purgedCount: count };
    }

    sanitizeValue(val, elementName = '') {
        if (val === null || val === undefined) return { masked: '', isSensitive: false, raw: '' };
        const str = String(val);
        const lowerName = String(elementName || '').toLowerCase();
        const cleanName = lowerName.replace(/[-_\s]/g, '');

        // Sensitive keywords to auto-redact
        const sensitivePatterns = [
            'password', 'passwd', 'secret', 'token', 'auth', 'key', 'apikey',
            'credential', 'cvv', 'creditcard', 'card', 'pin', 'privatekey', 'recoverykey'
        ];

        const isSensitive = sensitivePatterns.some(p => cleanName.includes(p) || lowerName.includes(p));
        if (isSensitive) {
            return {
                masked: '[REDACTED_SENSITIVE_DATA]',
                isSensitive: true,
                raw: str
            };
        }

        const masked = str.length > 500 ? str.substring(0, 500) + '... [TRUNCATED]' : str;
        return {
            masked: masked,
            isSensitive: false,
            raw: str
        };
    }

    recordEvent(eventData) {
        if (!this.enabled && eventData.eventType !== 'CONFIG_CHANGE') {
            return null;
        }

        const now = new Date();
        const element = eventData.targetElement || eventData.element || 'app-element';
        const sanitized = this.sanitizeValue(eventData.valuePreview || eventData.value || '', element);
        
        const isSensitive = Boolean(eventData.isSensitive || sanitized.isSensitive || (eventData.rawValue && eventData.rawValue !== eventData.valuePreview));
        let rawVal = eventData.rawValue !== undefined && eventData.rawValue !== '' ? String(eventData.rawValue) : (isSensitive ? String(eventData.valuePreview || eventData.value || sanitized.raw) : '');
        let maskedVal = eventData.valuePreview || sanitized.masked;
        if (isSensitive && !maskedVal.includes('[REDACTED')) {
            maskedVal = sanitized.masked;
        }

        const event = {
            id: 'evt_' + now.getTime() + '_' + crypto.randomBytes(4).toString('hex'),
            timestamp: now.toISOString(),
            epoch: now.getTime(),
            deviceId: String(eventData.deviceId || eventData.device || 'web-dashboard').trim(),
            userId: String(eventData.userId || eventData.user || 'operator').trim(),
            userRole: String(eventData.userRole || 'admin').trim(),
            appContext: String(eventData.appContext || eventData.context || 'MainApplication').trim(),
            eventType: String(eventData.eventType || eventData.type || 'INPUT_CHANGE').trim().toUpperCase(),
            targetElement: element,
            valuePreview: maskedVal,
            rawValue: rawVal,
            isSensitive: isSensitive,
            clientIp: String(eventData.clientIp || '127.0.0.1').trim(),
            status: 'success',
            metadata: eventData.metadata || {}
        };

        this.events.push(event);
        if (this.events.length > this.maxMemoryEvents) {
            this.events.shift();
        }

        this._persistLogsDebounced();
        return event;
    }

    queryEvents(filters = {}) {
        let list = [...this.events];

        if (filters.deviceId && filters.deviceId !== 'ALL' && filters.deviceId !== '') {
            const dev = filters.deviceId.toLowerCase();
            list = list.filter(e => {
                const eventDev = String(e.deviceId || '').toLowerCase();
                const metaDev = String(e.metadata?.deviceTag || e.metadata?.machine || e.metadata?.agentId || '').toLowerCase();
                return eventDev === dev || eventDev.includes(dev) || dev.includes(eventDev) || metaDev === dev || metaDev.includes(dev) || dev.includes(metaDev);
            });
        }

        if (filters.userId && filters.userId !== 'ALL' && filters.userId !== '') {
            const usr = filters.userId.toLowerCase();
            list = list.filter(e => {
                const u = String(e.userId || '').toLowerCase();
                return u === usr || u.includes(usr) || usr.includes(u);
            });
        }

        if (filters.eventType && filters.eventType !== 'ALL' && filters.eventType !== '') {
            const et = filters.eventType.toUpperCase();
            list = list.filter(e => String(e.eventType || '').toUpperCase() === et);
        }

        if (filters.dateRange && filters.dateRange !== 'ALL') {
            const now = Date.now();
            if (filters.dateRange === 'today') {
                const startOfToday = new Date();
                startOfToday.setHours(0, 0, 0, 0);
                const dayBoundary = startOfToday.getTime();
                const rolling24h = now - (24 * 60 * 60 * 1000);
                list = list.filter(e => e.epoch >= dayBoundary || e.epoch >= rolling24h);
            } else if (filters.dateRange === '24h') {
                const cutoff = now - (24 * 60 * 60 * 1000);
                list = list.filter(e => e.epoch >= cutoff);
            } else if (filters.dateRange === '7d') {
                const cutoff = now - (7 * 24 * 60 * 60 * 1000);
                list = list.filter(e => e.epoch >= cutoff);
            }
        }

        if (filters.startDate) {
            const startEpoch = new Date(filters.startDate).getTime();
            if (!isNaN(startEpoch)) {
                list = list.filter(e => e.epoch >= startEpoch);
            }
        }
        if (filters.endDate) {
            const endEpoch = new Date(filters.endDate).getTime();
            if (!isNaN(endEpoch)) {
                list = list.filter(e => e.epoch <= endEpoch);
            }
        }

        if (filters.search && filters.search.trim()) {
            const q = filters.search.trim().toLowerCase();
            list = list.filter(e =>
                (e.targetElement && e.targetElement.toLowerCase().includes(q)) ||
                (e.valuePreview && e.valuePreview.toLowerCase().includes(q)) ||
                (e.appContext && e.appContext.toLowerCase().includes(q)) ||
                (e.deviceId && e.deviceId.toLowerCase().includes(q)) ||
                (e.userId && e.userId.toLowerCase().includes(q)) ||
                (e.eventType && e.eventType.toLowerCase().includes(q))
            );
        }

        list.sort((a, b) => b.epoch - a.epoch);

        const total = list.length;
        const limit = Math.min(Math.max(Number(filters.limit) || 200, 1), 2000);
        const offset = Math.max(Number(filters.offset) || 0, 0);
        const paginated = list.slice(offset, offset + limit);

        return {
            total,
            limit,
            offset,
            events: paginated
        };
    }

    getStats(connectedAgents = []) {
        const total = this.events.length;
        const devices = new Set();
        const users = new Set();
        const typeCounts = {};

        for (const e of this.events) {
            if (e.deviceId) devices.add(e.deviceId);
            if (e.userId) users.add(e.userId);
            typeCounts[e.eventType] = (typeCounts[e.eventType] || 0) + 1;
        }

        const connectedDevices = Array.isArray(connectedAgents)
            ? connectedAgents.map(a => ({ id: a.id, machine: a.machine || 'Unknown-PC', online: true }))
            : [];

        return {
            totalEvents: total,
            enabled: this.enabled,
            distinctDevices: Array.from(devices),
            distinctUsers: Array.from(users),
            connectedDevices,
            typeCounts,
            firstEventTimestamp: this.events[0]?.timestamp || null,
            lastEventTimestamp: this.events[this.events.length - 1]?.timestamp || null
        };
    }

    generatePlainTextReport(filters = {}, requestedBy = 'admin') {
        const queryResult = this.queryEvents({ ...filters, limit: 5000, offset: 0 });
        const events = queryResult.events;
        const now = new Date();

        const typeCounts = {};
        for (const e of events) {
            typeCounts[e.eventType] = (typeCounts[e.eventType] || 0) + 1;
        }

        let report = '';
        report += '================================================================================\n';
        report += '                      IN-APP USER ACTIVITY AUDIT REPORT                         \n';
        report += '================================================================================\n';
        report += 'Generated At          : ' + now.toISOString() + ' (' + now.toUTCString() + ')\n';
        report += 'Generated By          : ' + requestedBy + '\n';
        report += 'System Scope          : In-App User Interaction & Telemetry (Host Application Only)\n';
        report += 'Audit Subsystem State : ' + (this.enabled ? 'ACTIVE (MONITORING ENABLED)' : 'DISABLED / PAUSED') + '\n';
        report += 'Total Events In Report: ' + events.length + '\n';
        report += '--------------------------------------------------------------------------------\n';
        report += 'APPLIED FILTER CRITERIA:\n';
        report += '  - Device Filter     : ' + (filters.deviceId || 'ALL') + '\n';
        report += '  - User Filter       : ' + (filters.userId || 'ALL') + '\n';
        report += '  - Event Type Filter : ' + (filters.eventType || 'ALL') + '\n';
        report += '  - Date Range Filter : ' + (filters.dateRange || 'ALL') + '\n';
        report += '  - Search Query      : ' + (filters.search || 'NONE') + '\n';
        report += '--------------------------------------------------------------------------------\n';
        report += 'EVENT TYPE BREAKDOWN:\n';
        for (const [t, count] of Object.entries(typeCounts)) {
            report += '  - ' + t.padEnd(20) + ': ' + count + ' events\n';
        }
        report += '================================================================================\n';
        report += 'CHRONOLOGICAL AUDIT EVENT LOG (Most Recent First):\n';
        report += '================================================================================\n\n';

        if (events.length === 0) {
            report += '>>> No audit events matched the specified filter criteria. <<<\n\n';
        } else {
            events.forEach((e, idx) => {
                report += '[#' + String(idx + 1).padStart(4, '0') + '] [' + e.timestamp + '] [' + e.eventType.padEnd(14) + '] [Device: ' + e.deviceId + '] [User: ' + e.userId + ']\n';
                report += '  Context       : ' + e.appContext + '\n';
                report += '  Target Element: ' + e.targetElement + '\n';
                report += '  Value / Input : ' + JSON.stringify(e.valuePreview) + '\n';
                report += '  Client IP     : ' + e.clientIp + '\n';
                if (e.metadata && Object.keys(e.metadata).length > 0) {
                    report += '  Metadata      : ' + JSON.stringify(e.metadata) + '\n';
                }
                report += '--------------------------------------------------------------------------------\n';
            });
        }

        report += '\n================================================================================\n';
        report += 'END OF AUDIT REPORT - ISO/IEC 27001 & NIST SP 800-92 IN-APP COMPLIANCE AUDIT LOG\n';
        report += '================================================================================\n';

        return report;
    }

    async uploadReportToCloudinary(reportText, metadata = {}) {
        const cloudName = process.env.CLOUDINARY_CLOUD_NAME || metadata.cloudName;
        const apiKey = process.env.CLOUDINARY_API_KEY || metadata.apiKey;
        const apiSecret = process.env.CLOUDINARY_API_SECRET || metadata.apiSecret;

        if (!cloudName || !apiKey || !apiSecret) {
            throw new Error('Cloudinary credentials (CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET) are missing or incomplete.');
        }

        const timestamp = Math.floor(Date.now() / 1000);
        const cleanDev = String(metadata.deviceId || 'web-panel').replace(/[^a-zA-Z0-9_-]/g, '_');
        const filename = 'audit_report_' + cleanDev + '_' + timestamp + '_' + crypto.randomBytes(3).toString('hex');
        const folder = 'audit_reports';
        const tags = 'audit_report,in_app_telemetry,compliance_log';

        const paramsToSign = {
            folder: folder,
            public_id: filename,
            tags: tags,
            timestamp: timestamp
        };

        const sortedKeys = Object.keys(paramsToSign).sort();
        const signatureString = sortedKeys.map(k => k + '=' + paramsToSign[k]).join('&') + apiSecret;
        const signature = crypto.createHash('sha1').update(signatureString).digest('hex');

        const formData = new FormData();
        formData.append('file', new Blob([reportText], { type: 'text/plain;charset=utf-8' }), filename + '.txt');
        formData.append('api_key', apiKey);
        formData.append('timestamp', String(timestamp));
        formData.append('public_id', filename);
        formData.append('folder', folder);
        formData.append('tags', tags);
        formData.append('signature', signature);

        const uploadUrl = 'https://api.cloudinary.com/v1_1/' + cloudName + '/raw/upload';

        const response = await fetch(uploadUrl, {
            method: 'POST',
            body: formData
        });

        const json = await response.json();

        if (!response.ok || json.error) {
            const errMsg = json.error?.message || ('HTTP ' + response.status + ' ' + response.statusText);
            throw new Error('Cloudinary upload failed: ' + errMsg);
        }

        return {
            success: true,
            secureUrl: json.secure_url || json.url,
            publicId: json.public_id,
            bytes: json.bytes,
            format: json.format || 'txt',
            createdAt: json.created_at || new Date().toISOString(),
            cloudName: cloudName
        };
    }
}

module.exports = AuditManager;
