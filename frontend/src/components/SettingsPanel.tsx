// Auraveil — Settings Panel (Phase 3)
// Runtime configuration: thresholds, auto-stop, whitelist management

import { useState, useEffect } from 'react';
import type { SettingsConfig } from '../types';
import { useThreatStore } from '../stores/threatStore';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

interface WhitelistEntry {
    id: number;
    process_name: string;
    added_at: string;
    reason: string;
}

export default function SettingsPanel() {
    const [settings, setSettings] = useState<SettingsConfig | null>(null);
    const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
    const [newProcess, setNewProcess] = useState('');
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
    const whitelistProcess = useThreatStore((s) => s.whitelistProcess);

    useEffect(() => {
        fetchSettings();
        fetchWhitelist();
    }, []);

    const fetchSettings = async () => {
        try {
            const res = await fetch(`${API_BASE}/api/settings`);
            const data = await res.json();
            setSettings(data);
        } catch { /* ignore */ }
    };

    const fetchWhitelist = async () => {
        try {
            const res = await fetch(`${API_BASE}/api/whitelist`);
            const data = await res.json();
            setWhitelist(data);
        } catch { /* ignore */ }
    };

    const saveSettings = async () => {
        if (!settings) return;
        setSaving(true);
        try {
            const res = await fetch(`${API_BASE}/api/settings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings),
            });
            if (res.ok) {
                showMessage('Settings saved', 'success');
            } else {
                showMessage('Failed to save settings', 'error');
            }
        } catch {
            showMessage('Connection error', 'error');
        }
        setSaving(false);
    };

    const addToWhitelist = async () => {
        if (!newProcess.trim()) return;
        try {
            await whitelistProcess(newProcess.trim());
            setNewProcess('');
            fetchWhitelist();
            showMessage(`${newProcess.trim()} whitelisted`, 'success');
        } catch {
            showMessage('Failed to whitelist process', 'error');
        }
    };

    const removeFromWhitelist = async (name: string) => {
        try {
            await fetch(`${API_BASE}/api/whitelist/${encodeURIComponent(name)}`, { method: 'DELETE' });
            fetchWhitelist();
            showMessage(`${name} removed`, 'success');
        } catch {
            showMessage('Failed to remove', 'error');
        }
    };

    const showMessage = (text: string, type: 'success' | 'error') => {
        setMessage({ text, type });
        setTimeout(() => setMessage(null), 3000);
    };

    if (!settings) return <div className="card settings-loading">Loading settings...</div>;

    return (
        <div className="settings-panel">
            {message && (
                <div className={`settings-toast settings-toast--${message.type}`}>
                    {message.text}
                </div>
            )}

            <div className="card settings-section">
                <h3 className="card-title">⚙️ Detection Thresholds</h3>
                <div className="settings-grid">
                    <div className="setting-item">
                        <label>Safe Threshold (0–100)</label>
                        <div className="setting-input-group">
                            <input
                                type="range"
                                min={0}
                                max={100}
                                value={settings.threshold_safe}
                                onChange={(e) =>
                                    setSettings({ ...settings, threshold_safe: Number(e.target.value) })
                                }
                            />
                            <span className="setting-value safe">{settings.threshold_safe}</span>
                        </div>
                        <span className="setting-hint">Scores below this are considered safe</span>
                    </div>

                    <div className="setting-item">
                        <label>Suspicious Threshold (0–100)</label>
                        <div className="setting-input-group">
                            <input
                                type="range"
                                min={0}
                                max={100}
                                value={settings.threshold_suspicious}
                                onChange={(e) =>
                                    setSettings({ ...settings, threshold_suspicious: Number(e.target.value) })
                                }
                            />
                            <span className="setting-value suspicious">{settings.threshold_suspicious}</span>
                        </div>
                        <span className="setting-hint">Scores above this are considered malicious</span>
                    </div>

                    <div className="setting-item">
                        <label>Alert Cooldown (seconds)</label>
                        <div className="setting-input-group">
                            <input
                                type="number"
                                min={5}
                                max={600}
                                value={settings.alert_cooldown}
                                onChange={(e) =>
                                    setSettings({ ...settings, alert_cooldown: Number(e.target.value) })
                                }
                            />
                        </div>
                        <span className="setting-hint">Minimum time between alerts for same process</span>
                    </div>
                </div>
            </div>

            <div className="card settings-section">
                <h3 className="card-title">🛑 Auto-Stop</h3>
                <div className="settings-grid">
                    <div className="setting-item">
                        <label className="toggle-label">
                            <span>Enable Auto-Stop</span>
                            <div
                                className={`toggle ${settings.auto_stop_enabled ? 'toggle--active' : ''}`}
                                onClick={() =>
                                    setSettings({ ...settings, auto_stop_enabled: !settings.auto_stop_enabled })
                                }
                            >
                                <div className="toggle-knob" />
                            </div>
                        </label>
                        <span className="setting-hint">Automatically kill processes above the threshold</span>
                    </div>

                    {settings.auto_stop_enabled && (
                        <div className="setting-item">
                            <label>Auto-Stop Threshold</label>
                            <div className="setting-input-group">
                                <input
                                    type="range"
                                    min={50}
                                    max={100}
                                    value={settings.auto_stop_threshold}
                                    onChange={(e) =>
                                        setSettings({ ...settings, auto_stop_threshold: Number(e.target.value) })
                                    }
                                />
                                <span className="setting-value malicious">{settings.auto_stop_threshold}</span>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            <div className="card settings-section">
                <h3 className="card-title">✅ Whitelist</h3>
                <div className="whitelist-add">
                    <input
                        type="text"
                        placeholder="Process name (e.g. chrome.exe)"
                        value={newProcess}
                        onChange={(e) => setNewProcess(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && addToWhitelist()}
                    />
                    <button className="btn btn--safe" onClick={addToWhitelist}>Add</button>
                </div>
                {whitelist.length === 0 ? (
                    <p className="whitelist-empty">No whitelisted processes</p>
                ) : (
                    <ul className="whitelist-list">
                        {whitelist.map((entry) => (
                            <li key={entry.id} className="whitelist-item">
                                <div>
                                    <span className="whitelist-name">{entry.process_name}</span>
                                    <span className="whitelist-meta">{entry.reason}</span>
                                </div>
                                <button
                                    className="btn btn--danger btn--sm"
                                    onClick={() => removeFromWhitelist(entry.process_name)}
                                >
                                    ✕
                                </button>
                            </li>
                        ))}
                    </ul>
                )}
            </div>

            <button className={`btn btn--primary save-btn ${saving ? 'saving' : ''}`} onClick={saveSettings}>
                {saving ? 'Saving...' : 'Save Settings'}
            </button>
        </div>
    );
}
