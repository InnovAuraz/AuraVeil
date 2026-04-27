// Auraveil — Zustand Store for threat and metrics state (Phase 2)

import { create } from 'zustand';
import type { MetricsSnapshot, SystemMetrics, ThreatRecord, NewAlert } from '../types';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

interface ThreatStore {
    // State
    latestSnapshot: MetricsSnapshot | null;
    metricsHistory: SystemMetrics[];
    activeAlerts: ThreatRecord[];
    connected: boolean;
    toastQueue: NewAlert[];
    threatHistory: ThreatRecord[];
    activeTab: 'dashboard' | 'network' | 'settings';

    // Actions
    setActiveTab: (tab: 'dashboard' | 'network' | 'settings') => void;

    // Actions
    updateSnapshot: (snapshot: MetricsSnapshot) => void;
    setConnected: (status: boolean) => void;
    addAlert: (alert: ThreatRecord) => void;
    resolveAlert: (id: number) => void;
    dismissToast: () => void;
    fetchThreatHistory: (days?: number) => Promise<void>;
    resolveAlertApi: (id: number) => Promise<void>;
    whitelistProcess: (name: string) => Promise<void>;
    killProcess: (pid: number) => Promise<{ success: boolean; message: string }>;
}

const MAX_HISTORY = 60;

export const useThreatStore = create<ThreatStore>((set) => ({
    latestSnapshot: null,
    metricsHistory: [],
    activeAlerts: [],
    connected: false,
    toastQueue: [],
    threatHistory: [],
    activeTab: 'dashboard',

    setActiveTab: (tab) => set({ activeTab: tab }),

    updateSnapshot: (snapshot) =>
        set((state) => {
            // Queue new alerts as toasts
            const newToasts = snapshot.new_alerts ?? [];
            return {
                latestSnapshot: snapshot,
                metricsHistory: [
                    ...state.metricsHistory.slice(-(MAX_HISTORY - 1)),
                    snapshot.system,
                ],
                toastQueue: newToasts.length > 0
                    ? [...state.toastQueue, ...newToasts].slice(-5)
                    : state.toastQueue,
            };
        }),

    setConnected: (status) => set({ connected: status }),

    addAlert: (alert) =>
        set((state) => ({
            activeAlerts: [alert, ...state.activeAlerts].slice(0, 50),
        })),

    resolveAlert: (id) =>
        set((state) => ({
            activeAlerts: state.activeAlerts.filter((a) => a.id !== id),
        })),

    dismissToast: () =>
        set((state) => ({
            toastQueue: state.toastQueue.slice(1),
        })),

    fetchThreatHistory: async (days = 7) => {
        try {
            const res = await fetch(`${API_BASE}/api/threats/history?days=${days}`);
            if (res.ok) {
                const data = await res.json();
                set({ threatHistory: data });
            }
        } catch (err) {
            console.error('Failed to fetch threat history:', err);
        }
    },

    resolveAlertApi: async (id: number) => {
        try {
            const res = await fetch(`${API_BASE}/api/threats/${id}/resolve`, { method: 'POST' });
            if (res.ok) {
                set((state) => ({
                    activeAlerts: state.activeAlerts.filter((a) => a.id !== id),
                    threatHistory: state.threatHistory.map((t) =>
                        t.id === id ? { ...t, resolved: true } : t
                    ),
                }));
            }
        } catch (err) {
            console.error('Failed to resolve alert:', err);
        }
    },

    whitelistProcess: async (name: string) => {
        try {
            await fetch(`${API_BASE}/api/whitelist/${encodeURIComponent(name)}`, { method: 'POST' });
        } catch (err) {
            console.error('Failed to whitelist:', err);
        }
    },

    killProcess: async (pid: number) => {
        try {
            const res = await fetch(`${API_BASE}/api/processes/${pid}/kill`, { method: 'POST' });
            const data = await res.json();
            return data;
        } catch (err) {
            return { success: false, message: String(err) };
        }
    },
}));
