// Auraveil — WebSocket Hook with auto-reconnect

import { useEffect, useRef, useCallback } from 'react';
import { useThreatStore } from '../stores/threatStore';
import type { MetricsSnapshot } from '../types';

const WS_URL = 'ws://127.0.0.1:8000/ws/live';
const RECONNECT_DELAY = 3000;

export function useWebSocket() {
    const wsRef = useRef<WebSocket | null>(null);
    const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    const { updateSnapshot, setConnected } = useThreatStore();

    const connect = useCallback(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) return;

        const ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            setConnected(true);
            console.log('[Auraveil] WebSocket connected');
        };

        ws.onmessage = (event) => {
            try {
                const data: MetricsSnapshot = JSON.parse(event.data);
                updateSnapshot(data);
            } catch (e) {
                console.error('[Auraveil] Failed to parse WS message:', e);
            }
        };

        ws.onclose = () => {
            setConnected(false);
            console.log('[Auraveil] WebSocket disconnected, reconnecting...');
            reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY);
        };

        ws.onerror = (err) => {
            console.error('[Auraveil] WebSocket error:', err);
            ws.close();
        };

        wsRef.current = ws;
    }, [updateSnapshot, setConnected]);

    useEffect(() => {
        connect();

        return () => {
            if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
            if (wsRef.current) wsRef.current.close();
        };
    }, [connect]);

    return { connected: useThreatStore((s) => s.connected) };
}
