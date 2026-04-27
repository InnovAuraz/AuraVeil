// Auraveil — StatusBar Component

import { useThreatStore } from '../stores/threatStore';

function formatUptime(snapshot: { timestamp: string } | null): string {
    if (!snapshot) return '--';
    return new Date(snapshot.timestamp).toLocaleTimeString();
}

export default function StatusBar() {
    const { connected, latestSnapshot } = useThreatStore();

    const processCount = latestSnapshot?.processes?.length ?? 0;
    const alertCount = latestSnapshot?.active_alerts ?? 0;
    const networkMode = latestSnapshot?.network ? 'Active' : 'Inactive';

    return (
        <div className="status-bar">
            <div className="status-item">
                <span
                    className={`status-dot ${connected ? 'status-dot--connected' : 'status-dot--disconnected'}`}
                />
                <span>{connected ? 'Connected' : 'Disconnected'}</span>
            </div>
            <div className="status-item">
                <span className="status-label">Last Update</span>
                <span className="status-value">{formatUptime(latestSnapshot)}</span>
            </div>
            <div className="status-item">
                <span className="status-label">Processes</span>
                <span className="status-value">{processCount}</span>
            </div>
            <div className="status-item">
                <span className="status-label">Active Alerts</span>
                <span className={`status-value ${alertCount > 0 ? 'status-value--alert' : ''}`}>
                    {alertCount}
                </span>
            </div>
            <div className="status-item">
                <span className="status-label">Network</span>
                <span className="status-value">{networkMode}</span>
            </div>
        </div>
    );
}
