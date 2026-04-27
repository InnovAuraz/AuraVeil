// Auraveil — AlertFeed Component (Phase 2)
// Live alert feed with resolve/whitelist action buttons and toast notifications

import { useThreatStore } from '../stores/threatStore';
import type { ProcessInfo } from '../types';

function AlertIcon({ level }: { level: string }) {
    if (level === 'malicious') {
        return <span className="alert-icon alert-icon--malicious">🔴</span>;
    }
    return <span className="alert-icon alert-icon--suspicious">⚠️</span>;
}

export default function AlertFeed() {
    const latestSnapshot = useThreatStore((s) => s.latestSnapshot);
    const toastQueue = useThreatStore((s) => s.toastQueue);
    const dismissToast = useThreatStore((s) => s.dismissToast);
    const whitelistProcess = useThreatStore((s) => s.whitelistProcess);

    // Filter to only suspicious and malicious processes
    const alerts: ProcessInfo[] = (latestSnapshot?.processes ?? [])
        .filter((p) => p.risk_level !== 'safe' && p.threat_score > 30)
        .sort((a, b) => b.threat_score - a.threat_score)
        .slice(0, 20);

    return (
        <div className="card alert-feed">
            <h2 className="card-title">
                Live Alerts
                {alerts.length > 0 && (
                    <span className="alert-count">{alerts.length}</span>
                )}
            </h2>

            {/* Toast notifications for new alerts */}
            {toastQueue.length > 0 && (
                <div className="toast-container">
                    {toastQueue.slice(0, 3).map((toast, i) => (
                        <div key={`toast-${i}`} className="toast toast--danger">
                            <span className="toast-icon">🚨</span>
                            <span className="toast-text">
                                <strong>{toast.process_name}</strong> flagged as {toast.risk_level} (score: {toast.threat_score})
                            </span>
                            <button className="toast-dismiss" onClick={dismissToast}>×</button>
                        </div>
                    ))}
                </div>
            )}

            <div className="alert-list">
                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <span className="empty-icon">✅</span>
                        <p>No active threats detected</p>
                    </div>
                ) : (
                    alerts.map((proc) => (
                        <div
                            key={proc.pid}
                            className={`alert-item alert-item--${proc.risk_level}`}
                        >
                            <div className="alert-header">
                                <AlertIcon level={proc.risk_level} />
                                <span className="alert-process-name">{proc.name}</span>
                                <span className="alert-pid">PID {proc.pid}</span>
                                <span
                                    className={`score-pill ${proc.threat_score > 70 ? 'score-pill--high' : 'score-pill--medium'
                                        }`}
                                >
                                    {proc.threat_score}
                                </span>
                            </div>
                            {proc.reasons.length > 0 && (
                                <ul className="alert-reasons">
                                    {proc.reasons.map((reason, i) => (
                                        <li key={i}>{reason}</li>
                                    ))}
                                </ul>
                            )}
                            <div className="alert-actions">
                                <button
                                    className="btn btn--sm btn--ghost"
                                    onClick={() => whitelistProcess(proc.name)}
                                    title="Trust this process"
                                >
                                    ✓ Whitelist
                                </button>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
