// Auraveil — Process Detail Modal (Phase 3)
// SHAP explanations, feature importance, process metadata

import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import type { ProcessInfo, ProcessExplanation } from '../types';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

interface Props {
    process: ProcessInfo;
    onClose: () => void;
}

export default function ProcessDetail({ process, onClose }: Props) {
    const [explanation, setExplanation] = useState<ProcessExplanation | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchExplanation();
    }, [process.pid]);

    const fetchExplanation = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/api/processes/${process.pid}/explain`);
            if (res.ok) {
                const data = await res.json();
                setExplanation(data);
            }
        } catch { /* ignore */ }
        setLoading(false);
    };

    const riskClass =
        process.risk_level === 'malicious' ? 'malicious' :
            process.risk_level === 'suspicious' ? 'suspicious' : 'safe';

    const features = explanation?.explanation?.features ?? [];
    const sortedFeatures = [...features].sort((a, b) => Math.abs(b.importance) - Math.abs(a.importance));

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <button className="modal-close" onClick={onClose}>✕</button>

                <div className="modal-header">
                    <h2>{process.name}</h2>
                    <span className={`risk-badge risk-badge--${riskClass}`}>
                        {process.risk_level}
                    </span>
                </div>

                {/* Process Info */}
                <div className="process-info-grid">
                    <div className="info-cell">
                        <span className="info-label">PID</span>
                        <span className="info-value">{process.pid}</span>
                    </div>
                    <div className="info-cell">
                        <span className="info-label">Threat Score</span>
                        <span className={`info-value score-${riskClass}`}>{process.threat_score}</span>
                    </div>
                    <div className="info-cell">
                        <span className="info-label">CPU</span>
                        <span className="info-value">{process.cpu_percent.toFixed(1)}%</span>
                    </div>
                    <div className="info-cell">
                        <span className="info-label">Memory</span>
                        <span className="info-value">{process.memory_percent.toFixed(1)}%</span>
                    </div>
                    <div className="info-cell">
                        <span className="info-label">Threads</span>
                        <span className="info-value">{process.num_threads}</span>
                    </div>
                    {process.parent_pid !== undefined && (
                        <div className="info-cell">
                            <span className="info-label">Parent PID</span>
                            <span className="info-value">{process.parent_pid}</span>
                        </div>
                    )}
                </div>

                {/* Reasons */}
                {process.reasons.length > 0 && (
                    <div className="detail-section">
                        <h3>⚠️ Anomaly Reasons</h3>
                        <ul className="reasons-list">
                            {process.reasons.map((reason, i) => (
                                <li key={i} className="reason-item">{reason}</li>
                            ))}
                        </ul>
                    </div>
                )}

                {/* SHAP Explanation */}
                <div className="detail-section">
                    <h3>🧠 Feature Importance {explanation?.explanation?.method ? `(${explanation.explanation.method})` : ''}</h3>
                    {loading ? (
                        <div className="loading-state">
                            <span className="spinner" /> Analyzing...
                        </div>
                    ) : sortedFeatures.length > 0 ? (
                        <ResponsiveContainer width="100%" height={Math.max(200, sortedFeatures.length * 35)}>
                            <BarChart data={sortedFeatures} layout="vertical">
                                <XAxis type="number" stroke="#64748b" fontSize={11} />
                                <YAxis
                                    type="category"
                                    dataKey="feature"
                                    stroke="#94a3b8"
                                    fontSize={11}
                                    width={140}
                                    tick={{ fill: '#94a3b8' }}
                                />
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: '#1e293b',
                                        border: '1px solid #334155',
                                        borderRadius: '8px',
                                        color: '#e2e8f0',
                                    }}
                                    formatter={(value) => [Number(value).toFixed(4), 'Importance']}
                                />
                                <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                                    {sortedFeatures.map((entry, index) => (
                                        <Cell
                                            key={index}
                                            fill={entry.importance > 0 ? '#ef4444' : '#10b981'}
                                        />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    ) : (
                        <p className="empty-state">No explanation data available</p>
                    )}
                </div>
            </div>
        </div>
    );
}
