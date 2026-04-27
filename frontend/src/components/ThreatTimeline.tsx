// Auraveil — ThreatTimeline Component (Phase 2)
// Historical threat visualization: bar chart showing threat density over time

import { useEffect, useState } from 'react';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';
import { useThreatStore } from '../stores/threatStore';

type TimeRange = '24h' | '7d';

interface TimelineBucket {
    label: string;
    suspicious: number;
    malicious: number;
    total: number;
}

export default function ThreatTimeline() {
    const threatHistory = useThreatStore((s) => s.threatHistory);
    const fetchThreatHistory = useThreatStore((s) => s.fetchThreatHistory);
    const [range, setRange] = useState<TimeRange>('24h');

    useEffect(() => {
        const days = range === '24h' ? 1 : 7;
        fetchThreatHistory(days);
        const interval = setInterval(() => fetchThreatHistory(days), 30000);
        return () => clearInterval(interval);
    }, [range, fetchThreatHistory]);

    // Bucket threats into time slots
    const buckets: TimelineBucket[] = (() => {
        const now = Date.now();
        const slotCount = range === '24h' ? 24 : 7;
        const slotDuration = range === '24h' ? 3600000 : 86400000;

        const slots: TimelineBucket[] = Array.from({ length: slotCount }, (_, i) => {
            const slotTime = new Date(now - (slotCount - 1 - i) * slotDuration);
            const label = range === '24h'
                ? slotTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                : slotTime.toLocaleDateString([], { weekday: 'short' });
            return { label, suspicious: 0, malicious: 0, total: 0 };
        });

        for (const threat of threatHistory) {
            const t = new Date(threat.timestamp).getTime();
            const idx = Math.floor((t - (now - slotCount * slotDuration)) / slotDuration);
            if (idx >= 0 && idx < slotCount) {
                slots[idx].total++;
                if (threat.risk_level === 'malicious') {
                    slots[idx].malicious++;
                } else {
                    slots[idx].suspicious++;
                }
            }
        }
        return slots;
    })();

    const hasData = buckets.some((b) => b.total > 0);

    return (
        <div className="card threat-timeline">
            <div className="card-header">
                <h2 className="card-title">Threat Timeline</h2>
                <div className="timeline-controls">
                    <button
                        className={`timeline-btn ${range === '24h' ? 'active' : ''}`}
                        onClick={() => setRange('24h')}
                    >
                        24h
                    </button>
                    <button
                        className={`timeline-btn ${range === '7d' ? 'active' : ''}`}
                        onClick={() => setRange('7d')}
                    >
                        7d
                    </button>
                </div>
            </div>
            {!hasData ? (
                <div className="empty-state">
                    <span className="empty-icon">📊</span>
                    <p>No threats recorded yet</p>
                </div>
            ) : (
                <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={buckets} barCategoryGap="15%">
                        <XAxis
                            dataKey="label"
                            tick={{ fill: '#8b8fa3', fontSize: 11 }}
                            axisLine={{ stroke: '#2a2d3e' }}
                            tickLine={false}
                        />
                        <YAxis
                            allowDecimals={false}
                            tick={{ fill: '#8b8fa3', fontSize: 11 }}
                            axisLine={false}
                            tickLine={false}
                            width={30}
                        />
                        <Tooltip
                            contentStyle={{
                                background: '#1a1d2e',
                                border: '1px solid #2a2d3e',
                                borderRadius: '8px',
                                color: '#e0e0e0',
                            }}
                        />
                        <Bar dataKey="suspicious" stackId="threats" name="Suspicious" fill="#f59e0b" radius={[0, 0, 0, 0]} />
                        <Bar dataKey="malicious" stackId="threats" name="Malicious" fill="#ef4444" radius={[4, 4, 0, 0]} />
                    </BarChart>
                </ResponsiveContainer>
            )}
        </div>
    );
}
