// Auraveil — Network Activity Panel (Phase 3)
// Real-time network monitoring: connections, DNS, suspicious ports

import { useThreatStore } from '../stores/threatStore';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function NetworkPanel() {
    const network = useThreatStore((s) => s.latestSnapshot?.network);

    if (!network) {
        return (
            <div className="network-panel">
                <div className="card">
                    <h3 className="card-title">🌐 Network Activity</h3>
                    <p className="empty-state">Waiting for network data...</p>
                </div>
            </div>
        );
    }

    const trafficData = [
        { name: 'Packets In', value: network.packets_in, color: '#22d3ee' },
        { name: 'Packets Out', value: network.packets_out, color: '#6366f1' },
    ];

    const formatBytes = (bytes: number): string => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / 1048576).toFixed(1)} MB`;
    };

    return (
        <div className="network-panel">
            {/* Stats Cards */}
            <div className="network-stats">
                <div className="card stat-card">
                    <div className="stat-icon">📡</div>
                    <div className="stat-content">
                        <span className="stat-value">{network.active_connections}</span>
                        <span className="stat-label">Active Connections</span>
                    </div>
                </div>
                <div className="card stat-card">
                    <div className="stat-icon">🌍</div>
                    <div className="stat-content">
                        <span className="stat-value">{network.unique_destinations}</span>
                        <span className="stat-label">Unique Destinations</span>
                    </div>
                </div>
                <div className="card stat-card">
                    <div className="stat-icon">⬇️</div>
                    <div className="stat-content">
                        <span className="stat-value">{formatBytes(network.bytes_in)}</span>
                        <span className="stat-label">Data Received</span>
                    </div>
                </div>
                <div className="card stat-card">
                    <div className="stat-icon">⬆️</div>
                    <div className="stat-content">
                        <span className="stat-value">{formatBytes(network.bytes_out)}</span>
                        <span className="stat-label">Data Sent</span>
                    </div>
                </div>
            </div>

            {/* Traffic Chart */}
            <div className="card">
                <h3 className="card-title">📊 Packet Traffic</h3>
                <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={trafficData} layout="vertical">
                        <XAxis type="number" stroke="#64748b" fontSize={12} />
                        <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={12} width={100} />
                        <Tooltip
                            contentStyle={{
                                backgroundColor: '#1e293b',
                                border: '1px solid #334155',
                                borderRadius: '8px',
                                color: '#e2e8f0',
                            }}
                        />
                        <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                            {trafficData.map((entry, index) => (
                                <Cell key={index} fill={entry.color} />
                            ))}
                        </Bar>
                    </BarChart>
                </ResponsiveContainer>
            </div>

            {/* DNS Queries */}
            <div className="card">
                <h3 className="card-title">🔍 DNS Queries</h3>
                {network.dns_queries.length === 0 ? (
                    <p className="empty-state">No DNS queries captured</p>
                ) : (
                    <ul className="dns-list">
                        {network.dns_queries.slice(-20).reverse().map((query, i) => (
                            <li key={i} className="dns-item">
                                <span className="dns-icon">🔗</span>
                                <span className="dns-domain">{query}</span>
                            </li>
                        ))}
                    </ul>
                )}
            </div>

            {/* Suspicious Ports */}
            {Array.isArray(network.suspicious_ports) && network.suspicious_ports.length > 0 && (
                <div className="card card--danger">
                    <h3 className="card-title">🚨 Suspicious Port Activity</h3>
                    <ul className="suspicious-list">
                        {network.suspicious_ports.map((entry, i) => (
                            <li key={i} className="suspicious-item">
                                <span className="port-badge">:{typeof entry === 'object' ? entry.port : entry}</span>
                                {typeof entry === 'object' && (
                                    <span className="port-detail">{entry.src} → {entry.dst}</span>
                                )}
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}
