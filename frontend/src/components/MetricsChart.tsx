// Auraveil — MetricsChart Component
// Real-time CPU and memory area charts using Recharts

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useThreatStore } from '../stores/threatStore';

export default function MetricsChart() {
    const metricsHistory = useThreatStore((s) => s.metricsHistory);

    const chartData = metricsHistory.map((m, i) => ({
        index: i,
        cpu: m.cpu_percent,
        memory: m.memory_percent,
    }));

    return (
        <div className="card">
            <h2 className="card-title">System Metrics</h2>
            <div className="chart-container">
                <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                        <defs>
                            <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4} />
                                <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="memGradient" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.4} />
                                <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                        <XAxis
                            dataKey="index"
                            tick={false}
                            axisLine={{ stroke: '#334155' }}
                        />
                        <YAxis
                            domain={[0, 100]}
                            tickFormatter={(v) => `${v}%`}
                            tick={{ fill: '#94a3b8', fontSize: 12 }}
                            axisLine={{ stroke: '#334155' }}
                        />
                        <Tooltip
                            contentStyle={{
                                backgroundColor: '#1e293b',
                                border: '1px solid #334155',
                                borderRadius: '8px',
                                color: '#e2e8f0',
                            }}
                            formatter={(value, name) => [
                                `${Number(value).toFixed(1)}%`,
                                name === 'cpu' ? 'CPU' : 'Memory',
                            ]}
                        />
                        <Area
                            type="monotone"
                            dataKey="cpu"
                            stroke="#6366f1"
                            strokeWidth={2}
                            fill="url(#cpuGradient)"
                            name="cpu"
                        />
                        <Area
                            type="monotone"
                            dataKey="memory"
                            stroke="#22d3ee"
                            strokeWidth={2}
                            fill="url(#memGradient)"
                            name="memory"
                        />
                    </AreaChart>
                </ResponsiveContainer>
                <div className="chart-legend">
                    <span className="legend-item">
                        <span className="legend-dot" style={{ backgroundColor: '#6366f1' }} />
                        CPU
                    </span>
                    <span className="legend-item">
                        <span className="legend-dot" style={{ backgroundColor: '#22d3ee' }} />
                        Memory
                    </span>
                </div>
            </div>
        </div>
    );
}
