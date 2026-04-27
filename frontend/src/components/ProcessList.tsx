// Auraveil — ProcessList Component (Phase 2)
// Sortable process table with kill button, parent info

import { useState, useMemo } from 'react';
import { useThreatStore } from '../stores/threatStore';
import type { ProcessInfo } from '../types';

type SortKey = 'name' | 'cpu_percent' | 'memory_percent' | 'threat_score';
type SortDir = 'asc' | 'desc';

function getRiskBadge(level: string) {
    switch (level) {
        case 'malicious':
            return <span className="badge badge--malicious">Malicious</span>;
        case 'suspicious':
            return <span className="badge badge--suspicious">Suspicious</span>;
        default:
            return <span className="badge badge--safe">Safe</span>;
    }
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function ProcessList({ onSelectProcess }: { onSelectProcess?: (p: ProcessInfo) => void }) {
    const latestSnapshot = useThreatStore((s) => s.latestSnapshot);
    const killProcess = useThreatStore((s) => s.killProcess);
    const [sortKey, setSortKey] = useState<SortKey>('threat_score');
    const [sortDir, setSortDir] = useState<SortDir>('desc');
    const [filter, setFilter] = useState('');
    const [killingPids, setKillingPids] = useState<Set<number>>(new Set());

    const processes = latestSnapshot?.processes ?? [];

    const sorted = useMemo(() => {
        let filtered = processes.filter((p) =>
            p.name.toLowerCase().includes(filter.toLowerCase())
        );

        filtered.sort((a, b) => {
            const aVal = a[sortKey];
            const bVal = b[sortKey];
            if (typeof aVal === 'string' && typeof bVal === 'string') {
                return sortDir === 'asc'
                    ? aVal.localeCompare(bVal)
                    : bVal.localeCompare(aVal);
            }
            return sortDir === 'asc'
                ? (aVal as number) - (bVal as number)
                : (bVal as number) - (aVal as number);
        });

        return filtered.slice(0, 100);
    }, [processes, sortKey, sortDir, filter]);

    const handleSort = (key: SortKey) => {
        if (key === sortKey) {
            setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
        } else {
            setSortKey(key);
            setSortDir('desc');
        }
    };

    const sortIcon = (key: SortKey) => {
        if (key !== sortKey) return '';
        return sortDir === 'asc' ? ' ↑' : ' ↓';
    };

    const handleKill = async (pid: number) => {
        setKillingPids((prev) => new Set(prev).add(pid));
        const result = await killProcess(pid);
        if (!result.success) {
            console.error(`Kill failed: ${result.message}`);
        }
        setKillingPids((prev) => {
            const next = new Set(prev);
            next.delete(pid);
            return next;
        });
    };

    return (
        <div className="card process-list">
            <div className="card-header">
                <h2 className="card-title">Processes</h2>
                <input
                    type="text"
                    className="search-input"
                    placeholder="Search processes..."
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                />
            </div>
            <div className="table-wrapper">
                <table className="process-table">
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th className="sortable" onClick={() => handleSort('name')}>
                                Name{sortIcon('name')}
                            </th>
                            <th className="sortable" onClick={() => handleSort('cpu_percent')}>
                                CPU{sortIcon('cpu_percent')}
                            </th>
                            <th className="sortable" onClick={() => handleSort('memory_percent')}>
                                Memory{sortIcon('memory_percent')}
                            </th>
                            <th>Threads</th>
                            <th>Disk I/O</th>
                            <th className="sortable" onClick={() => handleSort('threat_score')}>
                                Score{sortIcon('threat_score')}
                            </th>
                            <th>Risk</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sorted.map((proc) => (
                            <tr
                                key={proc.pid}
                                className={
                                    proc.risk_level === 'malicious'
                                        ? 'row--malicious'
                                        : proc.risk_level === 'suspicious'
                                            ? 'row--suspicious'
                                            : ''
                                }
                            >
                                <td className="td-pid">{proc.pid}</td>
                                <td className="td-name clickable" onClick={() => onSelectProcess?.(proc)}>{proc.name}</td>
                                <td>{proc.cpu_percent.toFixed(1)}%</td>
                                <td>{proc.memory_percent.toFixed(1)}%</td>
                                <td>{proc.num_threads}</td>
                                <td className="td-io">
                                    <span title="Read">↓{formatBytes(proc.io_counters?.read_bytes ?? 0)}</span>
                                    {' / '}
                                    <span title="Write">↑{formatBytes(proc.io_counters?.write_bytes ?? 0)}</span>
                                </td>
                                <td>
                                    <span
                                        className={`score-pill ${proc.threat_score > 70
                                            ? 'score-pill--high'
                                            : proc.threat_score > 30
                                                ? 'score-pill--medium'
                                                : 'score-pill--low'
                                            }`}
                                    >
                                        {proc.threat_score}
                                    </span>
                                </td>
                                <td>{getRiskBadge(proc.risk_level)}</td>
                                <td>
                                    {proc.risk_level !== 'safe' && (
                                        <button
                                            className="btn btn--sm btn--danger"
                                            onClick={() => handleKill(proc.pid)}
                                            disabled={killingPids.has(proc.pid)}
                                            title="Terminate this process"
                                        >
                                            {killingPids.has(proc.pid) ? '...' : '✕ Kill'}
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {sorted.length === 0 && (
                    <div className="empty-state">No processes found</div>
                )}
            </div>
        </div>
    );
}
