// Auraveil — Main App (Phase 3)
// Tabbed dashboard with glassmorphism, error boundary, process detail modal

import { useEffect, useRef, useState } from 'react';
import { useThreatStore } from './stores/threatStore';
import type { ProcessInfo } from './types';

import ErrorBoundary from './components/ErrorBoundary';
import StatusBar from './components/StatusBar';
import MetricsChart from './components/MetricsChart';
import AlertFeed from './components/AlertFeed';
import ThreatTimeline from './components/ThreatTimeline';
import ProcessList from './components/ProcessList';
import NetworkPanel from './components/NetworkPanel';
import SettingsPanel from './components/SettingsPanel';
import ProcessDetail from './components/ProcessDetail';

import './App.css';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://127.0.0.1:8000/ws/live';

export default function App() {
  const updateSnapshot = useThreatStore((s) => s.updateSnapshot);
  const setConnected = useThreatStore((s) => s.setConnected);
  const connected = useThreatStore((s) => s.connected);
  const activeTab = useThreatStore((s) => s.activeTab);
  const setActiveTab = useThreatStore((s) => s.setActiveTab);
  const wsRef = useRef<WebSocket | null>(null);
  const [selectedProcess, setSelectedProcess] = useState<ProcessInfo | null>(null);

  useEffect(() => {
    let ws: WebSocket;
    let retryTimeout: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        retryTimeout = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          updateSnapshot(data);
        } catch { /* ignore */ }
      };
    };

    connect();
    return () => {
      clearTimeout(retryTimeout);
      ws?.close();
    };
  }, [updateSnapshot, setConnected]);

  const tabs: Array<{ key: typeof activeTab; label: string; icon: string }> = [
    { key: 'dashboard', label: 'Dashboard', icon: '📊' },
    { key: 'network', label: 'Network', icon: '🌐' },
    { key: 'settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <ErrorBoundary>
      <div className="app">
        {/* Header */}
        <header className="app-header">
          <div className="brand">
            <span className="brand-icon">🔮</span>
            <h1 className="brand-title">Auraveil</h1>
            <span className="brand-version">v0.3.0</span>
          </div>
          <nav className="tab-nav">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                className={`tab-btn ${activeTab === tab.key ? 'tab-btn--active' : ''}`}
                onClick={() => setActiveTab(tab.key)}
              >
                <span className="tab-icon">{tab.icon}</span>
                <span className="tab-label">{tab.label}</span>
              </button>
            ))}
          </nav>
          <div className="header-status">
            <span className={`ws-dot ${connected ? 'ws-dot--on' : 'ws-dot--off'}`} />
            <span className="ws-label">{connected ? 'Live' : 'Offline'}</span>
          </div>
        </header>

        {/* Tab Content */}
        <main className="app-main">
          {activeTab === 'dashboard' && (
            <div className="dashboard-grid">
              <StatusBar />
              <MetricsChart />
              <AlertFeed />
              <ThreatTimeline />
              <ProcessList onSelectProcess={setSelectedProcess} />
            </div>
          )}
          {activeTab === 'network' && <NetworkPanel />}
          {activeTab === 'settings' && <SettingsPanel />}
        </main>

        {/* Process Detail Modal */}
        {selectedProcess && (
          <ProcessDetail
            process={selectedProcess}
            onClose={() => setSelectedProcess(null)}
          />
        )}
      </div>
    </ErrorBoundary>
  );
}
