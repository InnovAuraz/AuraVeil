// Auraveil — Shared TypeScript Interfaces (Phase 2)

export interface SystemMetrics {
    cpu_percent: number;
    memory_percent: number;
    disk_io: { read_bytes: number; write_bytes: number; read_count: number; write_count: number };
    net_io: { bytes_sent: number; bytes_recv: number; packets_sent: number; packets_recv: number };
}

export interface NetworkMetrics {
    timestamp: string;
    packets_in: number;
    packets_out: number;
    bytes_in: number;
    bytes_out: number;
    active_connections: number;
    unique_destinations: number;
    dns_queries: string[];
    suspicious_ports: Array<{ port: number; src: string; dst: string }>;
}

export interface FileActivity {
    timestamp: string;
    total_events: number;
    by_type: { created: number; modified: number; deleted: number; moved: number };
    files_affected: number;
}

export interface ProcessInfo {
    pid: number;
    name: string;
    cpu_percent: number;
    memory_percent: number;
    num_threads: number;
    io_counters: { read_bytes: number; write_bytes: number; read_count: number; write_count: number };
    threat_score: number;
    risk_level: 'safe' | 'suspicious' | 'malicious';
    reasons: string[];
    parent_pid?: number;
}

export interface LifecycleEvents {
    new_processes: number;
    terminated: number;
    suspicious_spawns: Array<{
        type: string;
        timestamp: string;
        parent_name: string;
        child_name: string;
        reason: string;
    }>;
}

export interface NewAlert {
    timestamp: string;
    process_name: string;
    pid: number;
    threat_score: number;
    risk_level: string;
    reasons: string[];
    action: string;
}

export interface MetricsSnapshot {
    timestamp: string;
    system: SystemMetrics;
    network: NetworkMetrics;
    file_activity: FileActivity;
    processes: ProcessInfo[];
    active_alerts: number;
    lifecycle?: LifecycleEvents;
    new_alerts?: NewAlert[];
}

export interface ThreatRecord {
    id: number;
    timestamp: string;
    process_name: string;
    pid: number;
    threat_score: number;
    risk_level: string;
    reasons: string[];
    action_taken: string;
    resolved: boolean;
}

export interface ModelInfo {
    is_trained: boolean;
    last_trained_at: string | null;
    training_samples: number;
    isolation_forest: { n_estimators: number; contamination: number };
    lstm: { available: boolean; is_trained: boolean; sequences_collected: number };
    shap: { available: boolean };
    ensemble_weights: { isolation_forest: number; lstm: number };
}

export interface EngineStatus {
    status: string;
    uptime_seconds: number;
    model_trained: boolean;
    training_samples: number;
    buffer_size: number;
    file_monitor_active: boolean;
    network_monitor_mode: string;
    ws_connections: number;
    model: ModelInfo;
}

export interface SettingsConfig {
    monitor_interval: number;
    threshold_safe: number;
    threshold_suspicious: number;
    auto_stop_enabled: boolean;
    auto_stop_threshold: number;
    alert_cooldown: number;
    ensemble_weight_if: number;
    ensemble_weight_lstm: number;
}

export interface ProcessExplanation {
    pid: number;
    process_name: string;
    explanation: {
        method: string;
        features: Array<{ feature: string; importance: number; value: number }>;
    };
}
