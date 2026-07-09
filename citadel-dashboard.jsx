import { useState, useEffect, useCallback, useRef } from "react";

// ─── Simulated Keystore State ───────────────────────────────────────────────
const THREAT_LEVELS = [
  { level: 1, name: "LOW", color: "#22c55e", bg: "rgba(34,197,94,0.08)", glow: "0 0 40px rgba(34,197,94,0.3)" },
  { level: 2, name: "GUARDED", color: "#3b82f6", bg: "rgba(59,130,246,0.08)", glow: "0 0 40px rgba(59,130,246,0.3)" },
  { level: 3, name: "ELEVATED", color: "#eab308", bg: "rgba(234,179,8,0.08)", glow: "0 0 40px rgba(234,179,8,0.3)" },
  { level: 4, name: "HIGH", color: "#f97316", bg: "rgba(249,115,22,0.08)", glow: "0 0 40px rgba(249,115,22,0.3)" },
  { level: 5, name: "CRITICAL", color: "#ef4444", bg: "rgba(239,68,68,0.08)", glow: "0 0 40px rgba(239,68,68,0.3)" },
];

const EVENT_KINDS = [
  { kind: "DecryptionFailure", label: "Decryption Failure", severity: 3.0, icon: "✕" },
  { kind: "RapidAccessPattern", label: "Rapid Access", severity: 4.0, icon: "⚡" },
  { kind: "AnomalousAccess", label: "Anomalous Access", severity: 5.0, icon: "⚠" },
  { kind: "ExternalAdvisory", label: "External Advisory", severity: 8.0, icon: "📡" },
  { kind: "AuthFailure", label: "Auth Failure", severity: 3.5, icon: "🔒" },
  { kind: "KeyEnumeration", label: "Key Enumeration", severity: 6.0, icon: "🔍" },
];

const SCALING = {
  1: { age: 1.0, grace: 1.0, lifetime: 1.0, usage: 1.0 },
  2: { age: 0.75, grace: 0.8, lifetime: 0.8, usage: 0.8 },
  3: { age: 0.5, grace: 0.5, lifetime: 0.6, usage: 0.6 },
  4: { age: 0.3, grace: 0.3, lifetime: 0.4, usage: 0.4 },
  5: { age: 0.2, grace: 0.1, lifetime: 0.25, usage: 0.25 },
};

const BASE_POLICIES = [
  { name: "DEK Policy", rotationAge: 90, gracePeriod: 7, maxLifetime: 365, usageLimit: 10000 },
  { name: "KEK Policy", rotationAge: 365, gracePeriod: 30, maxLifetime: null, usageLimit: null },
];

function genKeys() {
  const types = ["Root", "Domain", "KEK", "DEK", "DEK", "DEK", "DEK", "KEK"];
  const states = ["Active", "Active", "Active", "Active", "Rotated", "Active", "Pending", "Active"];
  return types.map((t, i) => ({
    id: `key-${String(i + 1).padStart(3, "0")}`,
    type: t,
    state: states[i],
    version: states[i] === "Rotated" ? 2 : 1,
    usage: Math.floor(Math.random() * 5000),
    created: new Date(Date.now() - Math.random() * 90 * 86400000).toISOString(),
  }));
}

// ─── Metric Computation ─────────────────────────────────────────────────────
function computeMetrics(level) {
  const lv = level;
  return {
    quantumResistance: Math.min(100, 95 - (lv - 1) * 2),
    classicalSecurity: Math.min(100, 98 - (lv - 1) * 1),
    sideChannelResistance: Math.min(100, 90 - (lv - 1) * 3),
    adaptiveDefense: Math.min(100, 60 + lv * 8),
    keyHygiene: 92,
  };
}

function overallScore(m) {
  return (m.quantumResistance * 0.25 + m.classicalSecurity * 0.2 + m.sideChannelResistance * 0.15 + m.adaptiveDefense * 0.2 + m.keyHygiene * 0.2).toFixed(1);
}

// ─── Animated Number ────────────────────────────────────────────────────────
function AnimNum({ value, decimals = 0 }) {
  const [display, setDisplay] = useState(value);
  const ref = useRef(null);
  useEffect(() => {
    let start = display;
    const end = value;
    const duration = 600;
    const startTime = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - startTime) / duration);
      const ease = 1 - Math.pow(1 - p, 3);
      setDisplay(start + (end - start) * ease);
      if (p < 1) ref.current = requestAnimationFrame(tick);
    }
    ref.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(ref.current);
  }, [value]);
  return <>{display.toFixed(decimals)}</>;
}

// ─── Radial Gauge ───────────────────────────────────────────────────────────
function RadialGauge({ value, max = 100, color, label, size = 100 }) {
  const r = (size - 12) / 2;
  const c = 2 * Math.PI * r;
  const pct = value / max;
  const offset = c * (1 - pct * 0.75);
  return (
    <div style={{ textAlign: "center", width: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6"
          strokeDasharray={`${c * 0.75} ${c * 0.25}`} strokeLinecap="round"
          transform={`rotate(135 ${size/2} ${size/2})`} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${c * 0.75} ${c * 0.25}`} strokeDashoffset={offset}
          strokeLinecap="round" transform={`rotate(135 ${size/2} ${size/2})`}
          style={{ transition: "stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1), stroke 0.4s ease" }} />
        <text x={size/2} y={size/2 - 4} textAnchor="middle" fill="white" fontSize="20" fontWeight="700" fontFamily="'JetBrains Mono', monospace">
          <AnimNum value={value} decimals={1} />
        </text>
        <text x={size/2} y={size/2 + 14} textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="8" fontFamily="'JetBrains Mono', monospace" letterSpacing="1">
          {label}
        </text>
      </svg>
    </div>
  );
}

// ─── Hex Badge (threat level) ───────────────────────────────────────────────
function ThreatHex({ level, config, pulse }) {
  const s = 140;
  const points = Array.from({ length: 6 }, (_, i) => {
    const a = (Math.PI / 3) * i - Math.PI / 2;
    return `${s/2 + (s/2 - 8) * Math.cos(a)},${s/2 + (s/2 - 8) * Math.sin(a)}`;
  }).join(" ");

  return (
    <div style={{ position: "relative", width: s, height: s }}>
      {pulse && (
        <div style={{
          position: "absolute", inset: -20, borderRadius: "50%",
          background: `radial-gradient(circle, ${config.color}22 0%, transparent 70%)`,
          animation: "threatPulse 2s ease-in-out infinite",
        }} />
      )}
      <svg width={s} height={s} viewBox={`0 0 ${s} ${s}`}>
        <polygon points={points} fill={config.bg} stroke={config.color} strokeWidth="2"
          style={{ filter: `drop-shadow(${config.glow})`, transition: "all 0.6s ease" }} />
        <text x={s/2} y={s/2 - 14} textAnchor="middle" fill={config.color} fontSize="38" fontWeight="800"
          fontFamily="'JetBrains Mono', monospace" style={{ transition: "fill 0.4s ease" }}>
          {level}
        </text>
        <text x={s/2} y={s/2 + 12} textAnchor="middle" fill={config.color} fontSize="12" fontWeight="600"
          fontFamily="'JetBrains Mono', monospace" letterSpacing="3" opacity="0.9">
          {config.name}
        </text>
      </svg>
    </div>
  );
}

// ─── Main Dashboard ─────────────────────────────────────────────────────────
export default function CitadelDashboard() {
  const [threatLevel, setThreatLevel] = useState(1);
  const [score, setScore] = useState(0);
  const [events, setEvents] = useState([]);
  const [keys] = useState(genKeys);
  const [showEventFeed, setShowEventFeed] = useState(true);
  const [flashLevel, setFlashLevel] = useState(false);

  const config = THREAT_LEVELS[threatLevel - 1];
  const metrics = computeMetrics(threatLevel);
  const scaling = SCALING[threatLevel];

  const addEvent = useCallback((eventKind) => {
    const ek = EVENT_KINDS.find(e => e.kind === eventKind) || EVENT_KINDS[0];
    const newEvent = {
      id: Date.now() + Math.random(),
      kind: ek.kind,
      label: ek.label,
      icon: ek.icon,
      severity: ek.severity,
      time: new Date().toLocaleTimeString(),
    };
    setEvents(prev => [newEvent, ...prev].slice(0, 50));
    setScore(prev => {
      const next = prev + ek.severity;
      const newLevel = next >= 50 ? 5 : next >= 30 ? 4 : next >= 15 ? 3 : next >= 5 ? 2 : 1;
      if (newLevel !== threatLevel) {
        setThreatLevel(newLevel);
        setFlashLevel(true);
        setTimeout(() => setFlashLevel(false), 1500);
      }
      return next;
    });
  }, [threatLevel]);

  const resetThreats = () => { setScore(0); setThreatLevel(1); setEvents([]); };

  // Decay score
  useEffect(() => {
    const iv = setInterval(() => {
      setScore(prev => {
        const next = prev * 0.97;
        const newLevel = next >= 50 ? 5 : next >= 30 ? 4 : next >= 15 ? 3 : next >= 5 ? 2 : 1;
        setThreatLevel(newLevel);
        return next;
      });
    }, 2000);
    return () => clearInterval(iv);
  }, []);

  const stateColor = (s) => ({ Active: "#22c55e", Rotated: "#eab308", Pending: "#3b82f6", Revoked: "#f97316", Destroyed: "#6b7280" }[s] || "#6b7280");

  return (
    <div style={{
      minHeight: "100vh", background: "#0a0c10", color: "#e2e8f0",
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      position: "relative", overflow: "hidden",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&display=swap');
        @keyframes threatPulse { 0%, 100% { transform: scale(1); opacity: 0.5; } 50% { transform: scale(1.3); opacity: 0; } }
        @keyframes scanline { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
        @keyframes fadeSlideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes glowPulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 0.7; } }
        @keyframes levelFlash { 0% { opacity: 1; } 100% { opacity: 0; } }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 2px; }
      `}</style>

      {/* Scanline overlay */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 100,
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)",
      }} />

      {/* Grid background */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", opacity: 0.03,
        backgroundImage: "linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)",
        backgroundSize: "40px 40px",
      }} />

      {/* Level flash overlay */}
      {flashLevel && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 90, pointerEvents: "none",
          background: `radial-gradient(ellipse at center, ${config.color}15, transparent 70%)`,
          animation: "levelFlash 1.5s ease-out forwards",
        }} />
      )}

      {/* ─── Header ───────────────────────────────────────────────── */}
      <header style={{
        padding: "16px 24px", display: "flex", alignItems: "center", justifyContent: "space-between",
        borderBottom: "1px solid rgba(255,255,255,0.06)", backdropFilter: "blur(12px)",
        background: "rgba(10,12,16,0.8)", position: "sticky", top: 0, zIndex: 50,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center",
            background: `linear-gradient(135deg, ${config.color}30, ${config.color}10)`,
            border: `1px solid ${config.color}40`, transition: "all 0.4s ease",
          }}>
            <span style={{ fontSize: 16 }}>🏰</span>
          </div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, letterSpacing: 2, color: "#fff" }}>CITADEL</div>
            <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.35)", marginTop: -2 }}>SECURITY OPERATIONS</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: 1 }}>
            X25519 + ML-KEM-768 + AES-256-GCM
          </div>
          <div style={{
            padding: "4px 10px", borderRadius: 4, fontSize: 10, fontWeight: 600, letterSpacing: 1,
            background: config.bg, color: config.color, border: `1px solid ${config.color}30`,
            transition: "all 0.4s ease",
          }}>
            DEFCON {6 - threatLevel}
          </div>
        </div>
      </header>

      <div style={{ padding: "20px 24px", maxWidth: 1400, margin: "0 auto" }}>

        {/* ─── Top Row: Threat + Metrics ─────────────────────────── */}
        <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 20, marginBottom: 20 }}>

          {/* Threat Level Card */}
          <div style={{
            background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 12, padding: 24, display: "flex", flexDirection: "column", alignItems: "center",
            position: "relative", overflow: "hidden",
          }}>
            <div style={{
              position: "absolute", top: 0, left: 0, right: 0, height: 2,
              background: `linear-gradient(90deg, transparent, ${config.color}, transparent)`,
              transition: "background 0.4s ease",
            }} />
            <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.35)", marginBottom: 16 }}>THREAT ASSESSMENT</div>
            <ThreatHex level={threatLevel} config={config} pulse={threatLevel >= 3} />
            <div style={{
              marginTop: 16, width: "100%", height: 4, borderRadius: 2, background: "rgba(255,255,255,0.06)",
              position: "relative", overflow: "hidden",
            }}>
              <div style={{
                position: "absolute", left: 0, top: 0, bottom: 0, borderRadius: 2,
                width: `${(score / 60) * 100}%`, maxWidth: "100%",
                background: `linear-gradient(90deg, ${config.color}80, ${config.color})`,
                transition: "width 0.6s ease, background 0.4s ease",
              }} />
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", marginTop: 8 }}>
              SCORE: <span style={{ color: config.color, fontWeight: 600 }}>{score.toFixed(1)}</span>
            </div>

            {/* Manual controls */}
            <div style={{ marginTop: 16, width: "100%", display: "flex", gap: 6 }}>
              <button onClick={resetThreats} style={{
                flex: 1, padding: "6px 0", fontSize: 9, fontWeight: 600, letterSpacing: 1,
                background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)",
                color: "#22c55e", borderRadius: 4, cursor: "pointer", fontFamily: "inherit",
              }}>↓ RESET</button>
              <button onClick={() => addEvent("ExternalAdvisory")} style={{
                flex: 1, padding: "6px 0", fontSize: 9, fontWeight: 600, letterSpacing: 1,
                background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)",
                color: "#ef4444", borderRadius: 4, cursor: "pointer", fontFamily: "inherit",
              }}>↑ ESCALATE</button>
            </div>
          </div>

          {/* Security Metrics */}
          <div style={{
            background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 12, padding: 24,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.35)" }}>SECURITY POSTURE</div>
              <div style={{ fontSize: 28, fontWeight: 800, color: config.color, transition: "color 0.4s ease" }}>
                <AnimNum value={parseFloat(overallScore(metrics))} decimals={1} />
                <span style={{ fontSize: 12, fontWeight: 400, color: "rgba(255,255,255,0.3)", marginLeft: 4 }}>/100</span>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 8 }}>
              {[
                { label: "QUANTUM", value: metrics.quantumResistance, color: "#a78bfa" },
                { label: "CLASSICAL", value: metrics.classicalSecurity, color: "#60a5fa" },
                { label: "SIDE-CH", value: metrics.sideChannelResistance, color: "#34d399" },
                { label: "ADAPTIVE", value: metrics.adaptiveDefense, color: config.color },
                { label: "HYGIENE", value: metrics.keyHygiene, color: "#f472b6" },
              ].map((m, i) => (
                <RadialGauge key={i} value={m.value} color={m.color} label={m.label} size={110} />
              ))}
            </div>
          </div>
        </div>

        {/* ─── Middle: Policy Adaptation ─────────────────────────── */}
        <div style={{
          background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 12, padding: 24, marginBottom: 20,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.35)" }}>ADAPTIVE POLICY ENGINE</div>
            <div style={{
              padding: "3px 8px", borderRadius: 3, fontSize: 9, fontWeight: 600,
              background: config.bg, color: config.color, border: `1px solid ${config.color}20`,
            }}>
              {threatLevel >= 3 ? "AUTO-ROTATE FORCED" : "NORMAL OPS"}
            </div>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                  {["POLICY", "PARAMETER", "BASE VALUE", "FACTOR", "EFFECTIVE", "CHANGE"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 9, letterSpacing: 2, color: "rgba(255,255,255,0.3)", fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {BASE_POLICIES.flatMap((pol, pi) => {
                  const rows = [
                    { param: "Rotation Age", base: pol.rotationAge ? `${pol.rotationAge}d` : "—", factor: scaling.age, effective: pol.rotationAge ? `${Math.round(pol.rotationAge * scaling.age)}d` : "—", baseVal: pol.rotationAge },
                    { param: "Grace Period", base: `${pol.gracePeriod}d`, factor: scaling.grace, effective: `${Math.round(pol.gracePeriod * scaling.grace)}d`, baseVal: pol.gracePeriod },
                    { param: "Max Lifetime", base: pol.maxLifetime ? `${pol.maxLifetime}d` : "∞", factor: scaling.lifetime, effective: pol.maxLifetime ? `${Math.round(pol.maxLifetime * scaling.lifetime)}d` : "∞", baseVal: pol.maxLifetime },
                    { param: "Usage Limit", base: pol.usageLimit ? pol.usageLimit.toLocaleString() : "∞", factor: scaling.usage, effective: pol.usageLimit ? Math.round(pol.usageLimit * scaling.usage).toLocaleString() : "∞", baseVal: pol.usageLimit },
                  ];
                  return rows.map((row, ri) => (
                    <tr key={`${pi}-${ri}`} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      {ri === 0 ? <td rowSpan={4} style={{ padding: "8px 12px", fontWeight: 600, color: "#fff", verticalAlign: "top", borderRight: "1px solid rgba(255,255,255,0.06)" }}>{pol.name}</td> : null}
                      <td style={{ padding: "8px 12px", color: "rgba(255,255,255,0.6)" }}>{row.param}</td>
                      <td style={{ padding: "8px 12px", color: "rgba(255,255,255,0.4)" }}>{row.base}</td>
                      <td style={{ padding: "8px 12px" }}>
                        <span style={{
                          color: row.factor < 1 ? config.color : "rgba(255,255,255,0.4)",
                          fontWeight: row.factor < 1 ? 600 : 400,
                        }}>
                          {row.factor === 1 ? "1.0×" : `${row.factor}×`}
                        </span>
                      </td>
                      <td style={{ padding: "8px 12px", fontWeight: 600, color: row.factor < 1 ? "#fff" : "rgba(255,255,255,0.4)" }}>{row.effective}</td>
                      <td style={{ padding: "8px 12px" }}>
                        {row.baseVal && row.factor < 1 ? (
                          <span style={{ color: config.color, fontSize: 11 }}>
                            ▼ {Math.round((1 - row.factor) * 100)}%
                          </span>
                        ) : <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>}
                      </td>
                    </tr>
                  ));
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* ─── Bottom Row: Events + Keys ─────────────────────────── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>

          {/* Event Injector + Feed */}
          <div style={{
            background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 12, padding: 24,
          }}>
            <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.35)", marginBottom: 12 }}>
              INJECT THREAT EVENTS
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, marginBottom: 16 }}>
              {EVENT_KINDS.map(ek => (
                <button key={ek.kind} onClick={() => addEvent(ek.kind)} style={{
                  padding: "8px 6px", fontSize: 9, fontWeight: 500, letterSpacing: 0.5,
                  background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.7)", borderRadius: 6, cursor: "pointer", fontFamily: "inherit",
                  display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
                  transition: "all 0.2s ease",
                }}
                onMouseEnter={e => { e.target.style.background = "rgba(255,255,255,0.06)"; e.target.style.borderColor = config.color + "40"; }}
                onMouseLeave={e => { e.target.style.background = "rgba(255,255,255,0.03)"; e.target.style.borderColor = "rgba(255,255,255,0.08)"; }}
                >
                  <span style={{ fontSize: 16 }}>{ek.icon}</span>
                  <span>{ek.label}</span>
                  <span style={{ color: "rgba(255,255,255,0.3)" }}>sev: {ek.severity}</span>
                </button>
              ))}
            </div>

            <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.35)", marginBottom: 8 }}>
              EVENT FEED ({events.length})
            </div>
            <div style={{ maxHeight: 200, overflowY: "auto" }}>
              {events.length === 0 ? (
                <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 11, textAlign: "center", padding: 24 }}>
                  No events. Click above to inject threats.
                </div>
              ) : events.map(ev => (
                <div key={ev.id} style={{
                  padding: "6px 10px", marginBottom: 3, borderRadius: 4,
                  background: "rgba(255,255,255,0.02)", borderLeft: `2px solid ${config.color}40`,
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  animation: "fadeSlideIn 0.3s ease",
                  fontSize: 11,
                }}>
                  <span>
                    <span style={{ marginRight: 6 }}>{ev.icon}</span>
                    <span style={{ color: "rgba(255,255,255,0.7)" }}>{ev.label}</span>
                  </span>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10 }}>{ev.time}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Key Inventory */}
          <div style={{
            background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 12, padding: 24,
          }}>
            <div style={{ fontSize: 9, letterSpacing: 3, color: "rgba(255,255,255,0.35)", marginBottom: 12 }}>
              KEY INVENTORY
            </div>
            <div style={{ maxHeight: 380, overflowY: "auto" }}>
              {keys.map(k => (
                <div key={k.id} style={{
                  padding: "10px 12px", marginBottom: 4, borderRadius: 6,
                  background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)",
                  display: "grid", gridTemplateColumns: "1fr auto auto auto", alignItems: "center", gap: 12,
                  fontSize: 11,
                }}>
                  <div>
                    <div style={{ fontWeight: 600, color: "#fff", fontSize: 12 }}>{k.id}</div>
                    <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, marginTop: 2 }}>
                      {k.type} · v{k.version}
                    </div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 10 }}>usage</div>
                    <div style={{ fontWeight: 600, color: "rgba(255,255,255,0.7)" }}>{k.usage.toLocaleString()}</div>
                  </div>
                  <div style={{
                    padding: "3px 8px", borderRadius: 3, fontSize: 9, fontWeight: 600, letterSpacing: 1,
                    background: stateColor(k.state) + "15", color: stateColor(k.state),
                    border: `1px solid ${stateColor(k.state)}25`, minWidth: 65, textAlign: "center",
                  }}>
                    {k.state.toUpperCase()}
                  </div>
                  <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, minWidth: 70, textAlign: "right" }}>
                    {new Date(k.created).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ─── Footer ─────────────────────────────────────────────── */}
        <div style={{
          marginTop: 20, padding: "12px 0", borderTop: "1px solid rgba(255,255,255,0.04)",
          display: "flex", justifyContent: "space-between", alignItems: "center",
          fontSize: 10, color: "rgba(255,255,255,0.2)",
        }}>
          <span>citadel-keystore v0.1.0 · citadel-envelope v0.1.0</span>
          <span>HYBRID POST-QUANTUM · FIPS 203 ML-KEM-768</span>
        </div>
      </div>
    </div>
  );
}
