import { useState, useEffect, useRef, useCallback } from "react";
import { AlertTriangle, Shield, Activity, Eye, Zap, Terminal, ChevronRight, X, Check, RefreshCw, Radio } from "lucide-react";

// ─── Color & severity helpers ────────────────────────────────────────────────
const SEV_COLOR = {
  CRITICAL: { bg: "#ff2d55", text: "#fff",     ring: "rgba(255,45,85,0.4)"  },
  HIGH:     { bg: "#ff9f0a", text: "#000",     ring: "rgba(255,159,10,0.4)" },
  MEDIUM:   { bg: "#ffd60a", text: "#000",     ring: "rgba(255,214,10,0.4)" },
  LOW:      { bg: "#30d158", text: "#000",     ring: "rgba(48,209,88,0.4)"  },
};
const sevColor = (s) => SEV_COLOR[s] || SEV_COLOR.LOW;

const THREAT_ICON = {
  "C2 Beaconing":      "📡",
  "Brute Force":       "🔨",
  "Data Exfiltration": "📤",
  "Lateral Movement":  "🔄",
  "Benign":            "✅",
};

// ─── Mock data generator (for demo without backend) ──────────────────────────
let _id = 1;
const THREAT_TYPES = ["C2 Beaconing","Brute Force","Data Exfiltration","Lateral Movement"];
const LAYERS       = ["network","endpoint","application"];
const SEVERITIES   = ["CRITICAL","HIGH","MEDIUM","LOW"];
const MITRE_MAP = {
  "C2 Beaconing":      { technique:"T1071", tactic:"Command & Control" },
  "Brute Force":       { technique:"T1110", tactic:"Credential Access"  },
  "Data Exfiltration": { technique:"T1041", tactic:"Exfiltration"        },
  "Lateral Movement":  { technique:"T1021", tactic:"Lateral Movement"   },
};

function rnd(a,b){ return Math.floor(Math.random()*(b-a+1))+a; }
function ip(internal=true){
  return internal
    ? `10.0.${rnd(0,5)}.${rnd(1,254)}`
    : `${rnd(45,203)}.${rnd(10,220)}.${rnd(1,250)}.${rnd(1,254)}`;
}

function mockIncident(overrides={}){
  const threat = THREAT_TYPES[rnd(0,3)];
  const sev    = SEVERITIES[rnd(0,3)];
  const conf   = +(Math.random()*0.45+0.55).toFixed(3);
  const isFP   = Math.random()<0.06;
  return {
    id:          `INC-${String(_id++).padStart(4,"0")}`,
    timestamp:   new Date().toISOString(),
    threat_type: threat,
    severity:    sev,
    confidence:  conf,
    source_layer:LAYERS[rnd(0,2)],
    src_ip:      ip(true),
    dst_ip:      ip(false),
    dst_port:    [443,22,445,3389,4444,8443][rnd(0,5)],
    bytes_transferred: rnd(500,500_000_000),
    is_false_positive: isFP,
    fp_reason:   isFP ? "Known backup process — bulk transfer expected" : null,
    is_correlated: Math.random()>0.4,
    correlated_layers: ["network","endpoint"].slice(0,rnd(1,2)),
    status:      "open",
    mitre:       MITRE_MAP[threat],
    explanation: {
      plain_english: `${threat} detected from ${ip(true)} — confidence ${(conf*100).toFixed(0)}%.`,
      shap_values: [
        { feature:"Beacon interval regularity",  shap_value:+(Math.random()*0.3+0.6).toFixed(2),  color:"red" },
        { feature:"Destination IP reputation",   shap_value:+(Math.random()*0.3+0.5).toFixed(2),  color:"red" },
        { feature:"Outbound payload size",        shap_value:+(Math.random()*0.3+0.4).toFixed(2),  color:"orange" },
        { feature:"Process ancestry",             shap_value:+(Math.random()*0.2+0.3).toFixed(2),  color:"orange" },
        { feature:"User schedule baseline",       shap_value:-(Math.random()*0.2+0.1).toFixed(2),  color:"green" },
        { feature:"Known admin task match",       shap_value:-(Math.random()*0.3+0.2).toFixed(2),  color:"green" },
      ],
      false_positive_risk: isFP ? "HIGH" : conf>0.8 ? "LOW" : "MEDIUM",
    },
    playbook_steps: {
      title: `${threat} Response Playbook`,
      mitre_tags: [MITRE_MAP[threat]?.technique,"TA0011"],
      steps: [
        { step:1, action:`Isolate source host ${ip(true)} from network segment`, priority:"IMMEDIATE", sla_minutes:1 },
        { step:2, action:`Block egress to ${ip(false)} at perimeter firewall`,   priority:"IMMEDIATE", sla_minutes:2 },
        { step:3, action:"Capture full PCAP for forensic analysis (60s window)", priority:"HIGH",      sla_minutes:5 },
        { step:4, action:"Scan host for malware — IOC list auto-attached",       priority:"HIGH",      sla_minutes:10},
        { step:5, action:"Escalate to P1 — notify IR team, open ticket",         priority:"HIGH",      sla_minutes:5 },
        { step:6, action:"Threat-hunt lateral movement from this host",           priority:"MEDIUM",    sla_minutes:30},
        { step:7, action:"Document findings, update threat intel feeds",          priority:"LOW",       sla_minutes:60},
      ]
    },
    ...overrides,
  };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent, pulse }){
  return (
    <div style={{
      background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.08)",
      borderRadius:12, padding:"18px 22px", position:"relative", overflow:"hidden",
    }}>
      {pulse && (
        <span style={{
          position:"absolute", top:14, right:14, width:8, height:8,
          borderRadius:"50%", background:accent,
          boxShadow:`0 0 8px ${accent}`,
          animation:"pulse-dot 1.5s ease-in-out infinite",
        }}/>
      )}
      <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", letterSpacing:"0.1em", textTransform:"uppercase", marginBottom:6 }}>{label}</div>
      <div style={{ fontSize:32, fontWeight:700, fontFamily:"'JetBrains Mono',monospace", color: accent || "#fff" }}>{value}</div>
      {sub && <div style={{ fontSize:11, color:"rgba(255,255,255,0.35)", marginTop:4 }}>{sub}</div>}
    </div>
  );
}

function SeverityBadge({ sev }){
  const c = sevColor(sev);
  return (
    <span style={{
      background: c.bg, color: c.text, fontSize:10, fontWeight:700,
      padding:"2px 8px", borderRadius:4, letterSpacing:"0.06em",
      fontFamily:"'JetBrains Mono',monospace",
    }}>{sev}</span>
  );
}

function IncidentRow({ inc, selected, onClick }){
  const c = sevColor(inc.severity);
  return (
    <div onClick={onClick} style={{
      display:"grid", gridTemplateColumns:"80px 1fr 110px 80px 100px 28px",
      alignItems:"center", gap:8,
      padding:"10px 16px", cursor:"pointer",
      background: selected ? "rgba(255,255,255,0.06)" : "transparent",
      borderLeft: `3px solid ${selected ? c.bg : "transparent"}`,
      transition:"all 0.15s",
    }}
      onMouseEnter={e=>{ if(!selected) e.currentTarget.style.background="rgba(255,255,255,0.03)"; }}
      onMouseLeave={e=>{ if(!selected) e.currentTarget.style.background="transparent"; }}
    >
      <span style={{ fontSize:11, fontFamily:"monospace", color:"rgba(255,255,255,0.4)" }}>
        {new Date(inc.timestamp).toLocaleTimeString()}
      </span>
      <div>
        <span style={{ fontSize:13, color:"#e0e0e0" }}>{THREAT_ICON[inc.threat_type]} {inc.threat_type}</span>
        <span style={{ fontSize:11, color:"rgba(255,255,255,0.35)", marginLeft:6 }}>
          {inc.src_ip} → {inc.dst_ip}
        </span>
      </div>
      <SeverityBadge sev={inc.severity}/>
      <span style={{ fontSize:11, fontFamily:"monospace", color:"rgba(255,255,255,0.5)" }}>
        {(inc.confidence*100).toFixed(0)}%
      </span>
      <span style={{
        fontSize:10, padding:"2px 6px", borderRadius:3,
        background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.4)",
        textTransform:"uppercase",
      }}>{inc.source_layer}</span>
      {inc.is_false_positive
        ? <span title="False Positive" style={{ fontSize:14, color:"#30d158" }}>✓</span>
        : <span/>
      }
    </div>
  );
}

function SHAPChart({ values }){
  if (!values?.length) return null;
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {values.map((v,i)=>(
        <div key={i} style={{ display:"grid", gridTemplateColumns:"180px 1fr 48px", alignItems:"center", gap:10 }}>
          <span style={{ fontSize:11, color:"rgba(255,255,255,0.6)", textAlign:"right" }}>{v.feature}</span>
          <div style={{ height:14, borderRadius:3, background:"rgba(255,255,255,0.07)", overflow:"hidden" }}>
            <div style={{
              height:"100%", borderRadius:3,
              width:`${Math.abs(v.shap_value)*100}%`,
              background: v.color==="red" ? "#ff2d55" : v.color==="orange" ? "#ff9f0a" : "#30d158",
              transition:"width 0.6s ease",
            }}/>
          </div>
          <span style={{
            fontSize:12, fontFamily:"monospace", fontWeight:600,
            color: v.shap_value>0 ? "#ff6b6b" : "#30d158",
            textAlign:"right",
          }}>{v.shap_value>0?"+":""}{v.shap_value}</span>
        </div>
      ))}
    </div>
  );
}

function PlaybookPanel({ pb }){
  if (!pb) return null;
  const priorityColor = { IMMEDIATE:"#ff2d55", HIGH:"#ff9f0a", MEDIUM:"#ffd60a", LOW:"#30d158" };
  return (
    <div>
      <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:12 }}>
        {pb.mitre_tags?.map(t=>(
          <span key={t} style={{
            fontSize:10, padding:"2px 8px", borderRadius:3,
            background:"rgba(99,102,241,0.2)", color:"#a5b4fc",
            fontFamily:"monospace", border:"1px solid rgba(99,102,241,0.3)",
          }}>{t}</span>
        ))}
      </div>
      <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
        {pb.steps?.map(s=>(
          <div key={s.step} style={{
            display:"flex", gap:10, alignItems:"flex-start",
            padding:"8px 10px", borderRadius:6,
            background:"rgba(255,255,255,0.03)",
            borderLeft:`3px solid ${priorityColor[s.priority]||"#555"}`,
          }}>
            <span style={{
              minWidth:22, height:22, borderRadius:"50%", display:"flex",
              alignItems:"center", justifyContent:"center",
              background: priorityColor[s.priority]||"#555",
              color:"#000", fontSize:11, fontWeight:700, flexShrink:0,
            }}>{s.step}</span>
            <div>
              <div style={{ fontSize:12, color:"#e0e0e0" }}>{s.action}</div>
              {s.sla_minutes && (
                <div style={{ fontSize:10, color:"rgba(255,255,255,0.35)", marginTop:2 }}>
                  SLA: {s.sla_minutes < 60 ? `${s.sla_minutes}m` : `${Math.floor(s.sla_minutes/60)}h`}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Threat rate sparkline ────────────────────────────────────────────────────
function Sparkline({ data, color="#6366f1", height=40 }){
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  const pts = data.map((v,i)=>`${(i/(data.length-1))*200},${height-(v/max)*height}`).join(" ");
  return (
    <svg width="100%" height={height} viewBox={`0 0 200 ${height}`} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round"/>
      <polyline points={`${pts} 200,${height} 0,${height}`}
        fill={`${color}22`} stroke="none"/>
    </svg>
  );
}

// ─── Detection pipeline phase indicator ──────────────────────────────────────
function PipelineIndicator({ phase }){
  const phases = [
    { label:"Scout",    sub:"Isolation Forest",  active: phase>=1 },
    { label:"Expert",   sub:"XGBoost + SHAP",    active: phase>=2 },
    { label:"Enforcer", sub:"Dynamic Playbooks",  active: phase>=3 },
  ];
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
      {phases.map((p,i)=>(
        <div key={i} style={{
          padding:"8px 10px", borderRadius:6,
          background: p.active ? "rgba(99,102,241,0.15)" : "rgba(255,255,255,0.03)",
          border: `1px solid ${p.active ? "rgba(99,102,241,0.4)" : "rgba(255,255,255,0.06)"}`,
          transition:"all 0.3s",
        }}>
          <div style={{ fontSize:10, fontWeight:700, color: p.active ? "#a5b4fc" : "rgba(255,255,255,0.3)", textTransform:"uppercase", letterSpacing:"0.08em" }}>
            Phase {i+1} — {p.label}
          </div>
          <div style={{ fontSize:11, color: p.active ? "rgba(255,255,255,0.6)" : "rgba(255,255,255,0.2)", marginTop:2 }}>
            {p.sub}
          </div>
          {p.active && (
            <div style={{ marginTop:6, height:2, borderRadius:1, background:"rgba(99,102,241,0.2)", overflow:"hidden" }}>
              <div style={{ height:"100%", width:"100%", background:"#6366f1", animation:"progress-bar 2s ease-in-out infinite" }}/>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Threat distribution donut ────────────────────────────────────────────────
function ThreatDonut({ counts }){
  const total = Object.values(counts).reduce((a,b)=>a+b, 0)||1;
  const colors = { "C2 Beaconing":"#ff2d55","Brute Force":"#ff9f0a","Data Exfiltration":"#6366f1","Lateral Movement":"#ffd60a" };
  let offset = 0;
  const cx=60, cy=60, r=45, stroke=14;
  const circ = 2*Math.PI*r;
  return (
    <div style={{ display:"flex", alignItems:"center", gap:20 }}>
      <svg width={120} height={120} viewBox="0 0 120 120">
        {Object.entries(counts).map(([k,v])=>{
          const pct = v/total;
          const dash = circ*pct;
          const gap  = circ*(1-pct);
          const rot  = 360*offset - 90;
          offset += pct;
          return (
            <circle key={k} cx={cx} cy={cy} r={r}
              fill="none" stroke={colors[k]||"#555"} strokeWidth={stroke}
              strokeDasharray={`${dash} ${gap}`}
              strokeDashoffset={0}
              transform={`rotate(${rot} ${cx} ${cy})`}
              opacity={0.85}
            />
          );
        })}
        <text x={cx} y={cy+4} textAnchor="middle" fill="#fff" fontSize={14} fontWeight={700}>{total}</text>
        <text x={cx} y={cy+16} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize={8}>incidents</text>
      </svg>
      <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
        {Object.entries(counts).map(([k,v])=>(
          <div key={k} style={{ display:"flex", alignItems:"center", gap:6 }}>
            <div style={{ width:8, height:8, borderRadius:2, background:colors[k]||"#555", flexShrink:0 }}/>
            <span style={{ fontSize:11, color:"rgba(255,255,255,0.6)" }}>{k}</span>
            <span style={{ fontSize:11, fontWeight:700, color:"#e0e0e0", marginLeft:"auto", paddingLeft:8 }}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function SOCDashboard(){
  const [incidents, setIncidents]       = useState([]);
  const [selected,  setSelected]        = useState(null);
  const [activeTab, setActiveTab]       = useState("explanation");  // explanation | playbook | timeline
  const [stats,     setStats]           = useState({ eps:510, open:0, detectTime:"0.7m", fp:252, conf:89 });
  const [rateHistory, setRateHistory]   = useState(Array(40).fill(0));
  const [pipelinePhase, setPipeline]    = useState(3);
  const [filter,    setFilter]          = useState("ALL");
  const [simulating, setSimulating]     = useState(false);
  const [connStatus, setConnStatus]     = useState("live");
  const feedRef = useRef(null);

  const threatCounts = incidents.reduce((acc,inc)=>{
    if (!inc.is_false_positive) acc[inc.threat_type] = (acc[inc.threat_type]||0)+1;
    return acc;
  }, {});

  // Live feed simulation
  useEffect(()=>{
    const tick = setInterval(()=>{
      const newOnes = Array(rnd(1,4)).fill(0).map(()=>mockIncident());
      setIncidents(prev=>[...newOnes, ...prev].slice(0,200));
      setStats(prev=>({
        ...prev,
        eps:  rnd(480,540),
        open: incidents.filter(i=>i.status==="open").length,
        fp:   prev.fp + (Math.random()<0.15 ? 1 : 0),
        conf: rnd(86,93),
      }));
      setRateHistory(prev=>[...prev.slice(1), rnd(2,12)]);
    }, 1200);
    return ()=>clearInterval(tick);
  }, [incidents.length]);

  // Pipeline phase animation
  useEffect(()=>{
    const cycle = setInterval(()=>{
      setPipeline(p=> p>=3 ? 1 : p+1);
    }, 2000);
    return ()=>clearInterval(cycle);
  }, []);

  const filtered = filter==="ALL"
    ? incidents
    : incidents.filter(i=>i.severity===filter);

  const openCount  = incidents.filter(i=>i.status==="open").length;
  const fpCount    = incidents.filter(i=>i.is_false_positive).length;
  const corrCount  = incidents.filter(i=>i.is_correlated).length;

  function runSimulation(scenario){
    setSimulating(true);
    const attack = { "c2":["C2 Beaconing","CRITICAL"], "brute":["Brute Force","HIGH"],
                     "exfil":["Data Exfiltration","HIGH"], "lateral":["Lateral Movement","MEDIUM"] }[scenario];
    const burst = Array(rnd(8,15)).fill(0).map(()=>mockIncident({ threat_type:attack[0], severity:attack[1] }));
    setTimeout(()=>{
      setIncidents(prev=>[...burst,...prev].slice(0,200));
      setSimulating(false);
    }, 1500);
  }

  const selInc = incidents.find(i=>i.id===selected);

  return (
    <div style={{
      minHeight:"100vh", background:"#0a0a0f", color:"#e0e0e0",
      fontFamily:"'Inter',system-ui,sans-serif", fontSize:13,
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap');
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar { width:4px; height:4px; }
        ::-webkit-scrollbar-track { background:transparent; }
        ::-webkit-scrollbar-thumb { background:#333; border-radius:2px; }
        @keyframes pulse-dot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(1.3)} }
        @keyframes progress-bar { 0%{transform:translateX(-100%)} 100%{transform:translateX(100%)} }
        @keyframes slide-in { from{opacity:0;transform:translateY(-8px)} to{opacity:1;transform:translateY(0)} }
      `}</style>

      {/* Header */}
      <div style={{
        padding:"14px 24px", borderBottom:"1px solid rgba(255,255,255,0.07)",
        display:"flex", alignItems:"center", justifyContent:"space-between",
        background:"rgba(0,0,0,0.4)", backdropFilter:"blur(12px)",
        position:"sticky", top:0, zIndex:100,
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <Shield size={20} color="#6366f1"/>
          <span style={{ fontWeight:700, fontSize:15, letterSpacing:"-0.02em" }}>
            AI Threat Detection Engine
          </span>
          <span style={{
            fontSize:10, padding:"2px 8px", borderRadius:3,
            background:"rgba(99,102,241,0.2)", color:"#a5b4fc", border:"1px solid rgba(99,102,241,0.3)",
          }}>HACK MALENADU '26</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
            <Radio size={12} color="#30d158"/>
            <span style={{ fontSize:11, color:"#30d158", fontFamily:"monospace" }}>LIVE</span>
            <span style={{ fontSize:11, color:"rgba(255,255,255,0.3)" }}>{stats.eps} ev/s</span>
          </div>
          <div style={{ display:"flex", gap:6 }}>
            {["c2","brute","exfil","lateral"].map(s=>(
              <button key={s} onClick={()=>runSimulation(s)} disabled={simulating} style={{
                fontSize:10, padding:"4px 10px", borderRadius:4, cursor:"pointer",
                background:simulating?"rgba(255,255,255,0.05)":"rgba(255,45,85,0.15)",
                color:simulating?"rgba(255,255,255,0.3)":"#ff6b8a",
                border:"1px solid rgba(255,45,85,0.2)", fontWeight:600,
                transition:"all 0.15s",
              }}>
                {simulating?"…":s.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ padding:"20px 24px 0", display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12 }}>
        <StatCard label="Events/Sec"     value={stats.eps}        sub="target: 500+"          accent="#6366f1" pulse/>
        <StatCard label="Open Incidents" value={openCount}        sub="+ active"              accent="#ff2d55" pulse/>
        <StatCard label="Mean Detect"    value={stats.detectTime} sub="goal: <1 min"           accent="#30d158"/>
        <StatCard label="FP Suppressed"  value={fpCount}          sub="by XGBoost+SHAP"        accent="#ff9f0a"/>
        <StatCard label="Avg Confidence" value={`${stats.conf}%`} sub="SHAP-verified"          accent="#a5b4fc"/>
      </div>

      {/* Main layout */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 340px", gap:16, padding:"16px 24px 24px" }}>

        {/* Left column */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>

          {/* Event feed */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:12 }}>
            <div style={{ padding:"12px 16px", borderBottom:"1px solid rgba(255,255,255,0.06)", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
              <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                <Terminal size={14} color="#6366f1"/>
                <span style={{ fontWeight:600, fontSize:13 }}>Real-Time Event Feed</span>
              </div>
              <div style={{ display:"flex", gap:6 }}>
                {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(f=>(
                  <button key={f} onClick={()=>setFilter(f)} style={{
                    fontSize:10, padding:"3px 8px", borderRadius:3, cursor:"pointer",
                    background: filter===f ? sevColor(f).bg||"rgba(99,102,241,0.3)" : "rgba(255,255,255,0.05)",
                    color: filter===f ? (sevColor(f).text||"#fff") : "rgba(255,255,255,0.4)",
                    border:"none", fontWeight:600,
                  }}>{f}</button>
                ))}
              </div>
            </div>

            {/* Column headers */}
            <div style={{
              display:"grid", gridTemplateColumns:"80px 1fr 110px 80px 100px 28px",
              gap:8, padding:"8px 16px", borderBottom:"1px solid rgba(255,255,255,0.05)",
            }}>
              {["TIME","THREAT / SOURCE","SEVERITY","CONF","LAYER","FP"].map(h=>(
                <span key={h} style={{ fontSize:10, color:"rgba(255,255,255,0.3)", letterSpacing:"0.08em", textTransform:"uppercase" }}>{h}</span>
              ))}
            </div>

            <div ref={feedRef} style={{ maxHeight:320, overflowY:"auto" }}>
              {filtered.slice(0,80).map(inc=>(
                <div key={inc.id} style={{ animation:"slide-in 0.3s ease" }}>
                  <IncidentRow inc={inc} selected={selected===inc.id} onClick={()=>{ setSelected(inc.id); setActiveTab("explanation"); }}/>
                </div>
              ))}
            </div>
          </div>

          {/* Incident detail panel */}
          {selInc && (
            <div style={{
              background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.08)",
              borderRadius:12, padding:0, overflow:"hidden",
              animation:"slide-in 0.25s ease",
            }}>
              {/* Detail header */}
              <div style={{
                padding:"12px 16px", borderBottom:"1px solid rgba(255,255,255,0.07)",
                display:"flex", alignItems:"center", justifyContent:"space-between",
                background:"rgba(0,0,0,0.2)",
              }}>
                <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                  <span style={{ fontSize:18 }}>{THREAT_ICON[selInc.threat_type]}</span>
                  <div>
                    <div style={{ fontWeight:700, fontSize:14 }}>{selInc.threat_type}</div>
                    <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", fontFamily:"monospace" }}>
                      {selInc.id} · {selInc.src_ip} → {selInc.dst_ip}:{selInc.dst_port}
                    </div>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <SeverityBadge sev={selInc.severity}/>
                  {selInc.is_false_positive && (
                    <span style={{ fontSize:10, padding:"2px 8px", borderRadius:3,
                      background:"rgba(48,209,88,0.15)", color:"#30d158", border:"1px solid rgba(48,209,88,0.3)" }}>
                      FALSE POSITIVE
                    </span>
                  )}
                  {selInc.is_correlated && (
                    <span style={{ fontSize:10, padding:"2px 8px", borderRadius:3,
                      background:"rgba(255,45,85,0.15)", color:"#ff6b8a", border:"1px solid rgba(255,45,85,0.3)" }}>
                      CORRELATED
                    </span>
                  )}
                  <button onClick={()=>setSelected(null)} style={{
                    background:"none", border:"none", cursor:"pointer", color:"rgba(255,255,255,0.4)",
                    display:"flex", alignItems:"center",
                  }}><X size={16}/></button>
                </div>
              </div>

              {/* Tabs */}
              <div style={{ display:"flex", borderBottom:"1px solid rgba(255,255,255,0.07)" }}>
                {[["explanation","🔍 Explanation"],["playbook","📋 Playbook"],["timeline","⏱ Timeline"]].map(([k,label])=>(
                  <button key={k} onClick={()=>setActiveTab(k)} style={{
                    padding:"10px 18px", background:"none", border:"none", cursor:"pointer",
                    borderBottom: activeTab===k ? "2px solid #6366f1" : "2px solid transparent",
                    color: activeTab===k ? "#a5b4fc" : "rgba(255,255,255,0.4)",
                    fontSize:12, fontWeight:600, transition:"all 0.15s",
                  }}>{label}</button>
                ))}
              </div>

              <div style={{ padding:16 }}>
                {activeTab==="explanation" && (
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
                    <div>
                      <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:10 }}>
                        SHAP — Why was this flagged?
                      </div>
                      <SHAPChart values={selInc.explanation?.shap_values}/>
                      <div style={{ marginTop:12, padding:"8px 10px", borderRadius:6, background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                        <span style={{ fontSize:11, color:"#a5b4fc" }}>
                          XGBoost confidence: {(selInc.confidence*100).toFixed(0)}% · SHAP-verified ·{" "}
                          False Positive Risk: {selInc.explanation?.false_positive_risk}
                        </span>
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:10 }}>
                        Plain-English Analysis
                      </div>
                      <div style={{ fontSize:12, color:"rgba(255,255,255,0.75)", lineHeight:1.7, marginBottom:14 }}>
                        {selInc.explanation?.plain_english}
                      </div>
                      {selInc.fp_reason && (
                        <div style={{ padding:"10px 12px", borderRadius:6, background:"rgba(48,209,88,0.08)", border:"1px solid rgba(48,209,88,0.2)" }}>
                          <div style={{ fontSize:10, color:"#30d158", fontWeight:700, marginBottom:4, textTransform:"uppercase", letterSpacing:"0.06em" }}>
                            ✓ FALSE POSITIVE DETECTED
                          </div>
                          <div style={{ fontSize:11, color:"rgba(48,209,88,0.8)" }}>{selInc.fp_reason}</div>
                        </div>
                      )}
                      {selInc.mitre && (
                        <div style={{ marginTop:10, display:"flex", gap:6 }}>
                          <span style={{ fontSize:10, padding:"3px 8px", borderRadius:3, background:"rgba(99,102,241,0.2)", color:"#a5b4fc", border:"1px solid rgba(99,102,241,0.3)", fontFamily:"monospace" }}>
                            {selInc.mitre.technique}
                          </span>
                          <span style={{ fontSize:10, padding:"3px 8px", borderRadius:3, background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.5)" }}>
                            {selInc.mitre.tactic}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {activeTab==="playbook" && (
                  <PlaybookPanel pb={selInc.playbook_steps}/>
                )}

                {activeTab==="timeline" && (
                  <div>
                    <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", marginBottom:10 }}>
                      Cross-layer correlation: {selInc.correlated_layers?.join(", ") || selInc.source_layer}
                    </div>
                    {[selInc].concat(incidents.filter(i=>i.src_ip===selInc.src_ip && i.id!==selInc.id).slice(0,5)).map((inc,i)=>(
                      <div key={i} style={{ display:"flex", gap:10, alignItems:"flex-start", marginBottom:10 }}>
                        <div style={{ display:"flex", flexDirection:"column", alignItems:"center" }}>
                          <div style={{ width:10, height:10, borderRadius:"50%", background:sevColor(inc.severity).bg, flexShrink:0 }}/>
                          {i<5 && <div style={{ width:2, height:24, background:"rgba(255,255,255,0.1)", marginTop:2 }}/>}
                        </div>
                        <div>
                          <div style={{ fontSize:12, color:"#e0e0e0" }}>{inc.threat_type} <span style={{ color:"rgba(255,255,255,0.3)" }}>·</span> <span style={{ color:"rgba(255,255,255,0.4)", fontFamily:"monospace", fontSize:11 }}>{new Date(inc.timestamp).toLocaleTimeString()}</span></div>
                          <div style={{ fontSize:11, color:"rgba(255,255,255,0.35)" }}>{inc.source_layer} · {inc.src_ip}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right column */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>

          {/* Threat distribution */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:12, padding:16 }}>
            <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:14 }}>
              Threat Distribution
            </div>
            <ThreatDonut counts={threatCounts}/>
          </div>

          {/* Detection pipeline */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:12, padding:16 }}>
            <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:12, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
              <span>Hybrid Detection Pipeline</span>
              <span style={{ color:"#6366f1", fontSize:10 }}>3-PHASE</span>
            </div>
            <PipelineIndicator phase={pipelinePhase}/>
          </div>

          {/* 1-10-60 tracker */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:12, padding:16 }}>
            <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:12 }}>
              1 · 10 · 60 Rule Tracker
            </div>
            {[
              { label:"DETECT",     target:"<1 min",  current:"0:47", met:true  },
              { label:"INVESTIGATE",target:"<10 min", current:"8:43", met:true  },
              { label:"REMEDIATE",  target:"<60 min", current:"41:12",met:false },
            ].map(r=>(
              <div key={r.label} style={{ marginBottom:10 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                  <span style={{ fontSize:10, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.06em" }}>{r.label} SLA</span>
                  <span style={{ fontSize:10, color: r.met?"#30d158":"#ff9f0a", fontFamily:"monospace", fontWeight:700 }}>
                    {r.met ? "✓ MET" : "⚠ 84%"}
                  </span>
                </div>
                <div style={{ display:"flex", gap:10, alignItems:"center" }}>
                  <span style={{ fontSize:18, fontFamily:"monospace", fontWeight:700, color:"#fff", minWidth:60 }}>{r.current}</span>
                  <div style={{ flex:1, height:4, borderRadius:2, background:"rgba(255,255,255,0.08)" }}>
                    <div style={{ height:"100%", borderRadius:2, width: r.met?"100%":"84%", background: r.met?"#30d158":"#ff9f0a", transition:"width 1s" }}/>
                  </div>
                  <span style={{ fontSize:10, color:"rgba(255,255,255,0.3)" }}>{r.target}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Event rate sparkline */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:12, padding:16 }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
              <span style={{ fontSize:11, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.08em" }}>Incident Rate</span>
              <span style={{ fontSize:11, fontFamily:"monospace", color:"#6366f1" }}>{rateHistory[rateHistory.length-1]} /s</span>
            </div>
            <Sparkline data={rateHistory} color="#6366f1"/>
          </div>

          {/* Correlation summary */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:12, padding:16 }}>
            <div style={{ fontSize:11, color:"rgba(255,255,255,0.4)", textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:12 }}>
              Cross-Layer Correlation
            </div>
            {[
              { label:"Multi-layer incidents", value: corrCount, color:"#ff2d55" },
              { label:"False positives filtered", value: fpCount, color:"#30d158" },
              { label:"Total analyzed",          value: incidents.length, color:"#6366f1" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                <span style={{ fontSize:12, color:"rgba(255,255,255,0.55)" }}>{r.label}</span>
                <span style={{ fontSize:15, fontWeight:700, fontFamily:"monospace", color:r.color }}>{r.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
