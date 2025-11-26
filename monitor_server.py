#!/usr/bin/env python3
"""
monitor_server.py
Policy-centric local dashboard + metrics receiver for malcolmai_daemon.

- Accepts HTTP POSTs from the daemon (redirected via hosts)
- Stores metrics in metrics_log.jsonl
- Reads:
    - malcolmai_daemon.log
    - policy.json
- Focuses on POLICY + IMPACT indicators:
    - Scope: universal / global / local
    - Domain categories: security, technology, governmental, infrastructure,
      economic, social, environmental, disasters
    - Reach, engagement, outcomes, and scores
- Serves a live dashboard at http://127.0.0.1:80/
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import time
from pathlib import Path
from urllib.parse import urlparse
import traceback

# ===== Configuration =====
PORT = 80  # must be 80 to receive daemon HTTP metrics (requires admin)
BASE_DIR = Path(__file__).resolve().parent

LOG_FILE = BASE_DIR / "malcolmai_daemon.log"
METRICS_LOG = BASE_DIR / "metrics_log.jsonl"
POLICY_FILE = BASE_DIR / "policy.json"

# ===== Policy mapping (scope + domains) =====
SCOPES = ["universal", "global", "local"]
DOMAINS = [
    "security",
    "technology",
    "governmental",
    "infrastructure",
    "economic",
    "social",
    "environmental",
    "disasters",
]

# Known policy flags mapped into scope + domains
POLICY_FLAG_META = {
    "monitoring_only": {
        "scope": "universal",
        "domains": ["security", "infrastructure"],
    },
    "enable_aggressive_tuning": {
        "scope": "global",
        "domains": ["technology", "infrastructure"],
    },
    "allow_kill_suspicious": {
        "scope": "local",
        "domains": ["security", "governmental"],
    },
    "allow_firewall_tighten": {
        "scope": "global",
        "domains": ["security", "infrastructure"],
    },
    "allow_nic_bounce": {
        "scope": "local",
        "domains": ["infrastructure", "technology"],
    },
    "allow_ab_update": {
        "scope": "universal",
        "domains": ["technology", "infrastructure", "economic"],
    },
    "allow_tpm_attest": {
        "scope": "universal",
        "domains": ["security", "governmental"],
    },
    "allow_ebpf": {
        "scope": "global",
        "domains": ["technology", "security"],
    },
    "allow_firmware_orchestrator": {
        "scope": "global",
        "domains": ["technology", "infrastructure"],
    },
    # Some plausible extras if present in policy.json:
    "allow_dns_prime": {
        "scope": "global",
        "domains": ["infrastructure", "technology"],
    },
    "allow_backup": {
        "scope": "local",
        "domains": ["infrastructure", "economic"],
    },
    "allow_system_hardening": {
        "scope": "universal",
        "domains": ["security", "governmental"],
    },
    "allow_incident_response": {
        "scope": "global",
        "domains": ["security", "disasters"],
    },
}

# ===== Simple in-memory cache for metrics =====
metrics_buffer = []  # list of dicts
metrics_lock = threading.Lock()


def append_metrics(entry: dict):
    """Append metrics to memory and to metrics_log.jsonl."""
    with metrics_lock:
        metrics_buffer.append(entry)
        if len(metrics_buffer) > 1000:
            metrics_buffer[:] = metrics_buffer[-1000:]

    try:
        with METRICS_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        traceback.print_exc()


def load_metrics_history():
    """Load metrics history from file into memory on startup."""
    if not METRICS_LOG.exists():
        return
    try:
        with METRICS_LOG.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        data = [json.loads(line) for line in lines[-1000:]]
        with metrics_lock:
            metrics_buffer[:] = data
    except Exception:
        traceback.print_exc()


def tail_log(path: Path, max_lines: int = 200):
    """Return last max_lines lines of log file as list of dicts."""
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        traceback.print_exc()
        return []

    lines = [ln.rstrip("\n\r") for ln in lines[-max_lines:]]
    entries = []
    for ln in lines:
        parts = ln.split(" :: ", 1)
        if len(parts) == 2:
            left, msg = parts
            entries.append({"raw": ln, "prefix": left, "message": msg})
        else:
            entries.append({"raw": ln, "prefix": "", "message": ln})
    return entries


# ===== Policy analysis =====

def load_policy():
    if not POLICY_FILE.exists():
        return None
    try:
        with POLICY_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        traceback.print_exc()
        return None


def categorize_policy_flags(flags: dict):
    """
    Build counts grouped by scope + domain for boolean policy flags.
    returns:
      {
        "by_scope": {scope: {domain: {"total":N, "enabled":M}}},
        "by_domain": {domain: {"total":N, "enabled":M}}
      }
    """
    by_scope = {
        scope: {dom: {"total": 0, "enabled": 0} for dom in DOMAINS}
        for scope in SCOPES
    }
    by_domain = {dom: {"total": 0, "enabled": 0} for dom in DOMAINS}

    for name, value in flags.items():
        if not isinstance(value, bool):
            continue
        meta = POLICY_FLAG_META.get(name, None)
        if meta is None:
            # Unknown flag: treat as local / technology
            meta = {"scope": "local", "domains": ["technology"]}
        scope = meta["scope"] if meta["scope"] in SCOPES else "local"
        domains = [d for d in meta["domains"] if d in DOMAINS] or ["technology"]

        for dom in domains:
            by_scope[scope][dom]["total"] += 1
            by_domain[dom]["total"] += 1
            if value:
                by_scope[scope][dom]["enabled"] += 1
                by_domain[dom]["enabled"] += 1

    return {"by_scope": by_scope, "by_domain": by_domain}


def summarize_policy(policy):
    """Produce a quantitative + structural summary of policy.json."""
    if not policy:
        return None

    flags = {k: v for k, v in policy.items() if isinstance(v, bool)}
    total = len(flags)
    enabled = sum(1 for v in flags.values() if v)
    disabled = total - enabled

    categorised = categorize_policy_flags(flags)
    by_scope = categorised["by_scope"]
    by_domain = categorised["by_domain"]

    monitoring_only = bool(policy.get("monitoring_only", False))

    notable = []
    for key in (
        "monitoring_only",
        "enable_aggressive_tuning",
        "allow_kill_suspicious",
        "allow_firewall_tighten",
        "allow_nic_bounce",
        "allow_ab_update",
        "allow_tpm_attest",
        "allow_ebpf",
        "allow_firmware_orchestrator",
    ):
        if key in flags:
            notable.append({"name": key, "value": flags[key]})

    def pct(on, total_):
        return (100.0 * on / total_) if total_ else None

    domain_activation = {}
    for dom, counts in by_domain.items():
        total_d = counts["total"]
        on_d = counts["enabled"]
        domain_activation[dom] = {
            "total": total_d,
            "enabled": on_d,
            "activation_pct": pct(on_d, total_d),
        }

    scope_domain_activation = {}
    for scope, doms in by_scope.items():
        scope_domain_activation[scope] = {}
        for dom, counts in doms.items():
            total_d = counts["total"]
            on_d = counts["enabled"]
            scope_domain_activation[scope][dom] = {
                "total": total_d,
                "enabled": on_d,
                "activation_pct": pct(on_d, total_d),
            }

    domain_pcts = [v["activation_pct"] for v in domain_activation.values() if v["activation_pct"] is not None]
    overall = sum(domain_pcts) / len(domain_pcts) if domain_pcts else None
    if overall is not None and monitoring_only:
        overall *= 0.5

    return {
        "total_flags": total,
        "enabled_flags": enabled,
        "disabled_flags": disabled,
        "monitoring_only": monitoring_only,
        "domain_activation": domain_activation,
        "scope_domain_activation": scope_domain_activation,
        "overall_activation_index": overall,
        "notable_flags": notable,
    }


# ===== Log-based indicators =====

def compute_log_indicators(log_entries):
    """Parse recent log lines into category-aligned stats."""
    if not log_entries:
        return None

    total = len(log_entries)
    info = warn = err = 0
    domain_events = {dom: 0 for dom in DOMAINS}

    for e in log_entries:
        raw = e.get("raw", "")
        msg = e.get("message", "")
        text = raw + " " + msg

        if "INFO" in raw:
            info += 1
        if "WARN" in raw:
            warn += 1
        if "ERROR" in raw or "ERR" in raw:
            err += 1

        # Security: SEC, FIM, FIREWALL, TPM, AB, suspicious, kill
        if any(tok in text for tok in ["SEC:", "FIM:", "FIREWALL", "TPM:", "AB:", "suspicious", "kill "]):
            domain_events["security"] += 1

        # Technology: NET:, HTTP:, EBPF, NIC, optimization, tuning
        if any(tok in text for tok in ["NET:", "HTTP:", "EBPF", "NIC", "optimize", "tune"]):
            domain_events["technology"] += 1

        # Governmental: "policy", "attest", "compliance"
        if any(tok.lower() in text.lower() for tok in ["policy:", "attest", "compliance"]):
            domain_events["governmental"] += 1

        # Infrastructure: "dns", "route", "interface", "FW: detected vendor"
        if any(tok.lower() in text.lower() for tok in ["dns", "route", "interface", "fw: detected vendor"]):
            domain_events["infrastructure"] += 1

        # Economic: "cost", "license", "quota"
        if any(tok.lower() in text.lower() for tok in ["cost", "license", "quota"]):
            domain_events["economic"] += 1

        # Social: "user", "session", "login"
        if any(tok.lower() in text.lower() for tok in ["user", "session", "login"]):
            domain_events["social"] += 1

        # Environmental: "thermal", "power", "energy"
        if any(tok.lower() in text.lower() for tok in ["thermal", "power", "energy"]):
            domain_events["environmental"] += 1

        # Disasters: "incident", "breach", "attack", "ransomware", "outage"
        if any(tok.lower() in text.lower() for tok in ["incident", "breach", "attack", "ransomware", "outage"]):
            domain_events["disasters"] += 1

    defence_events = (
        domain_events["security"]
        + domain_events["disasters"]
        + domain_events["governmental"]
    )
    defence_score = min(100.0, defence_events * 5.0)
    stability_score = max(0.0, 100.0 - min(50.0, err * 10.0))

    return {
        "log_total_lines": total,
        "log_info": info,
        "log_warn": warn,
        "log_error": err,
        "domain_events": domain_events,
        "defence_activity_score": defence_score,
        "stability_score": stability_score,
    }


# ===== Metrics-based stats (reach, modes, etc) =====

def compute_metrics_stats(metrics):
    """Compute reach/engagement stats from metrics_buffer."""
    if not metrics:
        return None

    ts_values = [m.get("ts") for m in metrics if isinstance(m.get("ts"), (int, float))]
    t_min = min(ts_values) if ts_values else None
    t_max = max(ts_values) if ts_values else None
    window_sec = (t_max - t_min) if (t_min is not None and t_max is not None) else None

    hosts = {}
    monitoring_true = monitoring_total = 0
    aggressive_true = aggressive_total = 0
    ebpf_true = ebpf_total = 0

    for m in metrics:
        host = m.get("host") or "unknown"
        ts = m.get("ts")
        if host not in hosts:
            hosts[host] = {
                "count": 0,
                "first_ts": ts,
                "last_ts": ts,
            }
        hosts[host]["count"] += 1
        if ts is not None:
            if hosts[host]["first_ts"] is None or ts < hosts[host]["first_ts"]:
                hosts[host]["first_ts"] = ts
            if hosts[host]["last_ts"] is None or ts > hosts[host]["last_ts"]:
                hosts[host]["last_ts"] = ts

        flags = m.get("flags") or {}
        if "monitoring_only" in flags:
            monitoring_total += 1
            if flags["monitoring_only"]:
                monitoring_true += 1
        if "aggressive" in flags:
            aggressive_total += 1
            if flags["aggressive"]:
                aggressive_true += 1
        if "ebpf" in flags:
            ebpf_total += 1
            if flags["ebpf"]:
                ebpf_true += 1

    def pct(n, d):
        return (100.0 * n / d) if d else None

    return {
        "metrics_count": len(metrics),
        "window_seconds": window_sec,
        "host_stats": hosts,
        "distinct_hosts": len(hosts),
        "monitoring_true_pct": pct(monitoring_true, monitoring_total),
        "aggressive_true_pct": pct(aggressive_true, aggressive_total),
        "ebpf_true_pct": pct(ebpf_true, ebpf_total),
    }


# ===== Metrics-based policy timeline & outcomes =====

def build_policy_timeline(metrics, policy_summary):
    """
    Create a time series of policy-performance scores per domain.

    Base score per domain comes from domain_activation (0-100).
    Per-metric modifiers:
      - monitoring_only flag: scales scores down (watch-only mode)
      - aggressive flag: scales security/technology/infrastructure up
      - ebpf flag: scales security/technology slightly up
    """
    if not metrics or not policy_summary:
        return []

    base = {}
    domain_activation = policy_summary.get("domain_activation", {})
    for dom in DOMAINS:
        dom_info = domain_activation.get(dom, {})
        base[dom] = dom_info.get("activation_pct") or 0.0

    timeline = []
    for m in metrics:
        ts = m.get("ts")
        if ts is None:
            continue
        flags = m.get("flags") or {}
        factor = 1.0
        if flags.get("monitoring_only"):
            factor *= 0.5
        if flags.get("aggressive"):
            factor *= 1.1
        if flags.get("ebpf"):
            factor *= 1.05

        scores = {}
        for dom in DOMAINS:
            v = base.get(dom, 0.0) * factor
            if dom in ("economic", "social", "environmental"):
                v = (base.get("infrastructure", 0.0) + base.get("security", 0.0)) * factor / 2.0
            scores[dom] = min(100.0, v)

        timeline.append({"t": ts, "scores": scores})

    return timeline


def compute_domain_outcomes(policy_summary, log_stats):
    """
    Per-domain outcome index (0-100) combining policy activation and observed activity.

    Highly heuristic but consistent:
      outcome_index = min(100, activation_pct * (1 + domain_events / 10))
    """
    if not policy_summary:
        return {}

    domain_activation = policy_summary.get("domain_activation", {}) or {}
    domain_events = (log_stats or {}).get("domain_events", {}) if log_stats else {}
    outcomes = {}

    for dom in DOMAINS:
        act = domain_activation.get(dom, {})
        act_pct = act.get("activation_pct") or 0.0
        events = domain_events.get(dom, 0)
        factor = 1.0 + min(2.0, events / 10.0)  # up to x3 boost from lots of activity
        outcome = min(100.0, act_pct * factor)
        outcomes[dom] = {
            "activation_pct": act_pct,
            "events": events,
            "outcome_index": outcome,
        }

    return outcomes


def compute_indicators(metrics, log_entries, policy_summary):
    """
    Combine policy + logs + metrics into a richer indicator set.
    """
    metrics_stats = compute_metrics_stats(metrics)
    log_stats = compute_log_indicators(log_entries)
    domain_outcomes = compute_domain_outcomes(policy_summary, log_stats)

    policy_index = policy_summary.get("overall_activation_index") if policy_summary else None

    scores = []
    if policy_index is not None:
        scores.append(policy_index)
    if log_stats:
        scores.append(log_stats["defence_activity_score"])
        scores.append(log_stats["stability_score"])
    overall_success = sum(scores) / len(scores) if scores else None

    return {
        "metrics_stats": metrics_stats,
        "log_stats": log_stats,
        "domain_outcomes": domain_outcomes,
        "overall_success_index": overall_success,
    }


# ===== HTML/JS dashboard =====

DASHBOARD_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Malcolm AI Daemon – Policy & Impact Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #111; color: #eee; }
    header { background: #222; padding: 10px 20px; }
    h1 { margin: 0; font-size: 20px; }
    main { padding: 20px; display: flex; flex-direction: column; gap: 20px; }
    section { background: #1b1b1b; padding: 15px; border-radius: 8px; }
    h2 { margin-top: 0; font-size: 18px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #333; padding: 4px 6px; vertical-align: top; }
    th { text-align: left; background: #222; }
    code { font-family: Consolas, monospace; font-size: 11px; }
    ul { margin: 0; padding-left: 18px; }
    #timeline-container { height: 260px; }
    #timeline-chart { width: 100%; height: 240px; background: #111; border: 1px solid #333; border-radius: 4px; }
    #domain-container { height: 260px; margin-top: 10px; }
    #domain-chart { width: 100%; height: 240px; background: #111; border: 1px solid #333; border-radius: 4px; }
    .hint { font-size: 11px; color: #aaa; }
  </style>
</head>
<body>
  <header>
    <h1>Malcolm AI Daemon – Policy, Reach & Outcomes</h1>
  </header>
  <main>
    <section>
      <h2>System Reach & Engagement</h2>
      <div id="reach-summary">Loading...</div>
    </section>

    <section>
      <h2>Policy Structure & Activation (Universal / Global / Local)</h2>
      <div id="policy-overview">Loading...</div>
    </section>

    <section>
      <h2>Key Policy Outcome & Impact Summary</h2>
      <div id="impact-summary">Loading...</div>
    </section>

    <section>
      <h2>Category Scores & Outcomes</h2>
      <div id="category-summary">Loading...</div>
      <div id="domain-container">
        <canvas id="domain-chart"></canvas>
      </div>
      <div class="hint">
        Bars show per-category outcome index (0–100), combining activation strength with how often that domain appears in recent activity.
      </div>
    </section>

    <section>
      <h2>Policy Performance Timeline (by Category)</h2>
      <div id="timeline-container">
        <canvas id="timeline-chart"></canvas>
      </div>
      <div class="hint">
        Each line shows how strongly a policy category is "activated" in practice over time, blending static policy switches and the daemon's current operating mode (monitoring-only, aggressive, eBPF).
      </div>
    </section>

    <section>
      <h2>Recent Log Snapshot</h2>
      <div id="log-indicators"></div>
      <table id="log-table">
        <thead>
          <tr>
            <th>Prefix</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </section>

    <section>
      <h2>Raw Metrics (from HTTP posts)</h2>
      <div id="metrics-empty" style="display:none; font-size:12px; color:#aaa;">
        No metrics received yet. Make sure:
        <ul>
          <li><code>hosts</code> maps <code>malcolmai.live</code> to <code>127.0.0.1</code></li>
          <li>This dashboard is running on port 80 (admin needed)</li>
        </ul>
      </div>
      <table id="metrics-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Host</th>
            <th>OS</th>
            <th>monitoring_only</th>
            <th>aggressive</th>
            <th>ebpf</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </section>
  </main>

  <script>
    const DOMAINS = ["security","technology","governmental","infrastructure","economic","social","environmental","disasters"];
    let timelineSeries = {}; // domain -> [{t,v}]
    let domainOutcomeSeries = {}; // domain -> value

    async function fetchData() {
      try {
        const res = await fetch('/data');
        const data = await res.json();
        renderReachSummary(data.indicators && data.indicators.metrics_stats);
        renderPolicyOverview(data.policy_summary);
        renderImpactSummary(data.policy_summary, data.indicators);
        renderCategorySummary(data.indicators && data.indicators.domain_outcomes);
        renderLogIndicators(data.indicators && data.indicators.log_stats);
        renderLog(data.log_tail);
        updateTimeline(data.policy_timeline);
        updateDomainOutcomes(data.indicators && data.indicators.domain_outcomes);
        drawTimelineChart();
        drawDomainChart();
        renderMetrics(data.metrics);
      } catch (e) {
        console.error('Error fetching data', e);
      }
    }

    function escapeHTML(str) {
      return String(str).replace(/[&<>"]/g, c => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;'
      }[c]));
    }

    function formatDuration(sec) {
      if (sec == null || isNaN(sec)) return "unknown";
      const s = Math.floor(sec);
      const m = Math.floor(s / 60);
      const h = Math.floor(m / 60);
      const d = Math.floor(h / 24);
      if (d > 0) return `${d}d ${h % 24}h`;
      if (h > 0) return `${h}h ${m % 60}m`;
      if (m > 0) return `${m}m ${s % 60}s`;
      return `${s}s`;
    }

    function renderReachSummary(stats) {
      const el = document.getElementById('reach-summary');
      if (!stats) {
        el.textContent = "No metrics observed yet. Once the daemon posts data, reach and engagement will be summarised here.";
        return;
      }
      const lines = [];
      lines.push(`Total metrics samples: ${stats.metrics_count}.`);
      lines.push(`Observed time window: approximately ${formatDuration(stats.window_seconds)}.`);
      lines.push(`Distinct hosts reporting: ${stats.distinct_hosts}.`);

      const hosts = stats.host_stats || {};
      const hostLines = [];
      Object.keys(hosts).forEach(h => {
        const hs = hosts[h];
        hostLines.push(`${h}: ${hs.count} samples.`);
      });
      if (hostLines.length) {
        lines.push("Per-host activity:");
        hostLines.forEach(x => lines.push("• " + x));
      }

      function pctStr(v) {
        return v == null ? "n/a" : v.toFixed(1) + "%";
      }
      lines.push(
        "Mode residency over this window: " +
        `monitoring-only=${pctStr(stats.monitoring_true_pct)}, ` +
        `aggressive=${pctStr(stats.aggressive_true_pct)}, ` +
        `eBPF-allowed=${pctStr(stats.ebpf_true_pct)}.`
      );

      el.innerHTML = "<ul>" + lines.map(x => "<li>" + escapeHTML(x) + "</li>").join("") + "</ul>";
    }

    function renderPolicyOverview(summary) {
      const el = document.getElementById('policy-overview');
      if (!summary) {
        el.textContent = 'No policy.json found or it could not be read.';
        return;
      }

      const lines = [];
      lines.push(`Total policy switches: ${summary.enabled_flags} enabled out of ${summary.total_flags}. Disabled: ${summary.disabled_flags}.`);

      const scopeDom = summary.scope_domain_activation || {};
      for (const scope of ["universal","global","local"]) {
        const doms = scopeDom[scope] || {};
        const domLines = [];
        for (const dom of DOMAINS) {
          const d = doms[dom] || {};
          if (d.total) {
            const pct = d.activation_pct != null ? d.activation_pct.toFixed(1) : "n/a";
            domLines.push(`${dom}: ${d.enabled}/${d.total} switches on (${pct}%)`);
          }
        }
        if (domLines.length) {
          lines.push(`<strong>${scope.toUpperCase()} scope:</strong>`);
          domLines.forEach(x => lines.push("• " + x));
        }
      }

      if (summary.overall_activation_index != null) {
        lines.push(`Overall activation index (averaged across all domains) is ${summary.overall_activation_index.toFixed(1)}/100.`);
      }
      if (summary.monitoring_only) {
        lines.push(`Mode: monitoring-only – the daemon observes rather than intervenes, so the practical impact of policies is intentionally reduced.`);
      } else {
        lines.push(`Mode: active – the daemon is allowed to act in line with the enabled policies (within this machine's scope).`);
      }

      el.innerHTML = "<ul>" + lines.map(x => "<li>" + x + "</li>").join("") + "</ul>";
    }

    function renderImpactSummary(summary, indicators) {
      const el = document.getElementById('impact-summary');
      if (!summary) {
        el.textContent = "No policy data available yet.";
        return;
      }
      const domainAct = summary.domain_activation || {};
      const domainOutcomes = indicators && indicators.domain_outcomes || {};
      const lines = [];

      function impactPhrase(dom, pct) {
        if (pct == null) return "no clear signals yet.";
        if (pct > 80) return "very strong emphasis and coverage in this area.";
        if (pct > 60) return "strong coverage with most tools enabled.";
        if (pct > 40) return "moderate coverage with room to expand.";
        if (pct > 20) return "light coverage; only a subset of tools are active.";
        if (pct > 0)  return "minimal coverage; only one or two levers are enabled.";
        return "currently disabled in policy.";
      }

      for (const dom of DOMAINS) {
        const d = domainAct[dom] || {};
        const pct = d.activation_pct;
        const outcome = (domainOutcomes[dom] && domainOutcomes[dom].outcome_index) || null;
        let human = "";
        if (dom === "security") {
          human = "affects how strongly the system can detect, contain, and disrupt threats for people relying on this machine or connected services.";
        } else if (dom === "technology") {
          human = "covers technical tuning, observability, and advanced features that improve reliability and insight over the software and network stack.";
        } else if (dom === "governmental") {
          human = "relates to governance-like controls: attestation, policy compliance behaviours, and traceable control over critical actions.";
        } else if (dom === "infrastructure") {
          human = "impacts the stability and resilience of core connectivity (network interfaces, DNS, routing, firmware-level coordination).";
        } else if (dom === "economic") {
          human = "touches cost/risk trade-offs via safe updates, backups, and reduced downtime risk, indirectly influencing financial stability.";
        } else if (dom === "social") {
          human = "affects how safely user sessions and interactions are mediated, reducing the chance of harmful behaviour reaching people.";
        } else if (dom === "environmental") {
          human = "captures indirect environmental impact through thermal and power-sensitive behaviours, though this daemon is not primarily green-tech.";
        } else if (dom === "disasters") {
          human = "relates to how well the system can respond when something goes very wrong (incidents, outages, attacks), limiting damage and speeding recovery.";
        }

        const pctStr = pct != null ? pct.toFixed(1) + "% activation" : "no measurable activation";
        const outStr = outcome != null ? `Outcome index: ${outcome.toFixed(1)}/100.` : "";
        lines.push(
          `<strong>${dom.charAt(0).toUpperCase() + dom.slice(1)}:</strong> ${pctStr}. ` +
          `${outStr} ` +
          `In practice, this means the policy set has ${impactPhrase(dom, pct)} ` +
          `For populations who depend on services chained through this machine, higher activation and outcome values generally mean lower risk and better continuity in this category.`
        );
      }

      const overall = indicators && indicators.overall_success_index;
      if (overall != null) {
        lines.push(
          `<strong>Combined success index:</strong> ${overall.toFixed(1)}/100. ` +
          `This blends how fully policies are turned on, how actively security responses appear in recent logs, and how stable the system looks. ` +
          `Higher values suggest a better defended, more reliable environment for the people and systems connected to this node.`
        );
      }

      el.innerHTML = "<ul>" + lines.map(x => "<li>" + x + "</li>").join("") + "</ul>";
    }

    function renderCategorySummary(domainOutcomes) {
      const el = document.getElementById('category-summary');
      if (!domainOutcomes) {
        el.textContent = "No category outcome data yet.";
        return;
      }
      const rows = [];
      DOMAINS.forEach(dom => {
        const d = domainOutcomes[dom] || {};
        const act = d.activation_pct != null ? d.activation_pct.toFixed(1) + "%" : "n/a";
        const events = d.events != null ? d.events : "0";
        const out = d.outcome_index != null ? d.outcome_index.toFixed(1) : "n/a";
        rows.push(`<tr><td>${dom}</td><td>${act}</td><td>${events}</td><td>${out}</td></tr>`);
      });

      el.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Category</th>
              <th>Activation %</th>
              <th>Recent events (logs)</th>
              <th>Outcome index (0–100)</th>
            </tr>
          </thead>
          <tbody>
            ${rows.join("")}
          </tbody>
        </table>
      `;
    }

    function renderLogIndicators(logStats) {
      const el = document.getElementById('log-indicators');
      if (!logStats) {
        el.textContent = "No log data available yet.";
        return;
      }
      const lines = [];
      lines.push(`Recent log window: ${logStats.log_total_lines} entries (INFO: ${logStats.log_info}, WARN: ${logStats.log_warn}, ERROR: ${logStats.log_error}).`);
      const de = logStats.domain_events || {};
      lines.push(
        "Domain-related activity (recent lines): " +
        DOMAINS.map(d => `${d}: ${de[d] || 0}`).join(", ")
      );
      lines.push(`Defence activity score: ${logStats.defence_activity_score.toFixed(1)}/100.`);
      lines.push(`Stability score: ${logStats.stability_score.toFixed(1)}/100.`);

      el.innerHTML = "<ul>" + lines.map(x => "<li>" + x + "</li>").join("") + "</ul>";
    }

    function renderLog(entries) {
      const tbody = document.querySelector('#log-table tbody');
      tbody.innerHTML = '';
      (entries || []).slice().reverse().forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML =
          '<td><code>' + escapeHTML(e.prefix || '') + '</code></td>' +
          '<td><code>' + escapeHTML(e.message || e.raw || '') + '</code></td>';
        tbody.appendChild(tr);
      });
    }

    function updateTimeline(policyTimeline) {
      timelineSeries = {};
      DOMAINS.forEach(dom => { timelineSeries[dom] = []; });
      if (!policyTimeline || !policyTimeline.length) return;

      policyTimeline.forEach(pt => {
        const t = pt.t * 1000; // to ms
        const scores = pt.scores || {};
        DOMAINS.forEach(dom => {
          const v = scores[dom];
          if (v != null) {
            timelineSeries[dom].push({ t, v });
          }
        });
      });
    }

    function updateDomainOutcomes(domainOutcomes) {
      domainOutcomeSeries = {};
      if (!domainOutcomes) return;
      DOMAINS.forEach(dom => {
        const d = domainOutcomes[dom] || {};
        domainOutcomeSeries[dom] = d.outcome_index != null ? d.outcome_index : 0;
      });
    }

    function drawTimelineChart() {
      const canvas = document.getElementById('timeline-chart');
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      if (canvas.width !== rect.width || canvas.height !== rect.height) {
        canvas.width = rect.width;
        canvas.height = rect.height;
      }
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const allPoints = [];
      for (const dom of DOMAINS) {
        (timelineSeries[dom] || []).forEach(p => allPoints.push(p));
      }
      if (!allPoints.length) {
        ctx.fillStyle = '#666';
        ctx.font = '12px Arial';
        ctx.fillText('Waiting for policy activity data...', 10, 20);
        return;
      }

      const minY = 0;
      const maxY = 100;
      const times = allPoints.map(p => p.t);
      const tMin = Math.min.apply(null, times);
      const tMax = Math.max.apply(null, times);
      const tSpan = Math.max(1, tMax - tMin);

      const padLeft = 35;
      const padRight = 80;
      const padTop = 10;
      const padBottom = 20;
      const w = canvas.width;
      const h = canvas.height;

      ctx.strokeStyle = '#333';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padLeft, padTop);
      ctx.lineTo(padLeft, h - padBottom);
      ctx.lineTo(w - padRight, h - padBottom);
      ctx.stroke();

      ctx.fillStyle = '#666';
      ctx.font = '10px Arial';
      ctx.fillText(maxY.toFixed(0), 2, padTop + 5);
      ctx.fillText(minY.toFixed(0), 2, h - padBottom);

      function yFor(v) {
        const frac = (v - minY) / (maxY - minY || 1);
        return h - padBottom - frac * (h - padTop - padBottom);
      }
      function xFor(t) {
        const frac = (t - tMin) / tSpan;
        return padLeft + frac * (w - padLeft - padRight);
      }

      const colors = {
        security: '#ff5252',
        technology: '#4caf50',
        governmental: '#ffb300',
        infrastructure: '#2196f3',
        economic: '#9c27b0',
        social: '#00bcd4',
        environmental: '#8bc34a',
        disasters: '#e91e63',
      };

      let legendY = padTop + 10;
      for (const dom of DOMAINS) {
        const series = timelineSeries[dom] || [];
        if (!series.length) continue;
        ctx.strokeStyle = colors[dom] || '#fff';
        ctx.beginPath();
        series.forEach((p, idx) => {
          const x = xFor(p.t);
          const y = yFor(p.v);
          if (idx === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.stroke();

        ctx.fillStyle = colors[dom] || '#fff';
        ctx.fillRect(w - padRight + 5, legendY - 7, 8, 8);
        ctx.fillStyle = '#ccc';
        ctx.fillText(dom, w - padRight + 20, legendY);
        legendY += 12;
      }
    }

    function drawDomainChart() {
      const canvas = document.getElementById('domain-chart');
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      if (canvas.width !== rect.width || canvas.height !== rect.height) {
        canvas.width = rect.width;
        canvas.height = rect.height;
      }
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const values = DOMAINS.map(dom => domainOutcomeSeries[dom] || 0);
      const maxVal = Math.max(100, ...values);
      const minY = 0;
      const maxY = maxVal;

      const padLeft = 45;
      const padRight = 20;
      const padTop = 10;
      const padBottom = 30;
      const w = canvas.width;
      const h = canvas.height;

      ctx.strokeStyle = '#333';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padLeft, padTop);
      ctx.lineTo(padLeft, h - padBottom);
      ctx.lineTo(w - padRight, h - padBottom);
      ctx.stroke();

      ctx.fillStyle = '#666';
      ctx.font = '10px Arial';
      ctx.fillText(maxY.toFixed(0), 2, padTop + 5);
      ctx.fillText(minY.toFixed(0), 2, h - padBottom);

      const barAreaWidth = w - padLeft - padRight;
      const barWidth = barAreaWidth / (DOMAINS.length * 1.5);

      function yFor(v) {
        const frac = (v - minY) / (maxY - minY || 1);
        return h - padBottom - frac * (h - padTop - padBottom);
      }

      const colors = {
        security: '#ff5252',
        technology: '#4caf50',
        governmental: '#ffb300',
        infrastructure: '#2196f3',
        economic: '#9c27b0',
        social: '#00bcd4',
        environmental: '#8bc34a',
        disasters: '#e91e63',
      };

      DOMAINS.forEach((dom, idx) => {
        const v = domainOutcomeSeries[dom] || 0;
        const xCenter = padLeft + (idx + 0.75) * (barAreaWidth / DOMAINS.length);
        const x = xCenter - barWidth / 2;
        const y = yFor(v);
        const baseY = h - padBottom;

        ctx.fillStyle = colors[dom] || '#fff';
        ctx.fillRect(x, y, barWidth, baseY - y);

        ctx.fillStyle = '#ccc';
        ctx.save();
        ctx.translate(xCenter, h - padBottom + 10);
        ctx.rotate(-Math.PI / 4);
        ctx.fillText(dom, 0, 0);
        ctx.restore();
      });
    }

    function renderMetrics(metrics) {
      const tbody = document.querySelector('#metrics-table tbody');
      const emptyInfo = document.getElementById('metrics-empty');
      tbody.innerHTML = '';

      if (!metrics || metrics.length === 0) {
        emptyInfo.style.display = 'block';
        return;
      } else {
        emptyInfo.style.display = 'none';
      }

      metrics.slice().reverse().forEach(m => {
        const flags = m.flags || {};
        const tr = document.createElement('tr');
        tr.innerHTML =
          '<td><code>' + escapeHTML(m.time || '') + '</code></td>' +
          '<td>' + escapeHTML(m.host || '') + '</td>' +
          '<td>' + escapeHTML(m.os || '') + '</td>' +
          '<td>' + (flags.monitoring_only ? "true" : "false") + '</td>' +
          '<td>' + (flags.aggressive ? "true" : "false") + '</td>' +
          '<td>' + (flags.ebpf ? "true" : "false") + '</td>';
        tbody.appendChild(tr);
      });
    }

    fetchData();
    setInterval(fetchData, 5000);
  </script>
</body>
</html>
"""

# ===== HTTP handler =====

class Handler(BaseHTTPRequestHandler):
    def _set_json(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()

    def _set_html(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self._set_html()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
        elif parsed.path == "/data":
            with metrics_lock:
                metrics_copy = list(metrics_buffer)
            log_tail = tail_log(LOG_FILE, 200)
            policy = load_policy()
            policy_summary = summarize_policy(policy)
            policy_timeline = build_policy_timeline(metrics_copy, policy_summary) if policy_summary else []
            indicators = compute_indicators(metrics_copy, log_tail, policy_summary) if policy_summary else None
            payload = {
                "metrics": metrics_copy,
                "log_tail": log_tail,
                "policy_summary": policy_summary,
                "policy_timeline": policy_timeline,
                "indicators": indicators,
            }
            self._set_json()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # metrics POST from daemon
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        entry = {
            "raw": data,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ts": time.time(),
            "host": "",
            "os": "",
            "flags": {}
        }

        d = data.get("data") if isinstance(data, dict) else {}
        if isinstance(d, dict):
            entry["host"] = d.get("host", "")
            entry["os"] = d.get("os", "")
            flags = d.get("flags") or {}
            if isinstance(flags, dict):
                entry["flags"] = flags

        append_metrics(entry)
        print("[monitor_server] received metrics:", entry)

        self._set_json()
        self.wfile.write(b'{"status":"ok"}')


def run():
    load_metrics_history()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[monitor_server] Listening on http://127.0.0.1:{PORT}/")
    server.serve_forever()


if __name__ == "__main__":
    run()
