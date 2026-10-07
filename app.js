const API_BASE = "http://127.0.0.1:5000/api";

// State
let radarTargets = [];
let radarAngle = 0;

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initClock();
    initRadarCanvas();
    initSliders();

    // Initial Data Fetch
    fetchSummary();
    fetchLogs();
    fetchDarkwebIntel();
    fetchLoginAttempts();
    fetchIPRules();

    // Event Listeners
    setupEventListeners();

    // Timers for live dynamic updates
    setInterval(fetchSummary, 5000);
    setInterval(fetchRadarFeed, 3000);
});

/* Navigation Tab Switching */
function initNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    const tabContents = document.querySelectorAll(".tab-content");

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetTab = item.getAttribute("data-tab");

            navItems.forEach(n => n.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));

            item.classList.add("active");
            document.getElementById(targetTab).classList.add("active");
        });
    });
}

/* UTC Clock */
function initClock() {
    const clockEl = document.getElementById("utc-clock");
    function updateClock() {
        const now = new Date();
        clockEl.textContent = now.toUTCString().split(" ")[4] + " UTC";
    }
    updateClock();
    setInterval(updateClock, 1000);
}

/* Slider value updates */
function initSliders() {
    const sliders = [
        { input: "input-packet-rate", val: "val-packet-rate" },
        { input: "input-byte-size", val: "val-byte-size" },
        { input: "input-entropy", val: "val-entropy" },
        { input: "input-failed-attempts", val: "val-failed-attempts" },
        { input: "input-port-count", val: "val-port-count" }
    ];

    sliders.forEach(s => {
        const inp = document.getElementById(s.input);
        const display = document.getElementById(s.val);
        if (inp && display) {
            inp.addEventListener("input", (e) => {
                display.textContent = e.target.value;
            });
        }
    });
}

/* API: Summary Stats */
async function fetchSummary() {
    try {
        const res = await fetch(`${API_BASE}/summary`);
        const data = await res.json();

        document.getElementById("stat-active-threats").textContent = data.active_threats;
        document.getElementById("stat-blacklisted-ips").textContent = data.blacklisted_ips;
        document.getElementById("stat-whitelisted-ips").textContent = data.whitelisted_ips;
        document.getElementById("stat-failed-logins").textContent = data.failed_logins;
    } catch (e) {
        console.warn("API Summary fetch offline", e);
    }
}

/* API: Logs & Threat Stream */
async function fetchLogs(searchQuery = "") {
    try {
        const url = searchQuery ? `${API_BASE}/logs?q=${encodeURIComponent(searchQuery)}` : `${API_BASE}/logs`;
        const res = await fetch(url);
        const logs = await res.json();

        renderOverviewThreats(logs.slice(0, 6));
        renderAuditLogs(logs);
    } catch (e) {
        console.warn("API Logs fetch offline", e);
    }
}

function renderOverviewThreats(logs) {
    const container = document.getElementById("overview-threat-list");
    if (!container) return;
    if (logs.length === 0) {
        container.innerHTML = `<div class="p-3 text-center text-muted">No threat events logged. System nominal.</div>`;
        return;
    }

    container.innerHTML = logs.map(log => `
        <div class="threat-item ${log.threat_level}">
            <div class="threat-info">
                <h4>${log.event_type} (${log.source_ip})</h4>
                <p>${log.description}</p>
            </div>
            <div class="threat-time">
                <span class="badge badge-${log.threat_level === 'CRITICAL' ? 'danger' : 'warning'}">${log.threat_level}</span>
            </div>
        </div>
    `).join("");
}

function renderAuditLogs(logs) {
    const tbody = document.getElementById("audit-logs-table");
    if (!tbody) return;

    tbody.innerHTML = logs.map(log => `
        <tr>
            <td class="font-mono">#${log.id}</td>
            <td>${log.timestamp}</td>
            <td class="font-mono text-cyan">${log.source_ip}</td>
            <td><strong>${log.event_type}</strong></td>
            <td><span class="badge badge-${log.threat_level === 'CRITICAL' ? 'danger' : (log.threat_level === 'HIGH' ? 'warning' : 'cyber')}">${log.threat_level}</span></td>
            <td class="font-mono">SEV-${log.severity}</td>
            <td>${log.description}</td>
            <td><span class="badge badge-success">${log.status}</span></td>
        </tr>
    `).join("");
}

/* API: DarkWeb Threat Intelligence */
async function fetchDarkwebIntel() {
    try {
        const res = await fetch(`${API_BASE}/darkweb-intel`);
        const intel = await res.json();

        const tbody = document.getElementById("darkweb-intel-table");
        if (!tbody) return;

        tbody.innerHTML = intel.map(item => `
            <tr>
                <td class="font-mono text-danger">${item.ioc}</td>
                <td><strong>${item.malware}</strong></td>
                <td><span class="badge badge-danger">ACTIVE IOC</span></td>
                <td><button class="btn btn-sm btn-outline" onclick="quickAddBlacklist('${item.ioc}', 'Global IOC Feed Threat')"><i class="fa-solid fa-ban"></i> Ban IP</button></td>
            </tr>
        `).join("");
    } catch (e) {
        console.warn("Darkweb Intel offline", e);
    }
}

/* API: Login Security Attempts */
async function fetchLoginAttempts() {
    try {
        const res = await fetch(`${API_BASE}/login-monitoring`);
        const attempts = await res.json();

        const tbody = document.getElementById("login-attempts-table");
        if (!tbody) return;

        tbody.innerHTML = attempts.map(att => `
            <tr>
                <td class="font-mono">${att.timestamp}</td>
                <td><strong>${att.username}</strong></td>
                <td class="font-mono">${att.ip_address}</td>
                <td>${att.location}</td>
                <td class="text-muted">${att.device}</td>
                <td><span class="badge badge-${att.status === 'SUCCESS' ? 'success' : 'danger'}">${att.status}</span></td>
                <td class="font-mono">${att.anomaly_score}%</td>
                <td><span class="badge badge-${att.risk_flag === 'CRITICAL' ? 'danger' : (att.risk_flag === 'HIGH' ? 'warning' : 'success')}">${att.risk_flag}</span></td>
            </tr>
        `).join("");
    } catch (e) {
        console.warn("Login attempts offline", e);
    }
}

/* API: IP Rules */
async function fetchIPRules() {
    try {
        const res = await fetch(`${API_BASE}/ip-rules`);
        const rules = await res.json();

        const tbody = document.getElementById("ip-rules-table");
        if (!tbody) return;

        tbody.innerHTML = rules.map(rule => `
            <tr>
                <td class="font-mono text-cyan"><strong>${rule.ip_address}</strong></td>
                <td><span class="badge badge-${rule.rule_type === 'BLACKLIST' ? 'danger' : 'success'}">${rule.rule_type}</span></td>
                <td>${rule.reason}</td>
                <td class="font-mono text-muted">${rule.added_at}</td>
                <td>
                    <button class="btn btn-sm btn-outline text-danger" onclick="deleteIPRule('${rule.ip_address}')">
                        <i class="fa-solid fa-trash"></i> Delete
                    </button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.warn("IP Rules offline", e);
    }
}

/* Event Listeners Setup */
function setupEventListeners() {
    // Form ML Classifier Submit
    const formClassifier = document.getElementById("form-classifier");
    if (formClassifier) {
        formClassifier.addEventListener("submit", async (e) => {
            e.preventDefault();
            const payload = {
                packet_rate: parseFloat(document.getElementById("input-packet-rate").value),
                byte_size: parseFloat(document.getElementById("input-byte-size").value),
                entropy: parseFloat(document.getElementById("input-entropy").value),
                failed_attempts: parseInt(document.getElementById("input-failed-attempts").value),
                port_count: parseInt(document.getElementById("input-port-count").value),
                source_ip: document.getElementById("input-source-ip").value
            };

            try {
                const res = await fetch(`${API_BASE}/classify`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                const result = await res.json();
                renderClassifierResult(result, payload.source_ip);
                fetchSummary();
                fetchLogs();
            } catch (err) {
                alert("Classification API call failed. Make sure server.py is running!");
            }
        });
    }

    // Refresh logs button
    document.getElementById("btn-refresh-logs")?.addEventListener("click", () => fetchLogs());

    // Simulate Attack button
    document.getElementById("btn-simulate-attack")?.addEventListener("click", async () => {
        const randomIp = `185.220.${Math.floor(Math.random()*254)}.${Math.floor(Math.random()*254)}`;
        await fetch(`${API_BASE}/classify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                packet_rate: 2200,
                byte_size: 64,
                entropy: 0.5,
                failed_attempts: 12,
                port_count: 85,
                source_ip: randomIp
            })
        });
        alert(`🚨 Attack Event Simulated from IP: ${randomIp}`);
        fetchSummary();
        fetchLogs();
    });

    // Simulate Login Attack button
    document.getElementById("btn-trigger-login-sim")?.addEventListener("click", async () => {
        await fetch(`${API_BASE}/login-monitoring`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: "root_admin",
                location: "Unknown Proxy Node",
                device: "Custom Exploit Tool",
                status: "FAILED"
            })
        });
        fetchLoginAttempts();
        fetchSummary();
    });

    // Search Log input
    document.getElementById("input-log-search")?.addEventListener("input", (e) => {
        fetchLogs(e.target.value);
    });

    // Modal controls for Add IP Rule
    const modal = document.getElementById("ip-modal");
    document.getElementById("btn-open-ip-modal")?.addEventListener("click", () => modal.classList.remove("hidden"));
    document.getElementById("btn-close-modal")?.addEventListener("click", () => modal.classList.add("hidden"));
    document.getElementById("btn-cancel-modal")?.addEventListener("click", () => modal.classList.add("hidden"));

    // Form Add IP submit
    document.getElementById("form-add-ip")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const ip = document.getElementById("modal-ip-address").value;
        const rule_type = document.getElementById("modal-rule-type").value;
        const reason = document.getElementById("modal-ip-reason").value;

        await fetch(`${API_BASE}/ip-rules`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip_address: ip, rule_type, reason })
        });

        modal.classList.add("hidden");
        fetchIPRules();
        fetchSummary();
    });

    // Export Logs JSON
    document.getElementById("btn-export-json")?.addEventListener("click", async () => {
        const res = await fetch(`${API_BASE}/logs`);
        const logs = await res.json();
        const blob = new Blob([JSON.stringify(logs, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `AegisAI_Security_Logs_${Date.now()}.json`;
        a.click();
    });

    // Chat Widget Toggle & Form Submit
    const chatWidget = document.getElementById("chat-widget");
    document.getElementById("btn-toggle-chat")?.addEventListener("click", () => chatWidget?.classList.toggle("hidden"));
    document.getElementById("btn-close-chat")?.addEventListener("click", () => chatWidget?.classList.add("hidden"));

    document.getElementById("form-chat")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const input = document.getElementById("input-chat-msg");
        const msg = input.value.trim();
        if (!msg) return;

        appendChatMessage("user", msg);
        input.value = "";

        try {
            const res = await fetch(`${API_BASE}/chat`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: msg })
            });
            const data = await res.json();
            appendChatMessage("bot", data.reply, data.actions);
        } catch (err) {
            appendChatMessage("bot", "⚠️ Network error connecting to SecOps AI Core.");
        }
    });
}

function sendQuickChat(promptText) {
    document.getElementById("chat-widget")?.classList.remove("hidden");
    const input = document.getElementById("input-chat-msg");
    if (input) {
        input.value = promptText;
        document.getElementById("form-chat")?.dispatchEvent(new Event("submit"));
    }
}

function appendChatMessage(sender, text, actions = null) {
    const container = document.getElementById("chat-messages");
    if (!container) return;

    const div = document.createElement("div");
    div.className = `chat-msg ${sender}`;

    // Simple markdown-style bold formatting
    let formatted = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                        .replace(/`(.*?)`/g, '<code class="font-mono text-cyan">$1</code>')
                        .replace(/\n/g, '<br>');

    div.innerHTML = `<p>${formatted}</p>`;

    if (actions && actions.length > 0) {
        const actDiv = document.createElement("div");
        actDiv.className = "chat-actions-row";
        actions.forEach(act => {
            const btn = document.createElement("button");
            btn.className = "btn btn-sm btn-outline";
            btn.innerHTML = act.label;
            btn.onclick = () => handleChatAction(act);
            actDiv.appendChild(btn);
        });
        div.appendChild(actDiv);
    }

    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function handleChatAction(act) {
    if (act.action === "blacklist_ip" && act.ip) {
        quickAddBlacklist(act.ip, "SecOps Assistant Action");
    } else if (act.action === "sim_attack") {
        document.getElementById("btn-simulate-attack")?.click();
    } else if (act.action.startsWith("nav-")) {
        const tab = act.action.replace("nav-", "tab-");
        document.querySelector(`.nav-item[data-tab="${tab}"]`)?.click();
    } else if (act.action === "query_status") {
        sendQuickChat("Summarize current system status");
    } else if (act.action === "query_ddos") {
        sendQuickChat("How to mitigate DDoS SYN flood?");
    }
}

/* Render ML Classifier Result Box */
function renderClassifierResult(res, sourceIp) {
    document.getElementById("result-placeholder")?.classList.add("hidden");
    const resultBox = document.getElementById("result-content");
    resultBox?.classList.remove("hidden");

    document.getElementById("res-type").textContent = res.threat_type;
    document.getElementById("res-risk-score").textContent = res.risk_score;
    document.getElementById("res-confidence").textContent = `${res.confidence}%`;
    document.getElementById("res-severity").textContent = `SEV-${res.severity} / 10`;
    document.getElementById("res-mitigation").textContent = res.mitigation;

    const banner = document.getElementById("res-banner");
    if (banner) {
        banner.style.borderColor = res.color;
        banner.style.background = `${res.color}22`;
    }

    const btnQuick = document.getElementById("btn-quick-blacklist");
    if (btnQuick) {
        btnQuick.onclick = () => quickAddBlacklist(sourceIp, `Flagged by AI Engine (${res.threat_type})`);
    }
}

async function quickAddBlacklist(ip, reason) {
    await fetch(`${API_BASE}/ip-rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip_address: ip, rule_type: "BLACKLIST", reason })
    });
    alert(`🛡️ IP ${ip} has been Blacklisted on firewall!`);
    fetchIPRules();
    fetchSummary();
}

async function deleteIPRule(ip) {
    if (confirm(`Remove IP rule for ${ip}?`)) {
        await fetch(`${API_BASE}/ip-rules?ip=${encodeURIComponent(ip)}`, { method: "DELETE" });
        fetchIPRules();
        fetchSummary();
    }
}

/* Radar Sweep Animation */
function initRadarCanvas() {
    const canvas = document.getElementById("radarCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = 180;

    fetchRadarFeed();

    function drawRadar() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Concentric radar circles
        ctx.strokeStyle = "rgba(0, 243, 255, 0.25)";
        ctx.lineWidth = 1;
        [40, 80, 120, 160, radius].forEach(r => {
            ctx.beginPath();
            ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
            ctx.stroke();
        });

        // Crosshairs
        ctx.beginPath();
        ctx.moveTo(centerX - radius, centerY);
        ctx.lineTo(centerX + radius, centerY);
        ctx.moveTo(centerX, centerY - radius);
        ctx.lineTo(centerX, centerY + radius);
        ctx.stroke();

        // Rotating Sweep Line
        radarAngle += 0.03;
        if (radarAngle >= Math.PI * 2) radarAngle = 0;

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(centerX + radius * Math.cos(radarAngle), centerY + radius * Math.sin(radarAngle));
        ctx.strokeStyle = "#00f3ff";
        ctx.lineWidth = 2;
        ctx.stroke();

        // Draw Threat Radar Targets
        radarTargets.forEach(t => {
            const rad = (t.angle * Math.PI) / 180;
            const dist = (t.distance / 100) * radius;
            const tx = centerX + dist * Math.cos(rad);
            const ty = centerY + dist * Math.sin(rad);

            ctx.beginPath();
            ctx.arc(tx, ty, 6, 0, Math.PI * 2);
            ctx.fillStyle = t.severity === 'CRITICAL' ? '#ff0055' : (t.severity === 'HIGH' ? '#ffb700' : '#00f3ff');
            ctx.fill();
            ctx.shadowBlur = 10;
            ctx.shadowColor = ctx.fillStyle;
        });

        requestAnimationFrame(drawRadar);
    }

    drawRadar();
}

async function fetchRadarFeed() {
    try {
        const res = await fetch(`${API_BASE}/radar-feed`);
        const data = await res.json();
        radarTargets = data.targets || [];
    } catch (e) {
        // Fallback target points
        radarTargets = [
            { angle: 45, distance: 60, severity: "CRITICAL" },
            { angle: 180, distance: 80, severity: "HIGH" },
            { angle: 270, distance: 35, severity: "LOW" }
        ];
    }
}
