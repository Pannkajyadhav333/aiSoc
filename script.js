const alerts = [
  {
    id: "SOC-1001",
    title: "Multiple failed administrator logins",
    severity: "High",
    system: "server-01",
    status: "Open",
    timestamp: "2026-06-28 09:15:22"
  },
  {
    id: "SOC-1002",
    title: "Suspicious outbound domain connection",
    severity: "High",
    system: "firewall-02",
    status: "Open",
    timestamp: "2026-06-28 09:20:11"
  },
  {
    id: "SOC-1003",
    title: "Unusual endpoint process execution",
    severity: "Medium",
    system: "laptop-18",
    status: "Resolved",
    timestamp: "2026-06-28 09:28:04"
  },
  {
    id: "SOC-1004",
    title: "Blocked malware signature",
    severity: "Medium",
    system: "gateway-01",
    status: "Open",
    timestamp: "2026-06-28 09:42:10"
  },
  {
    id: "SOC-1005",
    title: "Routine vulnerability scan completed",
    severity: "Low",
    system: "scanner-03",
    status: "Resolved",
    timestamp: "2026-06-28 10:05:32"
  },
  {
    id: "SOC-1006",
    title: "Safe heartbeat received",
    severity: "Low",
    system: "database-02",
    status: "Resolved",
    timestamp: "2026-06-28 10:20:14"
  }
];

const systems = ["server-01", "firewall-02", "laptop-18", "gateway-01", "scanner-03", "database-02", "mail-01", "vpn-01"];

document.addEventListener("DOMContentLoaded", () => {
  bindLoginForm();
  renderDashboard();
  renderReport();
  bindLogAnalysis();
  bindAlertFilters();
  bindCsvDownload();
});

function bindLoginForm() {
  const loginForm = document.getElementById("loginForm");
  const username = document.getElementById("username");
  const password = document.getElementById("password");
  const togglePassword = document.getElementById("togglePassword");
  const message = document.getElementById("loginMessage");

  if (!loginForm || !username || !password || !message) {
    return;
  }

  togglePassword?.addEventListener("click", () => {
    const isHidden = password.type === "password";
    password.type = isHidden ? "text" : "password";
    togglePassword.textContent = isHidden ? "Hide" : "Show";
    togglePassword.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
  });

  loginForm.addEventListener("submit", (event) => {
    event.preventDefault();

    const enteredUsername = username.value.trim();
    const enteredPassword = password.value.trim();

    message.classList.remove("success");

    if (!enteredUsername || !enteredPassword) {
      message.textContent = "Username and Password are required";
      return;
    }

    if (enteredUsername === "admin" && enteredPassword === "admin123") {
      message.textContent = "Access granted. Redirecting...";
      message.classList.add("success");
      window.setTimeout(() => {
        window.location.href = "index.html";
      }, 450);
      return;
    }

    message.textContent = "Invalid Username or Password";
  });
}

function renderDashboard() {
  const totalAlerts = document.getElementById("totalAlerts");
  const criticalAlerts = document.getElementById("criticalAlerts");
  const safeSystems = document.getElementById("safeSystems");
  const threatList = document.getElementById("threatList");
  const alertsTable = document.getElementById("alertsTable");

  if (!totalAlerts || !criticalAlerts || !safeSystems) {
    return;
  }

  const affectedSystems = new Set(alerts.filter((alert) => alert.status === "Open").map((alert) => alert.system));
  totalAlerts.textContent = alerts.length;
  criticalAlerts.textContent = alerts.filter((alert) => alert.severity === "High").length;
  safeSystems.textContent = systems.length - affectedSystems.size;

  if (threatList) {
    const severityCounts = ["High", "Medium", "Low"].map((severity) => ({
      severity,
      count: alerts.filter((alert) => alert.severity === severity).length
    }));

    threatList.innerHTML = severityCounts.map((item) => `
      <div class="threat-card">
        <span class="severity-pill ${item.severity.toLowerCase()}">${item.severity}</span>
        <div>
          <strong>${item.count} ${item.count === 1 ? "threat" : "threats"} detected</strong>
          <span>${getSeverityDescription(item.severity)}</span>
        </div>
      </div>
    `).join("");
  }

  if (alertsTable) {
    renderAlertsTable("all");
  }
}

function bindLogAnalysis() {
  const fileInput = document.getElementById("logFile");
  const logInput = document.getElementById("logInput");
  const analyzeButton = document.getElementById("analyzeLogs");
  const sampleButton = document.getElementById("loadSampleLogs");

  if (!logInput || !analyzeButton) {
    return;
  }

  fileInput?.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      logInput.value = String(reader.result || "");
      analyzeLogs();
    };
    reader.readAsText(file);
  });

  sampleButton?.addEventListener("click", () => {
    logInput.value = [
      "2026-06-28 09:15:22,auth,server-01,failed login for admin from 198.51.100.23",
      "2026-06-28 09:20:11,network,firewall-02,suspicious outbound connection to unknown domain",
      "2026-06-28 09:28:04,endpoint,laptop-18,user login successful",
      "2026-06-28 09:33:41,auth,server-04,multiple failed login attempts for root",
      "2026-06-28 09:42:10,ids,gateway-01,malware signature blocked"
    ].join("\n");
    analyzeLogs();
  });

  analyzeButton.addEventListener("click", analyzeLogs);
  analyzeLogs();
}

function analyzeLogs() {
  const logInput = document.getElementById("logInput");
  const results = document.getElementById("analysisResults");

  if (!logInput || !results) {
    return;
  }

  const lines = logInput.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const detections = lines.map((line) => {
    const lower = line.toLowerCase();

    if (lower.includes("failed login") || lower.includes("failed password")) {
      return {
        type: "Failed Login",
        severity: "High",
        line
      };
    }

    if (lower.includes("suspicious") || lower.includes("malware") || lower.includes("unknown domain")) {
      return {
        type: "Suspicious Activity",
        severity: lower.includes("malware") ? "High" : "Medium",
        line
      };
    }

    return null;
  }).filter(Boolean);

  if (detections.length === 0) {
    results.innerHTML = `
      <div class="result-item">
        <strong>No threats detected</strong>
        <span>${lines.length} log lines analyzed. No failed logins or suspicious activity found.</span>
      </div>
    `;
    return;
  }

  results.innerHTML = detections.map((item) => `
    <div class="result-item">
      <strong>${item.type} <span class="severity-pill ${item.severity.toLowerCase()}">${item.severity}</span></strong>
      <span>${escapeHtml(item.line)}</span>
    </div>
  `).join("");
}

function bindAlertFilters() {
  document.querySelectorAll(".filter-button").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".filter-button").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      renderAlertsTable(button.dataset.filter || "all");
    });
  });
}

function renderAlertsTable(filter) {
  const table = document.getElementById("alertsTable");

  if (!table) {
    return;
  }

  const visibleAlerts = filter === "all" ? alerts : alerts.filter((alert) => alert.status === filter);
  table.innerHTML = visibleAlerts.map((alert) => `
    <tr>
      <td>${alert.id}</td>
      <td>${alert.title}</td>
      <td><span class="severity-pill ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
      <td>${alert.system}</td>
      <td><span class="status-pill ${alert.status.toLowerCase()}">${alert.status}</span></td>
      <td><button class="table-action" type="button" data-id="${alert.id}">${alert.status === "Open" ? "Resolve" : "Reopen"}</button></td>
    </tr>
  `).join("");

  table.querySelectorAll(".table-action").forEach((button) => {
    button.addEventListener("click", () => {
      const alert = alerts.find((item) => item.id === button.dataset.id);
      if (alert) {
        alert.status = alert.status === "Open" ? "Resolved" : "Open";
        renderDashboard();
        renderAlertsTable(document.querySelector(".filter-button.active")?.dataset.filter || "all");
      }
    });
  });
}

function renderReport() {
  const reportTotal = document.getElementById("reportTotal");
  const reportCritical = document.getElementById("reportCritical");
  const reportResolved = document.getElementById("reportResolved");
  const reportTable = document.getElementById("reportTable");

  if (!reportTable || !reportTotal || !reportCritical || !reportResolved) {
    return;
  }

  reportTotal.textContent = alerts.length;
  reportCritical.textContent = alerts.filter((alert) => alert.severity === "High").length;
  reportResolved.textContent = alerts.filter((alert) => alert.status === "Resolved").length;

  reportTable.innerHTML = alerts.map((alert) => `
    <tr>
      <td>${alert.id}</td>
      <td>${alert.title}</td>
      <td><span class="severity-pill ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
      <td>${alert.system}</td>
      <td><span class="status-pill ${alert.status.toLowerCase()}">${alert.status}</span></td>
      <td>${alert.timestamp}</td>
    </tr>
  `).join("");
}

function bindCsvDownload() {
  const button = document.getElementById("downloadReport");

  if (!button) {
    return;
  }

  button.addEventListener("click", () => {
    const header = ["ID", "Alert", "Severity", "System", "Status", "Timestamp"];
    const rows = alerts.map((alert) => [alert.id, alert.title, alert.severity, alert.system, alert.status, alert.timestamp]);
    const csv = [header, ...rows].map((row) => row.map(csvEscape).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "ai-soc-security-report.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });
}

function getSeverityDescription(severity) {
  if (severity === "High") {
    return "Credential attacks, malware, or urgent network threats.";
  }

  if (severity === "Medium") {
    return "Suspicious behavior requiring investigation.";
  }

  return "Low risk events and informational security signals.";
}

function csvEscape(value) {
  const text = String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
