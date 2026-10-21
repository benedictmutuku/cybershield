"use strict";

const API_BASE = (window.CYBERSHIELD_API_BASE || "").replace(/\/$/, "");
const menuToggle = document.getElementById("menu-toggle");
const mobileScrim = document.getElementById("mobile-scrim");
const logoutButton = document.getElementById("logout-button");
const apiStatus = document.getElementById("api-status");
const scanForm = document.getElementById("scan-form");
const scanInput = document.getElementById("scan-input");
const scanResult = document.getElementById("scan-result");
const scanSubmit = document.getElementById("scan-submit");
const scanWarning = document.getElementById("scan-warning");
const modeButtons = document.querySelectorAll("[data-input-type]");
const navigationLinks = document.querySelectorAll(".side-nav [data-nav]");
const currentPage = document.getElementById("current-page");
const recentBody = document.getElementById("recent-body");
const activityList = document.getElementById("activity-list");
const timelineCanvas = document.getElementById("scan-timeline");
const timelineNote = document.getElementById("timeline-note");
let scanTimeline = null;

logoutButton.addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.assign("index.html");
});

function setApiStatus(state, message) {
  apiStatus.classList.remove("connected", "error");
  if (state === "connected") apiStatus.classList.add("connected");
  if (state === "error") apiStatus.classList.add("error");
  apiStatus.lastElementChild.textContent = message;
}

function renderStats(stats) {
  const keys = ["total", "phishing", "suspicious", "safe"];
  const values = Object.fromEntries(keys.map((key) => {
    const value = stats[key];
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`Invalid ${key} count in stats response.`);
    }
    return [key, value];
  }));
  const total = values.total;

  document.getElementById("stat-total").textContent = total.toLocaleString();
  ["phishing", "suspicious", "safe"].forEach((key) => {
    document.getElementById(`stat-${key}`).textContent = values[key].toLocaleString();
  });
}

function clearStats() {
  ["total", "phishing", "suspicious", "safe"].forEach((key) => {
    document.getElementById(`stat-${key}`).textContent = "—";
  });
}

function parseScanDate(value) {
  const normalized = value.replace(" ", "T");
  const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/i.test(normalized);
  return new Date(hasTimezone ? normalized : `${normalized}Z`);
}

function formatScanDate(value) {
  const date = parseScanDate(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function createPill(label) {
  const pill = document.createElement("span");
  pill.className = `assessment-pill ${label}`;
  pill.textContent = label;
  return pill;
}

function renderActivity(scans) {
  activityList.replaceChildren();
  if (scans.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No scans yet.";
    activityList.append(empty);
    return;
  }

  scans.slice(0, 5).forEach((scan) => {
    const row = document.createElement("div");
    row.className = "activity-row";

    const type = document.createElement("span");
    type.className = `activity-type${scan.input_type === "message" ? " message" : ""}`;
    type.setAttribute("aria-label", scan.input_type === "message" ? "Message" : "URL");
    type.textContent = scan.input_type === "message" ? "MSG" : "URL";

    const detail = document.createElement("span");
    detail.className = "activity-detail";
    const input = document.createElement("strong");
    input.textContent = scan.input_text;
    input.title = scan.input_text;
    const metadata = document.createElement("small");
    metadata.textContent = `${formatScanDate(scan.created_at)} · ${scan.risk_score} risk score`;
    detail.append(input, metadata);
    row.append(type, detail, createPill(scan.label));
    activityList.append(row);
  });
}

function renderRecentTable(scans) {
  recentBody.replaceChildren();
  document.getElementById("recent-count").textContent =
    scans.length ? `LATEST ${scans.length}` : "NO SCANS";

  if (scans.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.className = "table-empty";
    cell.colSpan = 4;
    cell.textContent = "No recent threats to display.";
    row.append(cell);
    recentBody.append(row);
    return;
  }

  scans.forEach((scan) => {
    const row = document.createElement("tr");
    const inputCell = document.createElement("td");
    const input = document.createElement("span");
    input.className = "table-content";
    input.title = scan.input_text;
    input.textContent = scan.input_text;
    inputCell.append(input);

    const scoreCell = document.createElement("td");
    scoreCell.className = "risk-number";
    scoreCell.textContent = `${scan.risk_score} / 100`;

    const statusCell = document.createElement("td");
    statusCell.append(createPill(scan.label));

    const dateCell = document.createElement("td");
    dateCell.textContent = formatScanDate(scan.created_at);
    row.append(inputCell, scoreCell, statusCell, dateCell);
    recentBody.append(row);
  });
}

function renderTimeline(scans) {
  if (scanTimeline) {
    scanTimeline.destroy();
    scanTimeline = null;
  }
  if (scans.length === 0) {
    timelineNote.textContent = "No recent scans to display yet.";
    return;
  }
  if (typeof window.Chart !== "function") {
    timelineNote.textContent = "Chart unavailable. Check your connection to the Chart.js CDN.";
    console.error("Chart.js did not load; the scan timeline cannot be displayed.");
    return;
  }

  const chronologicalScans = [...scans].sort(
    (left, right) => parseScanDate(left.created_at) - parseScanDate(right.created_at),
  );
  const colors = {
    safe: "rgba(55, 219, 161, 0.78)",
    suspicious: "rgba(255, 191, 90, 0.82)",
    phishing: "rgba(255, 100, 122, 0.84)",
  };
  const borderColors = {
    safe: "rgba(55, 219, 161, 1)",
    suspicious: "rgba(255, 191, 90, 1)",
    phishing: "rgba(255, 100, 122, 1)",
  };

  scanTimeline = new window.Chart(timelineCanvas, {
    type: "bar",
    data: {
      labels: chronologicalScans.map((scan) => formatScanDate(scan.created_at)),
      datasets: [{
        label: "Risk score",
        data: chronologicalScans.map((scan) => scan.risk_score),
        backgroundColor: chronologicalScans.map((scan) => colors[scan.label]),
        borderColor: chronologicalScans.map((scan) => borderColors[scan.label]),
        borderWidth: 1,
        borderRadius: 5,
        maxBarThickness: 34,
      }],
    },
    options: {
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: "index" },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label(context) {
              const scan = chronologicalScans[context.dataIndex];
              return ` ${scan.label}: ${scan.risk_score} / 100`;
            },
            afterLabel(context) {
              const scan = chronologicalScans[context.dataIndex];
              return scan.input_text;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: "#8291a5", maxRotation: 0, autoSkip: true },
          border: { color: "#26354a" },
        },
        y: {
          beginAtZero: true,
          max: 100,
          grid: { color: "rgba(38, 53, 74, 0.55)" },
          ticks: { color: "#8291a5", stepSize: 20 },
          border: { display: false },
        },
      },
    },
  });
  timelineNote.textContent = "Risk scores for your latest scans · color indicates verdict.";
}

function renderRecentScans(scans) {
  if (!Array.isArray(scans)) {
    throw new Error("The recent scans response must be a list.");
  }
  scans.forEach((scan) => {
    if (
      typeof scan.input_text !== "string"
      || !["url", "message"].includes(scan.input_type)
      || typeof scan.risk_score !== "number"
      || !Number.isFinite(scan.risk_score)
      || scan.risk_score < 0
      || scan.risk_score > 100
      || !["safe", "suspicious", "phishing"].includes(scan.label)
      || typeof scan.created_at !== "string"
    ) {
      throw new Error("The recent scans response contains an invalid scan.");
    }
  });

  renderActivity(scans);
  renderRecentTable(scans);
  renderTimeline(scans);
}

function showRecentError(error) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "table-empty";
  cell.textContent = "Could not load recent threats. Check the API connection and refresh.";
  row.append(cell);
  recentBody.replaceChildren(row);
  document.getElementById("recent-count").textContent = "UNAVAILABLE";
  activityList.textContent = "Could not load recent scans.";
  timelineNote.textContent = "Scan timeline unavailable. Check the API connection and refresh.";
  if (scanTimeline) {
    scanTimeline.destroy();
    scanTimeline = null;
  }
  console.error("Could not load recent scans:", error);
}

async function refreshRecentScans() {
  timelineNote.textContent = "Loading recent scans...";
  try {
    const response = await fetch(`${API_BASE}/recent`);
    if (!response.ok) {
      throw new Error(`Recent scans request failed (${response.status}).`);
    }
    renderRecentScans(await response.json());
  } catch (error) {
    showRecentError(error);
  }
}

function showScanResult(result) {
  if (!Number.isInteger(result.risk_score) || result.risk_score < 0 || result.risk_score > 100) {
    throw new Error("The API returned an invalid risk score.");
  }
  if (!["safe", "suspicious", "phishing"].includes(result.label)) {
    throw new Error("The API returned an invalid verdict.");
  }
  if (!Array.isArray(result.reasons) || !result.reasons.every((reason) => typeof reason === "string")) {
    throw new Error("The API returned an invalid reasons list.");
  }

  const resultContent = document.createElement("div");
  resultContent.className = "scan-result-content";

  const gauge = document.createElement("div");
  gauge.className = `risk-gauge ${result.label}`;
  gauge.setAttribute("role", "meter");
  gauge.setAttribute("aria-label", "Risk score");
  gauge.setAttribute("aria-valuemin", "0");
  gauge.setAttribute("aria-valuemax", "100");
  gauge.setAttribute("aria-valuenow", String(result.risk_score));
  gauge.style.setProperty("--risk-score", String(result.risk_score));

  const gaugeValue = document.createElement("strong");
  gaugeValue.className = "risk-gauge-value";
  gaugeValue.textContent = String(result.risk_score);
  const gaugeCaption = document.createElement("span");
  gaugeCaption.className = "risk-gauge-caption";
  gaugeCaption.textContent = "RISK SCORE";
  gauge.append(gaugeValue, gaugeCaption);

  const details = document.createElement("div");
  details.className = "assessment-details";
  const heading = document.createElement("div");
  heading.className = "result-heading";
  const verdictTitle = document.createElement("strong");
  verdictTitle.textContent = "Scan complete";
  const verdict = document.createElement("span");
  verdict.className = `result-label ${result.label}`;
  verdict.textContent = result.label;
  heading.append(verdictTitle, verdict);

  const reasonsTitle = document.createElement("h3");
  reasonsTitle.className = "reasons-title";
  reasonsTitle.textContent = "Reasons";
  const reasons = document.createElement("ul");
  reasons.className = "result-reasons";
  result.reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasons.append(item);
  });
  if (result.reasons.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No reasons were provided.";
    reasons.append(item);
  }

  details.append(heading, reasonsTitle, reasons);
  resultContent.append(gauge, details);
  scanResult.classList.remove("error");
  scanResult.replaceChildren(resultContent);
  scanResult.hidden = false;

  if (result.risk_score > 70) {
    document.getElementById("warning-message").textContent =
      `This content scored ${result.risk_score}/100. Avoid interacting with it.`;
    scanWarning.hidden = false;
  } else {
    scanWarning.hidden = true;
  }
}

async function refreshStats() {
  setApiStatus("loading", "Loading stats");
  try {
    const response = await fetch(`${API_BASE}/stats`);
    if (!response.ok) {
      throw new Error(`Stats request failed (${response.status}).`);
    }
    const stats = await response.json();
    renderStats(stats);
    setApiStatus("connected", "API connected");
  } catch (error) {
    clearStats();
    setApiStatus("error", "API unavailable");
    console.error("Could not load dashboard stats:", error);
  }
}

function closeMenu() {
  document.body.classList.remove("menu-open");
  menuToggle.setAttribute("aria-expanded", "false");
}

menuToggle.addEventListener("click", () => {
  const isOpen = document.body.classList.toggle("menu-open");
  menuToggle.setAttribute("aria-expanded", String(isOpen));
});

mobileScrim.addEventListener("click", closeMenu);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeMenu();
});

function updateNavigation() {
  const activeLink = [...navigationLinks].find((link) => link.hash === window.location.hash)
    || navigationLinks[0];

  navigationLinks.forEach((link) => {
    const isActive = link === activeLink;
    link.classList.toggle("active", isActive);
    if (isActive) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });

  currentPage.textContent = activeLink.querySelector("span").textContent;
  closeMenu();
}

window.addEventListener("hashchange", updateNavigation);
navigationLinks.forEach((link) => link.addEventListener("click", closeMenu));
updateNavigation();

modeButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const isUrl = button.dataset.inputType === "url";

    modeButtons.forEach((modeButton) => {
      const isActive = modeButton === button;
      modeButton.classList.toggle("active", isActive);
      modeButton.setAttribute("aria-pressed", String(isActive));
    });

    document.getElementById("scan-input-label").textContent = isUrl
      ? "URL TO CHECK"
      : "MESSAGE TO CHECK";
    document.getElementById("input-hint").textContent = isUrl
      ? "Enter the full link including https:// for the most accurate scan."
      : "Paste the suspicious text. Avoid sharing private or sensitive information.";
    scanInput.rows = isUrl ? 1 : 4;
    scanInput.placeholder = isUrl
      ? "https://example.com/login"
      : "Paste a suspicious message here...";
    scanInput.value = "";
    scanResult.hidden = true;
  });
});

document.getElementById("clear-input").addEventListener("click", () => {
  scanInput.value = "";
  scanInput.focus();
});

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const inputText = scanInput.value.trim();
  if (!inputText) {
    scanInput.focus();
    return;
  }

  const inputType = document.querySelector("[data-input-type].active").dataset.inputType;
  scanSubmit.disabled = true;
  scanSubmit.classList.add("loading");
  scanSubmit.querySelector(".submit-label").textContent = "Scanning...";
  scanWarning.hidden = true;
  scanResult.hidden = true;

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_text: inputText, input_type: inputType }),
    });
    if (!response.ok) {
      let message = `Scan failed (${response.status}).`;
      try {
        const payload = await response.json();
        if (typeof payload.detail === "string") message = payload.detail;
      } catch {
        // Use the status-based message when the response is not JSON.
      }
      throw new Error(message);
    }

    showScanResult(await response.json());
    await Promise.all([refreshStats(), refreshRecentScans()]);
  } catch (error) {
    scanResult.classList.add("error");
    scanResult.textContent = `Scan failed: ${error.message}`;
    scanResult.hidden = false;
  } finally {
    scanSubmit.disabled = false;
    scanSubmit.classList.remove("loading");
    scanSubmit.querySelector(".submit-label").textContent = "Scan";
  }
});

document.getElementById("warning-dismiss").addEventListener("click", () => {
  scanWarning.hidden = true;
});

document.getElementById("refresh-button").addEventListener("click", () => {
  Promise.all([refreshStats(), refreshRecentScans()]);
});

document.getElementById("today-label").textContent = new Intl.DateTimeFormat(undefined, {
  weekday: "short",
  month: "short",
  day: "numeric",
  year: "numeric",
}).format(new Date());
document.getElementById("year").textContent = new Date().getFullYear();
refreshStats();
refreshRecentScans();
