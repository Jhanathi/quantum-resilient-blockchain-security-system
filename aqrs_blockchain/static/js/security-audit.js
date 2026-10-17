const auditEscape = (value) => String(value ?? "-").replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;",
}[character]));
const auditDate = (value) => value ? new Date(value).toLocaleString() : "-";
let auditPage = 1;
let auditPageCount = 0;

async function auditRequest(url) {
  const response = await fetch(url, { credentials: "same-origin" });
  let payload = {};
  try {
    payload = await response.json();
  } catch (_) {
    throw new Error("The audit service returned an invalid response.");
  }
  if (response.status === 401) {
    window.location.href = "/login";
    throw new Error("Authentication required.");
  }
  if (response.status === 403) throw new Error("Permission denied.");
  if (!response.ok) throw new Error(payload.error || "Audit request failed.");
  return payload;
}

function currentAuditParams() {
  const form = document.querySelector("#audit-filter-form");
  const params = new URLSearchParams(new FormData(form));
  params.set("page", String(auditPage));
  params.set("page_size", "25");
  for (const [key, value] of [...params.entries()]) {
    if (!value) params.delete(key);
  }
  return params;
}

function setAuditError(message) {
  const body = document.querySelector("#security-audit-list");
  body.innerHTML = `<tr><td colspan="9" class="table-message">${auditEscape(message)}</td></tr>`;
}

function renderAuditBars(selector, data) {
  const container = document.querySelector(selector);
  const entries = Object.entries(data || {});
  if (!entries.length) {
    container.innerHTML = `<p class="audit-empty">No events recorded.</p>`;
    return;
  }
  const max = Math.max(...entries.map(([, count]) => Number(count)), 1);
  container.innerHTML = entries.map(([label, count]) => `
    <div class="audit-bar-row">
      <span>${auditEscape(label.replaceAll("_", " "))}</span>
      <span class="audit-bar-track"><span class="audit-bar-fill" style="width:${Math.max(2, Number(count) / max * 100)}%"></span></span>
      <strong>${auditEscape(count)}</strong>
    </div>`).join("");
}

function renderAuditStats(stats) {
  document.querySelector("#audit-total").textContent = stats.total_events;
  document.querySelector("#audit-day").textContent = stats.last_24_hours;
  document.querySelector("#audit-severe").textContent = stats.high_critical;
  document.querySelector("#audit-blocked").textContent = stats.failed_or_blocked;
  document.querySelector("#audit-demo").textContent = stats.demo_events;
  renderAuditBars("#audit-severity-chart", stats.severity_distribution);
  renderAuditBars("#audit-category-chart", stats.category_distribution);
  const recent = document.querySelector("#audit-recent-list");
  recent.innerHTML = stats.recent_events.length
    ? stats.recent_events.map((event) => `
      <div class="audit-recent-row">
        <time>${auditEscape(auditDate(event.created_at))}</time>
        <span class="audit-badge audit-badge-${auditEscape(event.severity.toLowerCase())}">${auditEscape(event.severity)}</span>
        <strong>${auditEscape(event.title)}</strong>
        <span class="${event.is_demo ? "audit-badge audit-badge-demo" : ""}">${event.is_demo ? "DEMO / SIMULATION" : auditEscape(event.outcome)}</span>
      </div>`).join("")
    : `<p class="audit-empty">No audit events recorded yet.</p>`;
}

function renderAuditEvents(data) {
  const body = document.querySelector("#security-audit-list");
  body.innerHTML = data.events.length ? data.events.map((event) => `
    <tr>
      <td>${auditEscape(auditDate(event.created_at))}</td>
      <td>${auditEscape(event.event_type)}</td>
      <td><span class="audit-badge audit-badge-${auditEscape(event.severity.toLowerCase())}">${auditEscape(event.severity)}</span></td>
      <td>${auditEscape(event.title)}</td>
      <td>${auditEscape(event.actor_username || event.actor_email || event.actor_id || "System")}</td>
      <td>${auditEscape(event.outcome)}</td>
      <td>${auditEscape(event.source)}</td>
      <td>${event.is_demo ? `<span class="audit-badge audit-badge-demo">DEMO</span>` : "Operational"}</td>
      <td><button class="button button-quiet" type="button" data-audit-detail="${auditEscape(event.id)}">Details</button></td>
    </tr>`).join("") : `<tr><td colspan="9" class="table-message">No matching events.</td></tr>`;
  auditPageCount = data.pagination.pages;
  document.querySelector("#audit-page-status").textContent =
    `Page ${data.pagination.page} of ${auditPageCount} - ${data.pagination.total} events`;
  document.querySelector("#audit-prev").disabled = auditPage <= 1;
  document.querySelector("#audit-next").disabled = auditPageCount === 0 || auditPage >= auditPageCount;
}

async function refreshAuditList() {
  const query = currentAuditParams();
  const data = await auditRequest(`/api/security/audit/events?${query}`);
  renderAuditEvents(data);
  document.querySelector("#audit-export-csv").href = `/api/security/audit/export.csv?${query}`;
  document.querySelector("#audit-export-json").href = `/api/security/audit/export.json?${query}`;
}

async function loadAuditDashboard() {
  const data = await auditRequest("/api/security/audit/dashboard");
  renderAuditStats(data.stats);
  const category = document.querySelector("#audit-category-filter");
  for (const value of data.categories) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value.replaceAll("_", " ");
    category.append(option);
  }
  await refreshAuditList();
}

async function showAuditDetails(eventId) {
  const data = await auditRequest(`/api/security/audit/events/${encodeURIComponent(eventId)}`);
  const event = data.event;
  const rows = {
    "Event ID": event.id,
    "Timestamp": auditDate(event.created_at),
    "Event type": event.event_type,
    "Category": event.category,
    "Severity": event.severity,
    "Title": event.title,
    "Description": event.description,
    "Actor": event.actor_username || event.actor_email || event.actor_id || "System",
    "Outcome": event.outcome,
    "Source": event.source,
    "Target": [event.target_type, event.target_id].filter(Boolean).join(": ") || "-",
    "Request correlation": event.correlation_id || "-",
    "Record kind": event.is_demo ? "DEMO / SIMULATION" : "Operational",
    "Metadata": JSON.stringify(event.metadata || {}, null, 2),
  };
  document.querySelector("#audit-detail-title").textContent = event.title;
  document.querySelector("#audit-detail-content").innerHTML = `
    <dl class="audit-detail-list">${Object.entries(rows).map(([label, value]) => `
      <div class="${label === "Metadata" ? "audit-detail-metadata" : ""}">
        <dt>${auditEscape(label)}</dt><dd>${auditEscape(value)}</dd>
      </div>`).join("")}</dl>`;
  document.querySelector("#audit-detail-dialog").showModal();
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelector("#audit-filter-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    auditPage = 1;
    try {
      await refreshAuditList();
    } catch (error) {
      setAuditError(error.message);
    }
  });
  document.querySelector("#audit-clear").addEventListener("click", async () => {
    document.querySelector("#audit-filter-form").reset();
    auditPage = 1;
    try {
      await refreshAuditList();
    } catch (error) {
      setAuditError(error.message);
    }
  });
  document.querySelector("#audit-prev").addEventListener("click", async () => {
    auditPage = Math.max(1, auditPage - 1);
    try {
      await refreshAuditList();
    } catch (error) {
      setAuditError(error.message);
    }
  });
  document.querySelector("#audit-next").addEventListener("click", async () => {
    auditPage = Math.min(auditPageCount, auditPage + 1);
    try {
      await refreshAuditList();
    } catch (error) {
      setAuditError(error.message);
    }
  });
  document.querySelector("#security-audit-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-audit-detail]");
    if (button) showAuditDetails(button.dataset.auditDetail).catch((error) => window.alert(error.message));
  });
  loadAuditDashboard().catch((error) => setAuditError(error.message));
});
