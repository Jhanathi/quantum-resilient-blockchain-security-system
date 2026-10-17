const labEscape = (value) => String(value ?? "-").replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;",
}[character]));

async function labRequest(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.method && options.method !== "GET") {
    headers["X-CSRF-Token"] = document.querySelector('meta[name="csrf-token"]')?.content || "";
  }
  const response = await fetch(url, { credentials: "same-origin", ...options, headers });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "The demonstration request failed.");
  return body;
}

function renderLabResult(result) {
  const container = document.querySelector(`[data-result-for="${result.scenario_id}"]`);
  if (!container) return;
  const outcome = result.detected ? "Tampering detected" : result.status.replaceAll("_", " ");
  const details = Object.entries(result.details || {}).map(([key, value]) =>
    `<div><dt>${labEscape(key.replaceAll("_", " "))}</dt><dd>${labEscape(typeof value === "object" ? JSON.stringify(value) : value)}</dd></div>`,
  ).join("");
  container.innerHTML = `
    <p class="lab-status lab-status-${labEscape(result.status.toLowerCase().replaceAll("_", "-"))}">${labEscape(outcome)}</p>
    <dl class="lab-result-list">
      <div><dt>Initial validation</dt><dd>${labEscape(result.baseline_status)}</dd></div>
      <div><dt>After tampering</dt><dd>${labEscape(result.post_tampering_status)}</dd></div>
      <div><dt>Tampering detected</dt><dd>${result.detected ? "Yes" : "No"}</dd></div>
      <div><dt>Operation completed</dt><dd>${result.operation_completed ? "Yes" : "No"}</dd></div>
      ${details}
    </dl>
    <p class="lab-explanation">${labEscape(result.explanation)}</p>
    <p class="lab-expected"><strong>Expected:</strong> ${labEscape(result.expected_outcome)}</p>`;
}

function renderLabHistory(history) {
  const container = document.querySelector("#lab-history");
  const records = history || [];
  if (!records.length) {
    container.textContent = "No demonstrations have been run in this process.";
    return;
  }
  container.innerHTML = records.slice(0, 15).map((record) => `
    <div class="lab-history-row">
      <strong>${labEscape(record.name)}</strong>
      <span>${labEscape(record.status)}${record.detected ? " - detected" : ""}</span>
      <time>${labEscape(new Date(record.timestamp).toLocaleString())}</time>
    </div>`).join("");
}

function renderLabSummary(summary) {
  document.querySelector("#lab-detected").textContent = summary.detected;
  document.querySelector("#lab-undetected").textContent = summary.failed_to_detect;
  document.querySelector("#lab-unsupported").textContent = summary.unsupported;
  document.querySelector("#lab-errors").textContent = summary.errored;
}

async function loadLabHistory() {
  const data = await labRequest("/api/security/lab/history");
  data.results.forEach(renderLabResult);
  renderLabSummary(data.summary);
  renderLabHistory(data.history);
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-run-scenario]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Verifying...";
      const scenario = button.dataset.runScenario;
      try {
        const data = await labRequest(`/api/security/lab/run/${encodeURIComponent(scenario)}`, { method: "POST" });
        renderLabResult(data.result);
        renderLabSummary(data.summary);
        renderLabHistory(data.history);
      } catch (error) {
        const result = document.querySelector(`[data-result-for="${scenario}"]`);
        result.textContent = error.message;
      } finally {
        button.disabled = false;
        button.textContent = "Run demonstration";
      }
    });
  });

  document.querySelector("#lab-reset").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const data = await labRequest("/api/security/lab/reset", { method: "POST" });
      document.querySelectorAll("[data-result-for]").forEach((result) => {
        result.textContent = "No result yet. Run this demonstration to validate a fresh baseline and tampered copy.";
      });
      renderLabSummary(data.summary);
      renderLabHistory(data.history);
    } catch (error) {
      window.alert(error.message);
    } finally {
      button.disabled = false;
    }
  });

  loadLabHistory().catch((error) => {
    document.querySelector("#lab-history").textContent = error.message;
  });
});
