const api = async (url, options = {}) => {
  const method = String(options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(url, { credentials: "same-origin", ...options, headers });
  let body = {};
  try { body = await response.json(); } catch (_) {}
  if (response.status === 401 && !["/api/auth/login", "/api/auth/password"].includes(new URL(url, window.location.origin).pathname)) { window.location.href = "/login"; throw new Error("Authentication required."); }
  if (!response.ok) throw new Error(body.error || "Request could not be completed.");
  return body;
};

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>\"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;" }[character]));
const money = (amount, currency = "INR") => new Intl.NumberFormat("en-IN", { style: "currency", currency, maximumFractionDigits: 2 }).format(Number(amount || 0));
const dateTime = (value) => value ? new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "-";
const showError = (element, message) => { if (element) element.textContent = message || ""; };
const toast = (message) => { const element = $("#toast"); if (!element) return; element.textContent = message; element.classList.add("show"); setTimeout(() => element.classList.remove("show"), 3200); };
let accountCache = [];
const createRequestId = () => {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  if (!globalThis.crypto?.getRandomValues) throw new Error("Secure transfer retry protection is unavailable.");
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

async function loadIdentity() {
  const data = await api("/api/auth/me");
  const name = data.user.name || data.user.username;
  if ($("#user-name")) $("#user-name").textContent = name;
  if ($("#welcome-name")) $("#welcome-name").textContent = name;
  return data.user;
}

async function loadAccounts() {
  const data = await api("/api/users/me/accounts");
  accountCache = data.accounts;
  const list = $("#account-list");
  if (list) list.innerHTML = data.accounts.length ? data.accounts.map((account) => `<article class="account-card"><span class="account-type">${escapeHtml(account.account_type || "Account")}</span><div class="balance">${money(account.balance, account.currency)}</div><div class="account-meta"><span>Account no. ${escapeHtml(account.account_number)}</span><span class="pill ${account.status === "ACTIVE" ? "pill-success" : ""}">${escapeHtml(account.status)}</span></div>${account.status === "ACTIVE" ? `<div class="account-actions"><button class="text-link" type="button" data-deposit-account="${escapeHtml(account.id)}">Add money</button><a class="text-link" href="/transfer?account=${encodeURIComponent(account.id)}">Transfer</a></div>` : ""}</article>`).join("") : `<div class="loading-card">No accounts yet. Create a new account to get started. <button class="button button-primary" type="button" data-create-account>Create New Account</button></div>`;
  const sender = $("#sender-account");
  const available = data.accounts.filter((account) => account.status === "ACTIVE");
  if (sender) {
    const requestedAccount = new URLSearchParams(window.location.search).get("account");
    const previousAccount = sender.value || requestedAccount;
    sender.innerHTML = available.length
      ? `<option value="">Choose an account</option>${available.map((account) => `<option value="${escapeHtml(account.id)}" data-account-number="${escapeHtml(account.account_number)}" data-balance="${escapeHtml(account.balance)}" data-currency="${escapeHtml(account.currency)}">${escapeHtml(account.account_number)} (${escapeHtml(account.account_type)}) - ${money(account.balance, account.currency)}</option>`).join("")}`
      : `<option value="">No active accounts available</option>`;
    if (available.some((account) => account.id === previousAccount)) sender.value = previousAccount;
    updateCurrency();
  }
  const depositAccount = $("#deposit-account");
  if (depositAccount) {
    const active = data.accounts.filter((account) => account.status === "ACTIVE");
    const previousAccount = depositAccount.value;
    depositAccount.innerHTML = active.length
      ? active.map((account) => `<option value="${escapeHtml(account.id)}">${escapeHtml(account.account_number)} (${escapeHtml(account.account_type)})</option>`).join("")
      : `<option value="">No active accounts available</option>`;
    if (active.some((account) => account.id === previousAccount)) depositAccount.value = previousAccount;
    updateDepositBalance();
  }
  document.querySelectorAll("[data-deposit-account]").forEach((button) => button.addEventListener("click", () => {
    if (depositAccount) {
      depositAccount.value = button.dataset.depositAccount;
      updateDepositBalance();
      depositAccount.scrollIntoView({ behavior: "smooth", block: "center" });
      $("#deposit-amount")?.focus();
    }
  }));
  document.querySelectorAll("[data-create-account]").forEach((button) => button.addEventListener("click", createAccount));
  return data.accounts;
}

async function loadRecentTransactions() {
  const data = await api("/api/transactions");
  const list = $("#recent-transactions");
  if (!list) return data.transactions;
  const recent = data.transactions.slice(0, 4);
  if (!recent.length) { list.innerHTML = `<div class="empty-state">No transactions yet.</div>`; return recent; }
  const rows = await Promise.all(recent.map(async (transaction) => { let block = null; try { block = (await api(`/api/transactions/${encodeURIComponent(transaction.transaction_id)}/block`)).block; } catch (_) {} return `<div class="activity-row"><div class="activity-main"><a class="activity-id" href="/transaction/${encodeURIComponent(transaction.transaction_id)}">${escapeHtml(transaction.transaction_id)}</a><div class="activity-date">${escapeHtml(transaction.transaction_type)} · ${dateTime(transaction.created_at)}</div></div><div class="activity-amount">${money(transaction.amount, transaction.currency)}</div><span class="pill ${block ? "pill-success" : ""}">${block ? `Block #${block.block_index}` : "Pending ledger"}</span></div>`; }));
  list.innerHTML = rows.join("");
  return data.transactions;
}

async function initDashboard() {
  await loadIdentity();
  await loadAccounts();
  await loadRecentTransactions();
  $("#create-account-button")?.addEventListener("click", createAccount);
  $("#deposit-account")?.addEventListener("change", updateDepositBalance);
  $("#deposit-form")?.addEventListener("submit", submitDeposit);
}

function updateCurrency() {
  const option = $("#sender-account")?.selectedOptions[0];
  if (option && $("#currency")) $("#currency").value = option.dataset.currency || "INR";
  if ($("#source-balance")) $("#source-balance").textContent = option?.dataset.balance
    ? `Available balance: ${money(option.dataset.balance, option.dataset.currency)}`
    : "Available balance: -";
}

function updateDepositBalance() {
  const account = accountCache.find((item) => item.id === $("#deposit-account")?.value);
  if ($("#deposit-balance")) $("#deposit-balance").textContent = account
    ? `Current balance for ${account.account_number}: ${money(account.balance, account.currency)}`
    : "Current balance: -";
}

async function initTransfer() { await loadIdentity(); await loadAccounts(); $("#sender-account")?.addEventListener("change", updateCurrency); $("#transfer-form")?.addEventListener("submit", submitTransfer); }

async function submitTransfer(event) {
  event.preventDefault(); const form = event.currentTarget; const button = $("#transfer-submit"); const error = $("#form-error"); showError(error, "");
  if (form.dataset.processing === "true") return;
  $("#transfer-result")?.classList.add("hidden");
  const amountText = $("#amount").value.trim(); const amount = Number(amountText); const sender = $("#sender-account").value; const senderAccountNumber = $("#sender-account").selectedOptions[0]?.dataset.accountNumber; const receiver = $("#receiver-account").value.trim();
  if (!sender || !receiver || receiver === senderAccountNumber || !/^[A-Za-z0-9-]{1,32}$/.test(receiver) || !/^\d+(\.\d{1,2})?$/.test(amountText) || !Number.isFinite(amount) || amount <= 0) { showError(error, "Choose an active source account, enter a recipient account number, and use a positive amount with up to two decimal places."); return; }
  button.disabled = true; button.textContent = "Processing...";
  form.dataset.processing = "true";
  try {
    const transfer = { sender_account_id: sender, receiver_account_number: receiver, amount: $("#amount").value, description: form.elements.description.value };
    const requestFingerprint = JSON.stringify(transfer);
    if (form.dataset.requestFingerprint !== requestFingerprint || !form.dataset.idempotencyKey) {
      form.dataset.requestFingerprint = requestFingerprint;
      form.dataset.idempotencyKey = createRequestId();
    }
    const data = await api("/api/transactions", { method: "POST", headers: { "Idempotency-Key": form.dataset.idempotencyKey }, body: JSON.stringify(transfer) });
    renderTransferResult(data.transaction);
    delete form.dataset.requestFingerprint;
    delete form.dataset.idempotencyKey;
    form.reset();
    try {
      await Promise.all([loadAccounts(), loadRecentTransactions()]);
    } catch (refreshError) {
      toast(`Transfer completed, but account activity could not be refreshed: ${refreshError.message}`);
    }
  }
  catch (requestError) { showError(error, requestError.message); }
  finally { delete form.dataset.processing; button.disabled = false; button.textContent = "Transfer money"; }
}

async function initTransactions() {
  await loadIdentity();
  const data = await api("/api/transactions");
  const body = $("#transaction-list");
  if (!data.transactions.length) { body.innerHTML = `<tr><td colspan="10" class="table-message">No transactions yet.</td></tr>`; return; }
  body.innerHTML = `<tr><td colspan="10" class="table-message">Loading ledger status...</td></tr>`;
  const rows = await Promise.all(data.transactions.map(async (transaction) => {
    let block = null;
    try { block = (await api(`/api/transactions/${encodeURIComponent(transaction.transaction_id)}/block`)).block; } catch (_) {}
    return `<tr><td><a class="text-link" href="/transaction/${encodeURIComponent(transaction.transaction_id)}">${escapeHtml(transaction.transaction_id)}</a></td><td>${escapeHtml(transaction.transaction_type)}</td><td>${escapeHtml(transaction.transaction_type === "DEPOSIT" ? "Simulated credit" : transaction.sender_account_number)}</td><td>${escapeHtml(transaction.receiver_account_number)}</td><td>${dateTime(transaction.created_at)}</td><td>${money(transaction.amount, transaction.currency)}</td><td><span class="pill">${escapeHtml(transaction.risk_level || "-")}</span></td><td><div class="security-cell"><strong>${escapeHtml(transaction.algorithm || transaction.security_level || "-")}</strong><small>${transaction.transaction_type === "DEPOSIT" ? "Not applicable" : "Server selected"}</small></div></td><td class="status-completed">${escapeHtml(transaction.status)}</td><td>${block ? `<span class="pill pill-success">#${block.block_index}</span>` : "-"}</td></tr>`;
  }));
  body.innerHTML = rows.join("");
}

async function initDetails() {
  await loadIdentity();
  const id = document.body.dataset.transactionId;
  const title = $("#detail-title");
  const error = $("#detail-error");
  try {
    const transactionData = await api(`/api/transactions/${encodeURIComponent(id)}`);
    if (transactionData.transaction.transaction_type === "DEPOSIT") {
      const blockData = await api(`/api/transactions/${encodeURIComponent(id)}/block`);
      renderDepositDetails(transactionData.transaction, blockData.block);
      return;
    }
    const [securityData, blockData] = await Promise.all([api(`/api/transactions/${encodeURIComponent(id)}/security`), api(`/api/transactions/${encodeURIComponent(id)}/block`)]);
    renderDetails(transactionData.transaction, securityData, blockData.block);
  } catch (requestError) { showError(error, requestError.message); title.textContent = "Transaction unavailable"; $("#transaction-detail").innerHTML = ""; }
}

function renderTransferResult(transaction) { const result = $("#transfer-result"); result.classList.remove("hidden"); result.innerHTML = `<p class="eyebrow">Transfer complete</p><h2>Transfer successful</h2><div class="result-grid"><div class="result-item"><span class="result-label">Amount</span><span class="result-value">${money(transaction.amount, transaction.currency)}</span></div><div class="result-item"><span class="result-label">Risk</span><span class="result-value">${escapeHtml(transaction.risk_level)}</span></div><div class="result-item"><span class="result-label">Algorithm</span><span class="result-value">${escapeHtml(transaction.algorithm)}</span></div><div class="result-item"><span class="result-label">Signature</span><span class="result-value">VERIFIED</span></div><div class="result-item"><span class="result-label">Blockchain</span><span class="result-value">CONFIRMED</span></div><div class="result-item"><span class="result-label">Block</span><span class="result-value">#${escapeHtml(transaction.block_number)}</span></div></div><p class="muted"><a class="text-link" href="/transaction/${encodeURIComponent(transaction.transaction_id)}">View transaction security</a></p>`; result.scrollIntoView({ behavior: "smooth", block: "center" }); }

function renderDetails(transaction, security, block) { $("#detail-title").textContent = transaction.transaction_id; $("#detail-subtitle").textContent = `${money(transaction.amount, transaction.currency)} - ${dateTime(transaction.created_at)}`; $("#transaction-detail").innerHTML = `<article class="detail-card"><p class="eyebrow">Transaction</p><h2>Transfer record</h2><dl class="detail-list"><div><dt>Type</dt><dd>TRANSFER</dd></div><div><dt>Status</dt><dd>${escapeHtml(transaction.status)}</dd></div><div><dt>Currency</dt><dd>${escapeHtml(transaction.currency)}</dd></div><div><dt>Sender account number</dt><dd>${escapeHtml(transaction.sender_account_number)}</dd></div><div><dt>Receiver account number</dt><dd>${escapeHtml(transaction.receiver_account_number)}</dd></div></dl></article><article class="detail-card"><p class="eyebrow">AQRS decision</p><h2>${escapeHtml(security.algorithm)}</h2><dl class="detail-list"><div><dt>Risk level</dt><dd>${escapeHtml(security.risk_level)}</dd></div><div><dt>Selected level</dt><dd>Level ${escapeHtml(security.selected_security_level)}</dd></div><div><dt>AQRS score</dt><dd>${escapeHtml(security.aqrs_score)}</dd></div><div><dt>Decision</dt><dd>${escapeHtml(security.decision_reason)}</dd></div></dl></article><article class="detail-card"><p class="eyebrow">Cryptographic security</p><h2>ML-DSA ${security.verification_status === "VERIFIED" ? "verified" : "status unavailable"}</h2><div class="stage-list"><div class="stage"><span class="check">OK</span> Signature ${escapeHtml(security.verification_status)}</div><div class="stage"><span class="check">OK</span> ${escapeHtml(security.signature_size)} byte signature</div></div></article><article class="detail-card"><p class="eyebrow">Blockchain ledger</p><h2>Block #${escapeHtml(block.block_index)}</h2><dl class="detail-list"><div><dt>Block hash</dt><dd>${escapeHtml(block.block_hash)}</dd></div><div><dt>Previous hash</dt><dd>${escapeHtml(block.previous_hash)}</dd></div><div><dt>Included at</dt><dd>${dateTime(block.timestamp)}</dd></div><div><dt>Ledger status</dt><dd>Confirmed</dd></div></dl></article>`; }

function renderDepositDetails(transaction, block) {
  $("#detail-title").textContent = transaction.transaction_id;
  $("#detail-subtitle").textContent = `${money(transaction.amount, transaction.currency)} · ${dateTime(transaction.created_at)}`;
  $("#transaction-detail").innerHTML = `<article class="detail-card"><p class="eyebrow">Simulated deposit receipt</p><h2>Demo credit</h2><p class="muted">This is a simulated research credit, not an external payment or verified bank deposit.</p><dl class="detail-list"><div><dt>Reference</dt><dd>${escapeHtml(transaction.transaction_id)}</dd></div><div><dt>Status</dt><dd>${escapeHtml(transaction.status)}</dd></div><div><dt>Account number</dt><dd>${escapeHtml(transaction.receiver_account_number)}</dd></div><div><dt>Amount</dt><dd>${money(transaction.amount, transaction.currency)}</dd></div><div><dt>Time</dt><dd>${dateTime(transaction.created_at)}</dd></div><div><dt>Ledger block</dt><dd>#${escapeHtml(block.block_index)}</dd></div><div><dt>Block hash</dt><dd>${escapeHtml(block.block_hash)}</dd></div></dl></article>`;
}

function renderDepositReceipt(transaction) {
  const receipt = $("#deposit-result");
  if (!receipt) return;
  receipt.classList.remove("hidden");
  receipt.innerHTML = `<p class="eyebrow">Simulated deposit receipt</p><h2>Demo credit added</h2><p class="muted">No external payment was made.</p><dl class="detail-list"><div><dt>Account number</dt><dd>${escapeHtml(transaction.account_number)}</dd></div><div><dt>Amount</dt><dd>${money(transaction.amount, transaction.currency)}</dd></div><div><dt>Reference</dt><dd>${escapeHtml(transaction.transaction_id)}</dd></div><div><dt>Time</dt><dd>${dateTime(transaction.created_at)}</dd></div><div><dt>Updated balance</dt><dd>${money(transaction.updated_balance, transaction.currency)}</dd></div><div><dt>Ledger block</dt><dd>#${escapeHtml(transaction.block_number)}</dd></div><div><dt>Block hash</dt><dd>${escapeHtml(transaction.block_hash)}</dd></div></dl>`;
}

async function createAccount(event) {
  const button = event?.currentTarget;
  if (button) { button.disabled = true; button.textContent = "Creating..."; }
  try {
    const data = await api("/api/users/me/accounts", { method: "POST", body: JSON.stringify({ account_type: "SAVINGS" }) });
    toast(`New unfunded account ${data.account.account_number} created.`);
    try { await loadAccounts(); } catch (refreshError) { toast(`Account created, but the account list could not be refreshed: ${refreshError.message}`); }
  } catch (requestError) {
    toast(requestError.message);
  } finally {
    if (button) { button.disabled = false; button.textContent = "Create New Account"; }
  }
}

async function submitDeposit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("#deposit-submit");
  const error = $("#deposit-error");
  showError(error, "");
  if (form.dataset.processing === "true") return;
  const accountId = $("#deposit-account").value;
  const amount = $("#deposit-amount").value.trim();
  if (!accountId || !/^\d+(\.\d{1,2})?$/.test(amount) || Number(amount) <= 0) {
    showError(error, "Choose one of your active accounts and enter a positive amount with up to two decimal places.");
    return;
  }
  const account = accountCache.find((item) => item.id === accountId);
  if (!account || !window.confirm(`Add a simulated demo credit of ${money(amount, account.currency)} to ${account.account_number}? This is not real money.`)) return;
  const deposit = { account_id: accountId, amount };
  const fingerprint = JSON.stringify(deposit);
  if (form.dataset.requestFingerprint !== fingerprint || !form.dataset.idempotencyKey) {
    form.dataset.requestFingerprint = fingerprint;
    form.dataset.idempotencyKey = createRequestId();
  }
  button.disabled = true;
  button.textContent = "Processing...";
  form.dataset.processing = "true";
  try {
    const data = await api("/api/deposits", { method: "POST", headers: { "Idempotency-Key": form.dataset.idempotencyKey }, body: JSON.stringify(deposit) });
    renderDepositReceipt(data.transaction);
    delete form.dataset.requestFingerprint;
    delete form.dataset.idempotencyKey;
    form.reset();
    try {
      await Promise.all([loadAccounts(), loadRecentTransactions()]);
    } catch (refreshError) {
      toast(`Deposit completed, but account activity could not be refreshed: ${refreshError.message}`);
    }
  } catch (requestError) {
    showError(error, requestError.message);
  } finally {
    delete form.dataset.processing;
    button.disabled = false;
    button.textContent = "Add demo money";
  }
}

async function login(event) { event.preventDefault(); const form = event.currentTarget; const error = $("#form-error"); const button = form.querySelector("button"); showError(error, ""); button.disabled = true; button.textContent = "Signing in..."; const identity = form.elements.identity.value.trim(); try { const data = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ email: identity, username: identity, password: form.elements.password.value }) }); const destination = { ADMIN: "/admin", SECURITY_ANALYST: "/research", CUSTOMER: "/dashboard" }[data.user.role] || "/dashboard"; window.location.href = destination; } catch (requestError) { showError(error, requestError.message); button.disabled = false; button.textContent = "Sign in"; } }

async function changePassword(event) { event.preventDefault(); const form = event.currentTarget; const error = $("#password-change-error"); const button = form.querySelector("button"); showError(error, ""); if (form.elements.new_password.value !== form.elements.confirm_password.value) { showError(error, "New password and confirmation do not match."); return; } button.disabled = true; button.textContent = "Updating..."; try { await api("/api/auth/password", { method: "POST", body: JSON.stringify({ current_password: form.elements.current_password.value, new_password: form.elements.new_password.value, confirm_password: form.elements.confirm_password.value }) }); window.location.href = "/login?password_changed=1"; } catch (requestError) { showError(error, requestError.message); button.disabled = false; button.textContent = "Update password"; } }

async function register(event) { event.preventDefault(); const form = event.currentTarget; const error = $("#form-error"); const button = form.querySelector("button"); showError(error, ""); button.disabled = true; button.textContent = "Creating account..."; try { await api("/api/auth/register", { method: "POST", body: JSON.stringify({ name: form.elements.name.value.trim(), username: form.elements.username.value.trim(), email: form.elements.email.value.trim(), password: form.elements.password.value }) }); window.location.href = "/login?registered=1"; } catch (requestError) { showError(error, requestError.message); button.disabled = false; button.textContent = "Create account"; } }

async function logout() { try { await api("/api/auth/logout", { method: "POST" }); window.location.href = "/login"; } catch (_) {} }

function wireAuth() { $("#login-form")?.addEventListener("submit", login); $("#register-form")?.addEventListener("submit", register); if (new URLSearchParams(window.location.search).get("registered")) toast("Account created. Sign in to continue."); }

async function init() { document.querySelectorAll("[data-nav]").forEach((link) => link.classList.toggle("active", link.dataset.nav === document.body.dataset.page)); $("#logout-button")?.addEventListener("click", logout); if (document.body.dataset.page === "login" || document.body.dataset.page === "register") { wireAuth(); return; } if (document.body.dataset.page === "account-security") { loadIdentity().then(() => $("#password-change-form")?.addEventListener("submit", changePassword)).catch((error) => toast(error.message)); return; } try { if (document.body.dataset.page === "dashboard") await initDashboard(); if (document.body.dataset.page === "transfer") await initTransfer(); if (document.body.dataset.page === "transactions") await initTransactions(); if (document.body.dataset.page === "transaction-details") await initDetails(); } catch (error) { toast(error.message); } }

document.addEventListener("DOMContentLoaded", init);
