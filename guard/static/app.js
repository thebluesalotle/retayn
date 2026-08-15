const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const nativeFetch = window.fetch.bind(window);
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
window.fetch = (input, init = {}) => {
  const requestUrl = new URL(typeof input === "string" ? input : input.url, window.location.href);
  const method = String(init.method || (typeof input !== "string" && input.method) || "GET").toUpperCase();
  if (requestUrl.origin === window.location.origin && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    const headers = new Headers(init.headers || (typeof input !== "string" ? input.headers : undefined));
    headers.set("X-CSRF-Token", csrfToken);
    init = { ...init, headers };
  }
  return nativeFetch(input, init);
};

let lastData = { accounts: [], assets: [], connectors: [], system_categories: [] };
let selectedAccountId = null;
let editingAssetId = null;
let actionBusy = false;
let editingSettings = false;
let recoveryData = { summary: {}, cases: [] };
let selectedRecoveryCaseId = null;
let selectedRecoveryContactId = null;
let recoveryEditing = false;
let recoveryDraftDirty = false;
let recoverySyncingTelegram = false;
let lastTelegramSyncAt = 0;
let evidenceRowId = 0;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function postForm(url, form) {
  const response = await fetch(url, { method: "POST", body: new FormData(form) });
  const payload = await response.json().catch(async () => ({ detail: await response.text().catch(() => "") }));
  if (!response.ok) throw new Error(payload.detail || "Request failed");
  return payload;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(async () => ({ detail: await response.text().catch(() => "") }));
  if (!response.ok) throw new Error(data.detail || "Request failed");
  return data;
}

async function postAction(url) {
  const response = await fetch(url, { method: "POST" });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || "Request failed");
  await loadOverview();
  return payload;
}

function activeEditableElement() {
  const active = document.activeElement;
  return active?.closest?.("input, textarea, select, [contenteditable='true']");
}

function viewIsActive(view) {
  return $(`#${view}View`)?.classList.contains("active");
}

function actionLabel(actionId) {
  const labels = {
    remove_collaborator: "Remove collaborator",
    downgrade_collaborator: "Downgrade promoted user to read",
    downgrade_actor: "Downgrade the appointer to read",
    remove_actor: "Remove the appointer",
    make_private: "Make repository private",
    protect_branch: "Restore branch protection",
    remove_deploy_key: "Remove write deploy key",
    remove_webhook: "Remove webhook",
  };
  return labels[actionId] || "Take supported action";
}

function personName(identity) {
  return identity.email || identity.real_name || identity.name || identity.login || identity.id || "Unknown person";
}

function roleName(connector, identity) {
  if (!identity) return "Unknown";
  if (connector === "slack") {
    if (identity.is_owner) return "Workspace owner";
    if (identity.is_admin) return "Workspace admin";
    if (identity.is_bot) return "Bot account";
    return "Member";
  }
  if (connector === "google_workspace") {
    return identity.is_admin ? "Google admin" : "User";
  }
  if (connector === "zendesk") {
    const role = String(identity.role || "").toLowerCase();
    if (role === "admin") return "Administrator";
    if (role === "agent") return "Agent";
    if (role === "end-user") return "End user";
  }
  if (connector === "airtable") {
    const level = String(identity.permission_level || identity.permissionLevel || "unknown").toLowerCase();
    const labels = {
      read: "Read-only",
      readonly: "Read-only",
      comment: "Commenter",
      commenter: "Commenter",
      edit: "Editor",
      editor: "Editor",
      create: "Creator",
      creator: "Creator",
      owner: "Owner",
    };
    return labels[level.replaceAll("_", "").replaceAll("-", "")] || level.replaceAll("_", " ");
  }
  return identity.role || identity.role_name || "Member";
}

function activeState(identity) {
  if (!identity) return "Unknown";
  if (identity.deleted || identity.suspended || identity.active === false) return "Inactive";
  return "Active";
}

function firstNonEmptyObject(...items) {
  return items.find((item) => item && Object.keys(item).length) || {};
}

function connectorName(account) {
  return account.connector_name || account.connector || "App";
}

function connectorMonogram(account) {
  const name = connectorName(account).replace(/[^A-Za-z0-9 ]/g, " ").trim();
  const words = name.split(/\s+/).filter(Boolean);
  return (words.length > 1 ? `${words[0][0]}${words[1][0]}` : name.slice(0, 2)).toUpperCase() || "AP";
}

function accountName(account) {
  return account.display_name || `${account.owner || ""}/${account.repo || ""}`.replace(/^\/|\/$/g, "");
}

function selectedConnector() {
  return (lastData.connectors || []).find((connector) => connector.id === $("#connectorSelect").value);
}

function connectFormValues() {
  const form = $("#connectForm");
  if (!form) return {};
  return Object.fromEntries(new FormData(form).entries());
}

function renderConnectorFields() {
  const connector = selectedConnector();
  const target = $("#connectorFields");
  const installButton = $("#installAppButton");
  const summary = $("#connectorSummary");
  const values = connectFormValues();
  if (!connector) {
    target.innerHTML = "";
    summary.innerHTML = "";
    installButton.classList.add("hidden");
    return;
  }
  if (connector.coming_soon) {
    target.innerHTML = "";
    summary.innerHTML = `
      <p>${escapeHtml(connector.description || "")}</p>
      <span class="status-pill coming-soon-pill">Coming soon</span>
      <small>This connection is prepared in Retayn, but it is disabled until the remaining provider setup is finished.</small>
    `;
    installButton.textContent = "Coming soon";
    installButton.disabled = true;
    installButton.classList.remove("hidden");
    return;
  }
  installButton.disabled = false;
  target.innerHTML = (connector.fields || []).map((field) => `
    <label>
      <span>${escapeHtml(field.label)}</span>
      <span class="field-with-help">
        <input name="${escapeHtml(field.name)}" type="${field.secret ? "password" : "text"}" autocomplete="off" placeholder="${escapeHtml(field.placeholder || "")}" value="${escapeHtml(values[field.name] || "")}" required />
        <span class="help-icon" tabindex="0" title="${escapeHtml(field.help || field.placeholder || field.label)}" data-tooltip="${escapeHtml(field.help || field.placeholder || field.label)}">?</span>
      </span>
    </label>
  `).join("");
  summary.innerHTML = `
    <p>${escapeHtml(connector.description || "")}</p>
    <div class="capability-list">${(connector.monitoring || []).map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>
    <small>${connector.action_support ? "Retayn can take supported protective actions." : "Monitoring and notifications are available; automatic action is not supported by this provider yet."}</small>
  `;
  installButton.textContent = `Open ${connector.name} install`;
  installButton.classList.toggle("hidden", !connector.install_url);
}

function renderConnectorSelect(connectors) {
  const select = $("#connectorSelect");
  const current = select.value || "github";
  const values = connectFormValues();
  select.innerHTML = connectors.map((connector) => `<option value="${escapeHtml(connector.id)}" ${connector.coming_soon ? "disabled" : ""}>${escapeHtml(connector.name)}${connector.coming_soon ? " (coming soon)" : ""}</option>`).join("");
  const requested = values.connector || current;
  const selectable = connectors.filter((connector) => !connector.coming_soon);
  select.value = selectable.some((connector) => connector.id === requested) ? requested : selectable[0]?.id || "github";
  renderConnectorFields();
}

function supportedActionsFor(event) {
  const details = event.details || {};
  if (Array.isArray(details.supported_actions) && details.supported_actions.length) {
    return details.supported_actions;
  }
  if (details.supported_action) {
    return [{ id: details.supported_action, label: actionLabel(details.supported_action) }];
  }
  return [];
}

function setButtonLoading(button, label = "Working...") {
  button.dataset.originalText = button.textContent;
  button.textContent = label;
  button.classList.add("loading");
  $$(".actions button:not(:disabled)").forEach((item) => {
    item.dataset.busyDisabled = "true";
    item.disabled = true;
  });
}

function clearButtonLoading(button) {
  button.classList.remove("loading");
  if (button.dataset.originalText) button.textContent = button.dataset.originalText;
  $$("[data-busy-disabled='true']").forEach((item) => {
    item.disabled = false;
    delete item.dataset.busyDisabled;
  });
}

async function confirmAndPost(event, url, message, busyLabel = "Working...") {
  const button = event.currentTarget;
  if (actionBusy || !confirm(message)) return;
  actionBusy = true;
  setButtonLoading(button, busyLabel);
  try {
    await postAction(url);
  } catch (error) {
    alert(error.message);
  } finally {
    actionBusy = false;
    clearButtonLoading(button);
  }
}

function setView(view) {
  if (view !== "apps") editingSettings = false;
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `${view}View`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  const pageMeta = {
    overview: ["Command center", "Monitoring overview"],
    recover: ["Restore control", "Recover"],
    protection: ["Business continuity", "Protection map"],
    apps: ["Connected services", "My apps"],
    connect: ["Secure a new system", "Connect an app"],
  };
  const [kicker, title] = pageMeta[view] || ["Retayn Guard", "Monitoring"];
  $("#pageKicker").textContent = kicker;
  $("#pageTitle").textContent = title;
  if (window.location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`);
  document.body.classList.remove("nav-open");
  $("#menuButton").setAttribute("aria-expanded", "false");
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (view === "recover") {
    loadRecovery();
    syncTelegramRecoveryQuiet();
  }
}

function recoveryStatusLabel(status) {
  const labels = {
    draft: "Building case",
    message_review: "Message review",
    outreach_active: "Outreach active",
    needs_owner: "Needs your input",
    action_required: "Handoff ready",
    recovered: "Recovered",
    closed: "Closed",
    queued: "Ready",
    contacted: "Contacted",
    responded: "Responded",
    needs_info: "Needs proof",
    success: "Handoff ready",
    waiting_setup: "Channel setup needed",
    manual_required: "Manual contact",
    failed: "Delivery failed",
    sent: "Sent",
    received: "Received",
    proof_request: "Proof requested",
    proof_response: "Proof reply",
    case_closure: "Closing message",
  };
  return labels[status] || String(status || "unknown").replaceAll("_", " ");
}

function recoveryContactRow(index = Date.now()) {
  return `
    <div class="recovery-contact-row" data-contact-row="${index}">
      <div class="contact-row-head"><strong>Recovery contact</strong><button type="button" class="remove-contact-button" onclick="removeRecoveryContact(this)" aria-label="Remove contact">&times;</button></div>
      <div class="recovery-fields two-column">
        <label>Name or support team<input name="contact_name" placeholder="Developer, agency, Apple Support..." required /></label>
        <label>Role<input name="contact_role" placeholder="Developer, account manager, support" /></label>
        <label>Organization<input name="contact_organization" placeholder="Company or platform" /></label>
        <label>Contact channel
          <select name="contact_channel" required>
            <option value="email">Support email</option>
            <option value="telegram">Telegram username or chat</option>
            <option value="whatsapp">WhatsApp</option>
            <option value="support_portal">Support portal</option>
            <option value="phone">Phone</option>
            <option value="other">Other</option>
          </select>
        </label>
        <label class="full-field">Email, phone, Telegram username, Telegram chat, WhatsApp number, or support URL<input name="contact_address" required /></label>
        <label class="full-field">What does this person control or know?<textarea name="contact_notes" rows="3"></textarea></label>
      </div>
    </div>
  `;
}

function addRecoveryContact() {
  $("#recoveryContacts").insertAdjacentHTML("beforeend", recoveryContactRow());
}

function removeRecoveryContact(button) {
  const rows = $$("#recoveryContacts .recovery-contact-row");
  if (rows.length <= 1) {
    alert("A recovery case needs at least one contact.");
    return;
  }
  button.closest(".recovery-contact-row").remove();
}

function evidenceFileRow() {
  evidenceRowId += 1;
  const inputId = `evidenceFile${evidenceRowId}`;
  return `
    <div class="evidence-file-row">
      <label class="evidence-description">
        <span>File description</span>
        <input name="evidence_label" maxlength="240" placeholder="Contract for when I hired the developer" />
      </label>
      <div class="file-picker">
        <input id="${inputId}" name="evidence_files" type="file" onchange="updateFilePickerLabel(this)" />
        <label for="${inputId}" class="file-picker-button">Choose file</label>
        <span class="file-picker-name">No file selected</span>
      </div>
      <button type="button" class="quiet-button remove-file-row" title="Remove file" onclick="removeEvidenceFileRow(this)">Remove</button>
    </div>
  `;
}

function addEvidenceFileRow(targetSelector = "#recoveryEvidenceFiles", required = false) {
  const target = $(targetSelector);
  if (!target) return;
  target.insertAdjacentHTML("beforeend", evidenceFileRow(required));
}

function addEvidenceFileRowForButton(button, required = false) {
  const target = button.closest("form")?.querySelector("[data-evidence-upload-rows]") || button.closest("form")?.querySelector(".evidence-file-rows");
  if (!target) return;
  target.insertAdjacentHTML("beforeend", evidenceFileRow(required));
}

function ensureEvidenceUploadRows(details) {
  if (!details.open) return;
  const target = details.querySelector("[data-evidence-upload-rows]");
  if (target && !target.children.length) {
    target.insertAdjacentHTML("beforeend", evidenceFileRow(true));
  }
}

function removeEvidenceFileRow(button) {
  const row = button.closest(".evidence-file-row");
  const group = row?.parentElement;
  if (!row || !group) return;
  if (group.querySelectorAll(".evidence-file-row").length <= 1) {
    row.querySelectorAll("input").forEach((input) => {
      input.value = "";
      if (input.type === "file") updateFilePickerLabel(input);
    });
    return;
  }
  row.remove();
}

function updateFilePickerLabel(input) {
  const label = input.closest(".file-picker")?.querySelector(".file-picker-name");
  if (!label) return;
  label.textContent = input.files?.length ? input.files[0].name : "No file selected";
}

function formDataWithEvidenceRows(form) {
  const formData = new FormData(form);
  formData.delete("evidence_label");
  formData.delete("evidence_files");
  form.querySelectorAll(".evidence-file-row").forEach((row) => {
    const fileInput = row.querySelector("input[type='file'][name='evidence_files']");
    const labelInput = row.querySelector("input[name='evidence_label']");
    if (!fileInput?.files?.length) return;
    formData.append("evidence_label", labelInput?.value || "");
    formData.append("evidence_files", fileInput.files[0]);
  });
  return formData;
}

function showRecoveryIntake(reset = true) {
  $("#recoveryEmpty").classList.add("hidden");
  $("#recoveryCaseDetail").classList.add("hidden");
  $("#recoveryIntake").classList.remove("hidden");
  if (reset) {
    $("#recoveryCaseForm").reset();
    $("#recoveryContacts").innerHTML = recoveryContactRow(1);
    $("#recoveryEvidenceFiles").innerHTML = evidenceFileRow();
    $("#recoveryFormNote").textContent = "";
  }
  recoveryEditing = true;
}

function hideRecoveryIntake() {
  recoveryEditing = false;
  $("#recoveryIntake").classList.add("hidden");
  if (selectedRecoveryCaseId) {
    $("#recoveryCaseDetail").classList.remove("hidden");
  } else {
    $("#recoveryEmpty").classList.remove("hidden");
  }
}

function renderRecoveryCaseList(cases) {
  const target = $("#recoveryCaseList");
  if (!cases.length) {
    target.innerHTML = '<p class="empty">No recovery cases yet.</p>';
    return;
  }
  target.innerHTML = cases.map((item) => `
    <button type="button" class="recovery-case-row ${item.id === selectedRecoveryCaseId ? "active" : ""}" onclick="selectRecoveryCase(${item.id})">
      <span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.platform_name)} &middot; ${item.contact_count} contacts</small></span>
      <span class="recovery-case-status ${escapeHtml(item.status)}">${escapeHtml(recoveryStatusLabel(item.status))}</span>
    </button>
  `).join("");
}

function recoveryFilesMarkup(files, source = null) {
  const filtered = source ? (files || []).filter((item) => item.source === source) : (files || []);
  if (!filtered.length) return '<p class="empty compact-empty">No files recorded.</p>';
  return filtered.map((item) => `
    <a class="recovery-file" href="/api/recovery/files/${item.id}/download">
      <span><strong>${escapeHtml(item.label || item.original_name)}</strong><small>${escapeHtml(item.original_name)} &middot; ${Math.max(1, Math.round((item.size_bytes || 0) / 1024))} KB</small></span>
      <span aria-hidden="true">&#8595;</span>
    </a>
  `).join("");
}

function recoveryMessageMarkup(message) {
  const outbound = message.direction === "outbound";
  return `
    <article class="recovery-message ${outbound ? "outbound" : "inbound"}">
      <div class="message-meta"><strong>${outbound ? (message.sender_type === "owner" ? "You" : "Retayn agent") : "Contact"}</strong><span>${escapeHtml(message.created_at)}</span></div>
      <p>${escapeHtml(message.body)}</p>
      ${(message.files || []).length ? `<div class="message-files">${recoveryFilesMarkup(message.files)}</div>` : ""}
      <div class="message-state">
        ${message.classification ? `<span>${escapeHtml(recoveryStatusLabel(message.classification))}</span>` : ""}
        <span>${escapeHtml(recoveryStatusLabel(message.status))}</span>
      </div>
      ${message.delivery_note ? `<p class="delivery-note">${escapeHtml(message.delivery_note)}</p>` : ""}
      ${["draft", "waiting_setup", "failed", "manual_required"].includes(message.status) ? `<button type="button" onclick="approveRecoveryMessage(event, ${message.id})">${message.status === "draft" ? "Review complete, send this reply" : "Try sending again"}</button>` : ""}
    </article>
  `;
}

function recoveryConversationMarkup(caseItem, contact) {
  if (!contact) return '<div class="conversation-empty"><p>Select a contact to see the conversation.</p></div>';
  const messages = contact.messages || [];
  return `
    <div class="conversation-head">
      <div><span class="section-label">${escapeHtml(contact.channel)}</span><h3>${escapeHtml(contact.name)}</h3><p>${escapeHtml(contact.organization || contact.address)}</p></div>
      <span class="status-pill ${["needs_info", "failed"].includes(contact.status) ? "danger" : ""}">${escapeHtml(recoveryStatusLabel(contact.status))}</span>
    </div>
    <div class="conversation-timeline">${messages.length ? messages.map(recoveryMessageMarkup).join("") : '<p class="empty">No messages recorded yet.</p>'}</div>
    <form class="conversation-compose" onsubmit="sendRecoveryReply(event, ${contact.id})">
      <label>Send a reviewed reply<textarea name="message" rows="4" placeholder="Write a factual reply..."></textarea></label>
      <button type="submit">Send reply</button>
    </form>
    <details class="manual-response">
      <summary>Record a reply received outside Retayn</summary>
      <form onsubmit="recordRecoveryResponse(event, ${contact.id})">
        <label>Contact's response<textarea name="body" rows="4"></textarea></label>
        <label>Files they sent<input name="response_files" type="file" multiple /></label>
        <button type="submit" class="secondary">Add response to conversation</button>
      </form>
    </details>
  `;
}

function renderRecoveryCase(caseItem) {
  selectedRecoveryCaseId = caseItem.id;
  if (!selectedRecoveryContactId || !(caseItem.contacts || []).some((item) => item.id === selectedRecoveryContactId)) {
    selectedRecoveryContactId = caseItem.contacts?.[0]?.id || null;
  }
  const activeContact = (caseItem.contacts || []).find((item) => item.id === selectedRecoveryContactId);
  const reviewable = ["draft", "message_review"].includes(caseItem.status);
  const outreachStarted = !reviewable;
  const caseClosed = ["recovered", "closed"].includes(caseItem.status);
  const headerActions = `
    <span class="status-pill ${caseItem.status === "needs_owner" ? "danger" : ""}">${escapeHtml(recoveryStatusLabel(caseItem.status))}</span>
    ${outreachStarted && !caseClosed ? `<button type="button" class="secondary" onclick="completeRecoveryCase(${caseItem.id})">Mark recovered</button>` : ""}
    ${!caseClosed ? `<button type="button" class="secondary-danger" onclick="cancelRecoveryCase(${caseItem.id})">Cancel case</button>` : ""}
  `;
  $("#recoveryIntake").classList.add("hidden");
  $("#recoveryEmpty").classList.add("hidden");
  const target = $("#recoveryCaseDetail");
  target.classList.remove("hidden");
  target.innerHTML = `
    <section class="panel recovery-case-header">
      <div><span class="section-label">${escapeHtml(caseItem.platform_name)}</span><h2>${escapeHtml(caseItem.title)}</h2><p>${escapeHtml(caseItem.asset_type)} &middot; opened ${escapeHtml(caseItem.created_at)}</p></div>
      <div class="case-header-actions">${headerActions}</div>
    </section>

    <section class="recovery-case-grid">
      <section class="panel recovery-draft-panel">
        <div class="panel-head"><div><span class="section-label">Owner-approved outreach</span><h2>First message</h2></div><span class="truth-badge">Fact locked</span></div>
        <textarea id="recoveryDraftMessage" rows="13" ${reviewable ? "" : "disabled"}>${escapeHtml(caseItem.draft_message || "")}</textarea>
        <p class="draft-help">The AI draft is checked against this case. Edit anything you want before approval. Retayn will never start outreach without the button below.</p>
        ${reviewable ? `<div class="actions"><button type="button" onclick="saveRecoveryDraft(event, ${caseItem.id})">Save changes</button><button type="button" class="secondary" onclick="regenerateRecoveryDraft(event, ${caseItem.id})">Regenerate from case facts</button><button type="button" class="safe" onclick="approveRecoveryOutreach(event, ${caseItem.id})">Approve and start outreach</button></div>` : `<div class="approved-banner"><span></span>Approved message locked after outreach began.</div>`}
      </section>
      <aside class="panel recovery-facts-panel">
        <div class="panel-head"><div><span class="section-label">Case record</span><h2>Known facts</h2></div></div>
        <dl class="recovery-facts">
          <div><dt>Owner</dt><dd>${escapeHtml(caseItem.owner_name)}</dd></div>
          <div><dt>Business</dt><dd>${escapeHtml(caseItem.business_name || "Not provided")}</dd></div>
          <div><dt>Account</dt><dd>${escapeHtml(caseItem.account_identifier || "Not provided")}</dd></div>
          <div><dt>Goal</dt><dd>${escapeHtml(caseItem.recovery_goal)}</dd></div>
          <div><dt>Lockout</dt><dd>${escapeHtml(caseItem.lockout_story)}</dd></div>
          <div><dt>Proof described</dt><dd>${escapeHtml(caseItem.ownership_proof || "None described")}</dd></div>
        </dl>
      </aside>
    </section>

    <section class="panel recovery-evidence-panel">
      <div class="panel-head"><div><span class="section-label">Evidence locker</span><h2>Owner documents and received files</h2></div><span class="status-pill">${(caseItem.files || []).length} files</span></div>
      <div class="recovery-files">${recoveryFilesMarkup(caseItem.files)}</div>
      <details class="evidence-upload" ontoggle="ensureEvidenceUploadRows(this)"><summary>Add more ownership evidence</summary><form onsubmit="uploadRecoveryEvidence(event, ${caseItem.id})"><div class="evidence-file-rows" data-evidence-upload-rows></div><div class="actions"><button type="button" class="secondary" onclick="addEvidenceFileRowForButton(this, true)"><span aria-hidden="true">+</span> Add file</button><button type="submit">Upload evidence</button></div></form></details>
    </section>

    <section class="recovery-conversation-layout">
      <aside class="panel recovery-contacts-panel">
        <div class="panel-head"><div><span class="section-label">Outreach map</span><h2>Contacts</h2></div><span class="status-pill">${(caseItem.contacts || []).length}</span></div>
        <div class="recovery-contact-list">${(caseItem.contacts || []).map((contact) => `
          <button type="button" class="recovery-contact-button ${contact.id === selectedRecoveryContactId ? "active" : ""}" onclick="selectRecoveryContact(${contact.id})">
            <span><strong>${escapeHtml(contact.name)}</strong><small>${escapeHtml(contact.organization || contact.channel)} &middot; ${escapeHtml(contact.address)}</small></span>
            <span class="contact-status-dot ${escapeHtml(contact.status)}" title="${escapeHtml(recoveryStatusLabel(contact.status))}"></span>
          </button>`).join("")}</div>
      </aside>
      <section class="panel recovery-conversation">${recoveryConversationMarkup(caseItem, activeContact)}</section>
    </section>
  `;
  const draftBox = $("#recoveryDraftMessage");
  if (draftBox) {
    draftBox.addEventListener("input", () => {
      recoveryDraftDirty = true;
      recoveryEditing = true;
    });
  }
  $$("#recoveryCaseDetail textarea, #recoveryCaseDetail input, #recoveryCaseDetail select").forEach((input) => {
    input.addEventListener("focus", () => {
      recoveryEditing = true;
    });
    input.addEventListener("input", () => {
      recoveryEditing = true;
    });
    input.addEventListener("blur", () => {
      recoveryEditing = false;
    });
  });
  renderRecoveryCaseList(recoveryData.cases || []);
}

async function loadRecoveryCase(caseId) {
  const response = await fetch(`/api/recovery/cases/${caseId}`);
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "Could not load recovery case.");
  renderRecoveryCase(data);
}

async function loadRecovery() {
  if (recoveryEditing || recoveryDraftDirty || activeEditableElement()?.closest?.("#recoverView")) return;
  try {
    const response = await fetch("/api/recovery");
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Could not load recovery cases.");
    recoveryData = data;
    $("#recoveryTotal").textContent = data.summary.total || 0;
    $("#recoveryActive").textContent = data.summary.active || 0;
    $("#recoveryNeedsOwner").textContent = data.summary.needs_owner || 0;
    $("#recoveryComplete").textContent = data.summary.recovered || 0;
    renderRecoveryCaseList(data.cases || []);
    if (selectedRecoveryCaseId && (data.cases || []).some((item) => item.id === selectedRecoveryCaseId)) {
      await loadRecoveryCase(selectedRecoveryCaseId);
    } else if ((data.cases || []).length) {
      selectedRecoveryCaseId = data.cases[0].id;
      await loadRecoveryCase(selectedRecoveryCaseId);
    } else {
      selectedRecoveryCaseId = null;
      $("#recoveryCaseDetail").classList.add("hidden");
      $("#recoveryEmpty").classList.remove("hidden");
    }
  } catch (error) {
    $("#recoveryCaseList").innerHTML = `<p class="empty">${escapeHtml(error.message)}</p>`;
  }
}

async function selectRecoveryCase(caseId) {
  recoveryEditing = false;
  recoveryDraftDirty = false;
  selectedRecoveryCaseId = caseId;
  selectedRecoveryContactId = null;
  await loadRecoveryCase(caseId);
}

async function selectRecoveryContact(contactId) {
  selectedRecoveryContactId = contactId;
  if (selectedRecoveryCaseId) await loadRecoveryCase(selectedRecoveryCaseId);
}

async function syncTelegramRecovery(event) {
  const button = event.currentTarget;
  setButtonLoading(button, "Syncing...");
  $("#telegramSyncNote").textContent = "Checking the recovery Telegram account...";
  try {
    const response = await fetch("/api/recovery/telegram/sync", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "Telegram sync failed.");
    $("#telegramSyncNote").textContent = payload.message || `Synced ${payload.synced || 0} Telegram message(s).`;
    await loadRecovery();
    await loadOverview();
  } catch (error) {
    $("#telegramSyncNote").textContent = error.message;
  } finally {
    clearButtonLoading(button);
  }
}

async function syncTelegramRecoveryQuiet(force = false) {
  if (recoverySyncingTelegram || !viewIsActive("recover") || recoveryEditing || recoveryDraftDirty || activeEditableElement()?.closest?.("#recoverView")) return;
  const now = Date.now();
  if (!force && now - lastTelegramSyncAt < 25000) return;
  recoverySyncingTelegram = true;
  lastTelegramSyncAt = now;
  try {
    const response = await fetch("/api/recovery/telegram/sync", { method: "POST" });
    const payload = await response.json().catch(() => ({}));
    if (response.ok && Number(payload.synced || 0) > 0) {
      await loadRecovery();
      await loadOverview();
    }
  } catch (error) {
    console.debug("Telegram recovery sync skipped", error);
  } finally {
    recoverySyncingTelegram = false;
  }
}

async function refreshRecoveryCaseFromResponse(response) {
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "Recovery request failed.");
  recoveryEditing = false;
  recoveryDraftDirty = false;
  selectedRecoveryCaseId = data.id;
  await loadRecovery();
  return data;
}

async function saveRecoveryDraft(event, caseId) {
  const button = event.currentTarget;
  setButtonLoading(button, "Saving...");
  recoveryEditing = true;
  try {
    const message = $("#recoveryDraftMessage").value;
    const response = await fetch(`/api/recovery/cases/${caseId}/draft`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Could not save the recovery message.");
    recoveryEditing = false;
    recoveryDraftDirty = false;
    selectedRecoveryCaseId = data.id;
    recoveryData.cases = (recoveryData.cases || []).map((item) => (item.id === data.id ? { ...item, ...data } : item));
    renderRecoveryCase(data);
  } catch (error) {
    alert(error.message);
  } finally {
    clearButtonLoading(button);
  }
}

async function regenerateRecoveryDraft(event, caseId) {
  if (!confirm("Regenerate the first message from the facts currently saved in this case? Your edits will be replaced.")) return;
  const button = event.currentTarget;
  setButtonLoading(button, "Drafting...");
  try {
    const response = await fetch(`/api/recovery/cases/${caseId}/regenerate`, { method: "POST" });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  } finally {
    clearButtonLoading(button);
  }
}

async function approveRecoveryOutreach(event, caseId) {
  if (!confirm("Start recovery outreach now? Retayn will send the approved message through every configured channel. Channels without working credentials will be marked for setup or manual contact.")) return;
  const button = event.currentTarget;
  setButtonLoading(button, "Starting outreach...");
  try {
    const saveResponse = await fetch(`/api/recovery/cases/${caseId}/draft`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: $("#recoveryDraftMessage").value }),
    });
    if (!saveResponse.ok) {
      const error = await saveResponse.json();
      throw new Error(error.detail || "Could not save the approved message.");
    }
    const response = await fetch(`/api/recovery/cases/${caseId}/approve`, { method: "POST" });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  } finally {
    clearButtonLoading(button);
  }
}

async function uploadRecoveryEvidence(event, caseId) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type='submit']");
  setButtonLoading(button, "Uploading...");
  try {
    const response = await fetch(`/api/recovery/cases/${caseId}/evidence`, { method: "POST", body: formDataWithEvidenceRows(form) });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  } finally {
    clearButtonLoading(button);
  }
}

async function recordRecoveryResponse(event, contactId) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type='submit']");
  setButtonLoading(button, "Analyzing response...");
  try {
    const response = await fetch(`/api/recovery/contacts/${contactId}/responses`, { method: "POST", body: new FormData(form) });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  } finally {
    clearButtonLoading(button);
  }
}

async function sendRecoveryReply(event, contactId) {
  event.preventDefault();
  const form = event.currentTarget;
  const message = form.message.value.trim();
  if (!message || !confirm("Send this reviewed reply to the recovery contact now?")) return;
  const button = form.querySelector("button[type='submit']");
  setButtonLoading(button, "Sending...");
  try {
    const response = await fetch(`/api/recovery/contacts/${contactId}/reply`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  } finally {
    clearButtonLoading(button);
  }
}

async function approveRecoveryMessage(event, messageId) {
  if (!confirm("Send this evidence response now? Review the text and the evidence locker before continuing.")) return;
  const button = event.currentTarget;
  setButtonLoading(button, "Sending...");
  try {
    const response = await fetch(`/api/recovery/messages/${messageId}/send`, { method: "POST" });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  } finally {
    clearButtonLoading(button);
  }
}

async function completeRecoveryCase(caseId) {
  if (!confirm("Mark this recovery case as completed? The conversation and files will remain available.")) return;
  try {
    const response = await fetch(`/api/recovery/cases/${caseId}/complete`, { method: "POST" });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  }
}

async function cancelRecoveryCase(caseId) {
  if (!confirm("Cancel this recovery case? Retayn will close the case and draft a closing response for contacts already involved.")) return;
  const reason = prompt("Why are you closing this recovery case? For example: I got access back, I no longer need help, or this was opened by mistake.");
  if (reason === null) return;
  if (!reason.trim()) {
    alert("Add a short reason before closing the case.");
    return;
  }
  try {
    const response = await fetch(`/api/recovery/cases/${caseId}/cancel`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    await refreshRecoveryCaseFromResponse(response);
  } catch (error) {
    alert(error.message);
  }
}

function renderAccounts(accounts) {
  const target = $("#accountsList");
  if (!accounts.length) {
    target.innerHTML = '<p class="empty">No apps connected yet.</p>';
    return;
  }
  target.innerHTML = accounts.map((account) => `
    <div class="account-row">
      <span class="account-provider" aria-hidden="true">${escapeHtml(connectorMonogram(account))}</span>
      <div class="account-main">
        <strong>${escapeHtml(accountName(account))}</strong>
        <small>${escapeHtml(connectorName(account))} &middot; ${escapeHtml(account.status)}</small>
      </div>
      <span class="connection-dot ${account.status === "error" ? "error" : ""}" title="${escapeHtml(account.status)}"></span>
    </div>
  `).join("");
}

function renderManageApps(accounts) {
  const target = $("#manageAppsList");
  if (!accounts.length) {
    target.innerHTML = '<p class="empty">No connected apps yet.</p>';
    $("#appDetail").classList.add("hidden");
    return;
  }
  target.innerHTML = accounts.map((account) => `
    <button class="manage-row ${account.id === selectedAccountId ? "active" : ""}" onclick="selectAccount(${account.id})">
      <span class="manage-app-copy"><strong>${escapeHtml(accountName(account))}</strong><small>${escapeHtml(connectorName(account))}</small></span>
      <small class="manage-status">${escapeHtml(account.status)}</small>
    </button>
  `).join("");
  if (!selectedAccountId || !accounts.some((account) => account.id === selectedAccountId)) {
    selectedAccountId = accounts[0].id;
  }
  renderAccountDetail(accounts.find((account) => account.id === selectedAccountId));
}

function renderAccountDetail(account) {
  const target = $("#appDetail");
  if (!account) {
    target.classList.add("hidden");
    return;
  }
  target.classList.remove("hidden");
  const settings = account.settings || {};
  const baseline = account.baseline || {};
  const allowedPeople = account.connector === "github" ? (settings.github_allowed_users || []) : (settings.allowed_identities || []);
  const monitoringList = (account.monitoring || []).map((item) => `<span>${escapeHtml(item)}</span>`).join("");
  const lastScan = baseline.last_scan || {};
  target.innerHTML = `
    <div class="panel-head">
      <h2>${escapeHtml(accountName(account))}</h2>
      <span class="status-pill ${account.status === "error" ? "danger" : ""}">${escapeHtml(account.status)}</span>
    </div>
    <div class="monitoring-summary">
      <div><strong>${escapeHtml(connectorName(account))}</strong><div class="capability-list">${monitoringList || "Connection health"}</div></div>
      <small>Last check: ${escapeHtml(lastScan.at || account.updated_at || "Not yet checked")}</small>
    </div>
    <form class="inline-form ${account.connector === "github" ? "" : "hidden"}" onsubmit="editAccount(event, ${account.id})">
      <input name="repo" value="${escapeHtml(`${account.owner}/${account.repo}`)}" required />
      <button type="submit" class="secondary">Save</button>
    </form>
    <form class="settings-grid app-settings-form" onsubmit="saveAccountSettings(event, ${account.id})">
      <label class="toggle-label"><input name="auto_action_enabled" type="checkbox" ${settings.auto_action_enabled ? "checked" : ""} /> Take supported action if untouched</label>
      <label class="toggle-label"><input name="windows_notifications" type="checkbox" ${settings.windows_notifications ? "checked" : ""} /> Windows notifications</label>
      <label>Untouched delay, minutes<input name="auto_action_delay_minutes" type="number" min="1" step="1" value="${escapeHtml(settings.auto_action_delay_minutes || 30)}" /></label>
      <label>Polling interval, seconds<input name="monitoring_poll_seconds" type="number" min="10" step="5" value="${escapeHtml(settings.monitoring_poll_seconds || settings.github_poll_seconds || 30)}" /></label>
      <label>Allowed people or accounts<textarea name="allowed_identities" rows="5">${escapeHtml(allowedPeople.join("\n"))}</textarea></label>
      <label class="${account.connector === "github" ? "" : "hidden"}">Allowed webhook URLs<textarea name="github_allowed_hook_urls" rows="5">${escapeHtml((settings.github_allowed_hook_urls || []).join("\n"))}</textarea></label>
      <label class="${account.connector === "github" ? "" : "hidden"}">Allowed write deploy key titles<textarea name="github_allowed_write_deploy_keys" rows="4">${escapeHtml((settings.github_allowed_write_deploy_keys || []).join("\n"))}</textarea></label>
      <div class="settings-actions">
        <button type="submit">Save settings</button>
        <button type="button" class="secondary" onclick="refreshAccount(${account.id})">Refresh baseline</button>
        <span class="tooltip-wrap backup-soon" data-tooltip="Backup is coming soon for connected apps. For now, Retayn monitors and records changes.">
          <button type="button" class="secondary" disabled>Backup coming soon</button>
        </span>
        <button type="button" class="danger" onclick="deleteAccount(event, ${account.id})">Delete</button>
      </div>
    </form>
    ${renderBaseline(account)}
  `;
  const settingsForm = target.querySelector(".app-settings-form");
  settingsForm.addEventListener("focusin", () => {
    editingSettings = true;
  });
  settingsForm.addEventListener("input", () => {
    editingSettings = true;
  });
}

function renderBaseline(account) {
  const baseline = account.baseline || {};
  if (account.connector === "github") {
    return `
      <div class="baseline-grid">
      <div><strong>Baseline users</strong><pre>${escapeHtml((baseline.users || []).map((item) => `${item.login} (${item.role_name || "unknown"})`).join("\n") || "None")}</pre></div>
      <div><strong>Baseline webhooks</strong><pre>${escapeHtml((baseline.webhooks || []).map((item) => item.url || item.id).join("\n") || "None")}</pre></div>
      <div><strong>Write deploy keys</strong><pre>${escapeHtml((baseline.write_deploy_keys || []).map((item) => item.title || item.id).join("\n") || "None")}</pre></div>
      </div>
    `;
  }
  const users = baseline.workspace_users || [];
  const workspaceDetails = firstNonEmptyObject(baseline.workspace, baseline.shop, baseline.account, baseline.base);
  const tables = baseline.tables || [];
  const access = baseline.access || [];
  return `
    <div class="baseline-grid">
      <div><strong>Workspace or account</strong><pre>${escapeHtml(Object.entries(workspaceDetails).map(([key, value]) => `${key}: ${value}`).join("\n") || "Connected")}</pre></div>
      <div><strong>Baseline users</strong><pre>${escapeHtml(users.map((item) => {
        const label = item.email || item.real_name || item.name || item.id;
        const access = roleName(account.connector, item);
        const source = item.source ? ` via ${item.source}` : "";
        return `${label} (${access}${source})`;
      }).join("\n") || "None exposed by this API")}</pre></div>
      <div><strong>Resources</strong><pre>${escapeHtml(tables.map((item) => `${item.name} (${(item.fields || []).length} fields)`).join("\n") || access.map((item) => `${item.name}: ${item.status}`).join("\n") || "None")}</pre></div>
    </div>
  `;
}

function selectAccount(accountId) {
  editingSettings = false;
  selectedAccountId = accountId;
  renderManageApps(lastData.accounts || []);
}

function detailsFor(event) {
  const details = event.details || {};
  if (event.event_type === "new_collaborator") {
    const collab = details.collaborator || {};
    const actor = details.appointed_by || {};
    return { title: "Collaborator details", lines: [`User: ${collab.login || "unknown"}`, `Role: ${collab.role_name || "unknown"}`, `Type: ${collab.type || "unknown"}`, `Added by: ${actor.login || "unknown"}`] };
  }
  if (event.event_type === "role_escalation") {
    const actor = details.appointed_by || {};
    return { title: "Permission change", lines: [`User: ${(details.after || {}).login || "unknown"}`, `Before: ${(details.before || {}).role_name || "unknown"}`, `After: ${(details.after || {}).role_name || "unknown"}`, `Appointed by: ${actor.login || "unknown"}`] };
  }
  if (event.event_type === "branch_protection_removed") return { title: "Branch protection", lines: [`Branch: ${details.branch || "unknown"}`] };
  if (event.event_type === "write_deploy_key") {
    const key = details.deploy_key || {};
    return { title: "Deploy key", lines: [`Title: ${key.title || "unknown"}`, `Read-only: ${key.read_only ? "yes" : "no"}`] };
  }
  if (event.event_type === "new_webhook") {
    const hook = details.webhook || {};
    return { title: "Webhook", lines: [`URL: ${hook.url || "unknown"}`, `Events: ${(hook.events || []).join(", ")}`] };
  }
  if (event.event_type === "webhooks_inaccessible") {
    const error = details.github_error || {};
    return { title: "GitHub permission response", lines: [`Reason: ${error.reason || details.reason || "unknown"}`, `Required by GitHub: ${error.accepted_github_permissions || "not provided"}`] };
  }
  if (event.event_type === "branch_protection_unsupported") {
    return { title: "GitHub plan limitation", lines: [`Branch: ${details.branch || "unknown"}`, `Reason: ${details.reason || "GitHub did not expose branch protection"}`] };
  }
  if (event.event_type === "connection_error") {
    const attempts = details.consecutive_failures ? `Failed checks: ${details.consecutive_failures}` : "";
    return { title: "Connection health", lines: [`Provider: ${event.connector_name || event.connector}`, attempts, `Reason: ${details.error || "Retayn could not complete a monitoring check"}`].filter(Boolean) };
  }
  if (["new_identity", "identity_reactivated", "privileged_identity_removed", "identity_removed", "identity_deactivated", "trusted_identity_removed"].includes(event.event_type)) {
    const identity = details.identity || details.after || {};
    return {
      title: "Person affected",
      lines: [
        `Name: ${personName(identity)}`,
        `Access level: ${roleName(event.connector, identity)}`,
        `Status: ${activeState(identity)}`,
      ],
    };
  }
  if (["identity_escalation", "identity_role_downgrade"].includes(event.event_type)) {
    const before = details.before || {};
    const after = details.after || {};
    return {
      title: "Access changed",
      lines: [
        `Name: ${personName(after)}`,
        `Before: ${roleName(event.connector, before)}`,
        `Now: ${roleName(event.connector, after)}`,
        `Account status: ${activeState(after)}`,
      ],
    };
  }
  if (event.event_type === "shop_identity_changed") {
    return { title: "Store account changes", lines: Object.entries(details.changes || {}).map(([key, value]) => `${key}: ${value.before || "empty"} -> ${value.after || "empty"}`) };
  }
  if (event.event_type === "airtable_schema_changed") {
    return { title: "Schema changes", lines: [`Added: ${(details.added || []).map((item) => item.name).join(", ") || "none"}`, `Removed: ${(details.removed || []).map((item) => item.name).join(", ") || "none"}`, `Changed: ${(details.changed || []).map((item) => item.name).join(", ") || "none"}`] };
  }
  return { title: "Details", lines: [JSON.stringify(details, null, 2)] };
}

function renderEvents(events) {
  const target = $("#eventsList");
  if (!events.length) {
    target.innerHTML = '<p class="empty">No pending notifications.</p>';
    return;
  }
  target.innerHTML = events.map((event) => {
    const info = detailsFor(event);
    const actions = supportedActionsFor(event);
    const supportedAction = actions.length > 0;
    const primaryAction = actions[0] || null;
    const actionText = primaryAction ? primaryAction.label || actionLabel(primaryAction.id) : "";
    const actionButtons = actions.slice(1).map((action) => `
      <button class="danger secondary-danger" onclick="confirmAndPost(event, '/api/events/${event.id}/actions/${encodeURIComponent(action.id)}', 'Are you sure? Retayn will ${escapeHtml((action.label || actionLabel(action.id)).toLowerCase())}.', 'Taking action...')">${escapeHtml(action.label || actionLabel(action.id))}</button>
    `).join("");
    const disabledTitle = supportedAction ? "" : 'title="This app does not support an action for this notification."';
    return `
      <article class="event-card ${escapeHtml(event.severity)}">
        <div class="event-head">
          <div class="event-copy">
            <strong>${escapeHtml(event.title)}</strong>
            <span class="event-time">${escapeHtml(event.created_at)} &middot; ${escapeHtml(event.connector_name || event.connector || "Retayn")} &middot; ${escapeHtml(`${event.owner || ""}/${event.repo || ""}`.replace(/^\/|\/$/g, ""))}</span>
          </div>
          <span class="severity ${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span>
        </div>
        <p class="event-summary">${escapeHtml(event.summary)}</p>
        <div class="details"><strong>${escapeHtml(info.title)}</strong><pre>${escapeHtml(info.lines.join("\n"))}</pre></div>
        ${supportedAction ? `<p class="planned-action"><strong>Take action:</strong> ${escapeHtml(actionText)}</p>` : ""}
        <div class="actions">
          <button class="safe" onclick="confirmAndPost(event, '/api/events/${event.id}/me', 'Are you sure? Retayn will approve this notification and trust the current state.', 'Approving...')">Approve</button>
          <span class="tooltip-wrap" data-tooltip="This app does not support an action for this notification.">
            <button class="danger" ${supportedAction ? "" : "disabled"} ${disabledTitle} onclick="confirmAndPost(event, '/api/events/${event.id}/actions/${primaryAction ? encodeURIComponent(primaryAction.id) : ''}', 'Are you sure? Retayn will ${escapeHtml(actionText.toLowerCase())}.', 'Taking action...')">Take action</button>
          </span>
          ${actionButtons}
          <button class="secondary" onclick="confirmAndPost(event, '/api/events/${event.id}/ignore', 'Are you sure? Retayn will ignore this notification and stop showing it as pending.', 'Ignoring...')">Ignore</button>
        </div>
      </article>
    `;
  }).join("");
}

function renderRecent(events) {
  const target = $("#recentList");
  if (!events.length) {
    target.innerHTML = '<p class="empty">No activity recorded yet.</p>';
    return;
  }
  target.innerHTML = events.map((event) => `
    <div class="recent-row">
      <strong>${escapeHtml(event.title)} &middot; ${escapeHtml(event.status)}</strong>
      <small>${escapeHtml(event.created_at)} ${event.action_taken ? `&middot; ${escapeHtml(event.action_taken)}` : ""}</small>
    </div>
  `).join("");
}

function textareaToList(value) {
  return String(value || "").split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
}

function categoryOptions(selected = "") {
  return (lastData.system_categories || []).map((category) => `<option value="${escapeHtml(category.id)}" ${category.id === selected ? "selected" : ""}>${escapeHtml(category.name)}</option>`).join("");
}

function renderCoverage(protection) {
  const categories = protection.categories || [];
  $("#coverageStrip").innerHTML = categories.map((category) => `
    <button type="button" class="coverage-item ${escapeHtml(category.status)}" onclick="setView('protection')">
      <span class="coverage-dot"></span>
      <span>${escapeHtml(category.name)}</span>
    </button>
  `).join("");
}

function renderProtection(protection, assets) {
  $("#protectionScore").textContent = protection.score || 0;
  $("#assetCount").textContent = `${assets.length} recorded`;
  $("#assetCategory").innerHTML = categoryOptions($("#assetCategory").value);
  $("#protectionCategories").innerHTML = (protection.categories || []).map((category) => {
    const providers = [
      ...(category.connections || []).map((item) => `${item.provider}: ${item.name}`),
      ...(category.assets || []).map((item) => `${item.provider}: ${item.name}`),
    ];
    return `
      <article class="category-row ${escapeHtml(category.status)}">
        <div class="category-status"><span class="coverage-dot"></span><span>${escapeHtml(category.status.replace("_", " "))}</span></div>
        <div>
          <h3>${escapeHtml(category.name)}</h3>
          <p>${escapeHtml(category.description)}</p>
        </div>
        <div class="category-providers">${providers.length ? providers.map((item) => `<span>${escapeHtml(item)}</span>`).join("") : `<span class="gap-copy">No system recorded</span>`}</div>
      </article>
    `;
  }).join("");
  if (editingAssetId === null) renderAssetList(assets);
}

function assetPayload(form) {
  return {
    category: form.category.value,
    provider: form.provider.value,
    name: form.name.value,
    url: form.url.value,
    criticality: form.criticality.value,
    control_holders: textareaToList(form.control_holders.value),
    recovery_contact: form.recovery_contact.value,
    recovery_method: form.recovery_method.value,
    backup_status: form.backup_status.value,
    notes: form.notes.value,
  };
}

function renderAssetList(assets) {
  const target = $("#assetList");
  if (!assets.length) {
    target.innerHTML = '<p class="empty">No critical systems recorded yet.</p>';
    return;
  }
  target.innerHTML = assets.map((asset) => {
    if (editingAssetId === asset.id) {
      return `
        <form class="asset-edit-form" onsubmit="saveAsset(event, ${asset.id})">
          <label>Category<select name="category">${categoryOptions(asset.category)}</select></label>
          <label>Provider<input name="provider" value="${escapeHtml(asset.provider)}" required /></label>
          <label>System name<input name="name" value="${escapeHtml(asset.name)}" required /></label>
          <label>Account URL<input name="url" type="url" value="${escapeHtml(asset.url || "")}" /></label>
          <label>Criticality<select name="criticality">${["critical", "high", "medium", "low"].map((item) => `<option value="${item}" ${asset.criticality === item ? "selected" : ""}>${item}</option>`).join("")}</select></label>
          <label>People with control<textarea name="control_holders">${escapeHtml((asset.control_holders || []).join("\n"))}</textarea></label>
          <label>Recovery contact<input name="recovery_contact" value="${escapeHtml(asset.recovery_contact || "")}" /></label>
          <label>Recovery path<textarea name="recovery_method">${escapeHtml(asset.recovery_method || "")}</textarea></label>
          <label>Backup status<select name="backup_status">${["independent", "provider_only", "missing", "unknown", "not_applicable"].map((item) => `<option value="${item}" ${asset.backup_status === item ? "selected" : ""}>${item.replaceAll("_", " ")}</option>`).join("")}</select></label>
          <label>Notes<textarea name="notes">${escapeHtml(asset.notes || "")}</textarea></label>
          <div class="actions"><button type="submit">Save</button><button type="button" class="secondary" onclick="cancelAssetEdit()">Cancel</button></div>
        </form>
      `;
    }
    return `
      <article class="asset-row">
        <div class="asset-head">
          <div><strong>${escapeHtml(asset.provider)} &middot; ${escapeHtml(asset.name)}</strong><small>${escapeHtml(asset.category_name)} &middot; ${escapeHtml(asset.criticality)}</small></div>
          <span class="status-pill ${asset.risk_status === "at_risk" ? "danger" : ""}">${asset.risk_status === "at_risk" ? "Needs details" : "Recovery ready"}</span>
        </div>
        <div class="asset-facts">
          <span>Control: ${escapeHtml((asset.control_holders || []).join(", ") || "Not recorded")}</span>
          <span>Backup: ${escapeHtml((asset.backup_status || "unknown").replaceAll("_", " "))}</span>
          <span>Reviewed: ${escapeHtml(asset.last_reviewed_at || "Not yet")}</span>
        </div>
        ${(asset.risks || []).length ? `<div class="risk-list">${asset.risks.map((risk) => `<span>${escapeHtml(risk)}</span>`).join("")}</div>` : ""}
        <div class="actions">
          <button type="button" class="secondary" onclick="reviewAsset(${asset.id})">Mark reviewed</button>
          <button type="button" class="secondary" onclick="editAsset(${asset.id})">Edit</button>
          <button type="button" class="secondary-danger" onclick="deleteAsset(${asset.id})">Delete</button>
        </div>
      </article>
    `;
  }).join("");
}

function editAsset(assetId) {
  editingAssetId = assetId;
  renderAssetList(lastData.assets || []);
}

function cancelAssetEdit() {
  editingAssetId = null;
  renderAssetList(lastData.assets || []);
}

async function saveAsset(event, assetId) {
  event.preventDefault();
  try {
    await postJson(`/api/assets/${assetId}`, assetPayload(event.currentTarget));
    editingAssetId = null;
    await loadOverview();
  } catch (error) {
    alert(error.message);
  }
}

async function reviewAsset(assetId) {
  await postAction(`/api/assets/${assetId}/review`);
}

async function deleteAsset(assetId) {
  if (!confirm("Remove this system from the Retayn protection map?")) return;
  editingAssetId = null;
  await postAction(`/api/assets/${assetId}/delete`);
}

async function loadOverview() {
  const response = await fetch("/api/overview");
  const data = await response.json();
  lastData = data;
  const hasSystems = Boolean(data.stats.has_systems);
  $("#securityScore").textContent = hasSystems ? data.stats.security_score : "--";
  $("#securityScoreBar").style.width = `${hasSystems ? Math.max(0, Math.min(100, Number(data.stats.security_score) || 0)) : 0}%`;
  $("#postureTitle").textContent = hasSystems ? "Your connected systems are being watched." : "Connect your first app.";
  $("#postureBody").textContent = hasSystems
    ? "Retayn is comparing access, roles, settings, and critical resources against your approved baseline."
    : "Add GitHub, Slack, Zendesk, Airtable, or another supported app to start monitoring access and role changes.";
  $("#openCount").textContent = data.stats.open_events;
  $("#coverageCount").textContent = data.stats.coverage;
  $("#sidebarPosture").textContent = data.stats.overall_security;
  $("#autoActionState").textContent = data.stats.auto_action_enabled ? "On" : "Off";
  if (!activeEditableElement()?.closest?.("#connectView")) renderConnectorSelect(data.connectors || []);
  renderCoverage(data.protection || { categories: [] });
  renderProtection(data.protection || { categories: [], score: 0 }, data.assets || []);
  renderAccounts(data.accounts);
  if (!editingSettings) renderManageApps(data.accounts);
  renderEvents(data.open_events);
  renderRecent(data.recent_events);
}

$("#connectForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const connector = selectedConnector();
  if (connector?.coming_soon) {
    $("#formNote").textContent = `${connector.name} is coming soon. Many more apps are on the way.`;
    return;
  }
  const button = form.querySelector("button[type='submit']");
  button.disabled = true;
  $("#formNote").textContent = "Checking whether Retayn can access that app...";
  try {
    const payload = await postForm("/api/accounts/start", form);
    $("#formNote").textContent = `${payload.repo} is now monitored.`;
    form.reset();
    await loadOverview();
    setView("overview");
  } catch (error) {
    $("#formNote").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#assetForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type='submit']");
  button.disabled = true;
  $("#assetFormNote").textContent = "Adding system...";
  try {
    await postJson("/api/assets", assetPayload(form));
    form.reset();
    $("#assetFormNote").textContent = "System added to your protection map.";
    await loadOverview();
  } catch (error) {
    $("#assetFormNote").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#installAppButton").addEventListener("click", () => {
  const connector = selectedConnector();
  if (connector && connector.install_url) {
    const formData = new FormData($("#connectForm"));
    const url = new URL(connector.install_url, window.location.origin);
    for (const [key, value] of formData.entries()) {
      if (key !== "connector" && value) url.searchParams.set(key, value);
    }
    window.open(url.toString(), "_blank", "noopener,noreferrer");
    $("#formNote").textContent = `After installing Retayn in ${connector.name}, return here and click Finish connection.`;
    return;
  }
  $("#formNote").textContent = "The install URL for this app is not configured yet.";
});

$("#connectorSelect").addEventListener("change", () => {
  $("#formNote").textContent = "";
  renderConnectorFields();
});

$("#newRecoveryCaseButton").addEventListener("click", () => showRecoveryIntake());
$("#syncTelegramRecoveryButton")?.addEventListener("click", syncTelegramRecovery);
$("#addRecoveryContactButton").addEventListener("click", addRecoveryContact);
$("#addRecoveryEvidenceFileButton").addEventListener("click", () => addEvidenceFileRow());
$("#cancelRecoveryCaseButton").addEventListener("click", hideRecoveryIntake);
$("#recoveryCaseForm").addEventListener("input", () => {
  recoveryEditing = true;
});
$("#recoveryCaseForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type='submit']");
  setButtonLoading(button, "Preparing case...");
  $("#recoveryFormNote").textContent = "Saving the facts and preparing a first message...";
  try {
    const response = await fetch("/api/recovery/cases", { method: "POST", body: formDataWithEvidenceRows(form) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Could not create the recovery case.");
    recoveryEditing = false;
    selectedRecoveryCaseId = data.id;
    selectedRecoveryContactId = data.contacts?.[0]?.id || null;
    $("#recoveryIntake").classList.add("hidden");
    await loadRecovery();
  } catch (error) {
    $("#recoveryFormNote").textContent = error.message;
  } finally {
    clearButtonLoading(button);
  }
});

async function refreshAccount(accountId) {
  editingSettings = false;
  await postAction(`/api/accounts/${accountId}/refresh`);
}

async function deleteAccount(event, accountId) {
  const button = event?.currentTarget;
  if (!confirm("Are you sure? Retayn will delete this connection and its local monitoring history.")) return;
  editingSettings = false;
  selectedAccountId = null;
  if (button) setButtonLoading(button, "Deleting...");
  try {
    const payload = await postAction(`/api/accounts/${accountId}/delete`);
    if (payload.manual_disconnect?.message) {
      alert(payload.manual_disconnect.message);
    }
  } catch (error) {
    alert(error.message);
  } finally {
    if (button) clearButtonLoading(button);
  }
}

async function editAccount(event, accountId) {
  event.preventDefault();
  try {
    await postForm(`/api/accounts/${accountId}/edit`, event.currentTarget);
    await loadOverview();
  } catch (error) {
    alert(error.message);
  }
}

async function saveAccountSettings(event, accountId) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    auto_action_enabled: form.auto_action_enabled.checked,
    windows_notifications: form.windows_notifications.checked,
    auto_action_delay_minutes: Number(form.auto_action_delay_minutes.value || 30),
    monitoring_poll_seconds: Number(form.monitoring_poll_seconds.value || 30),
    github_poll_seconds: Number(form.monitoring_poll_seconds.value || 30),
    allowed_identities: textareaToList(form.allowed_identities.value),
    github_allowed_users: accountId && (lastData.accounts || []).find((item) => item.id === accountId)?.connector === "github" ? textareaToList(form.allowed_identities.value) : [],
    github_allowed_hook_urls: textareaToList(form.github_allowed_hook_urls.value),
    github_allowed_write_deploy_keys: textareaToList(form.github_allowed_write_deploy_keys.value),
  };
  try {
    await postJson(`/api/accounts/${accountId}/settings`, payload);
    editingSettings = false;
    await loadOverview();
  } catch (error) {
    alert(error.message);
  }
}

$("#refreshButton").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.classList.add("refreshing");
  button.disabled = true;
  try {
    await loadOverview();
  } finally {
    button.classList.remove("refreshing");
    button.disabled = false;
  }
});
$$(".nav-item").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));

$("#menuButton").addEventListener("click", () => {
  const isOpen = document.body.classList.toggle("nav-open");
  $("#menuButton").setAttribute("aria-expanded", String(isOpen));
});

$("#mobileScrim").addEventListener("click", () => {
  document.body.classList.remove("nav-open");
  $("#menuButton").setAttribute("aria-expanded", "false");
});

if ($("#recoveryEvidenceFiles")) {
  $("#recoveryEvidenceFiles").innerHTML = evidenceFileRow();
}

loadOverview();
setView(["overview", "recover", "protection", "apps", "connect"].includes(window.location.hash.slice(1)) ? window.location.hash.slice(1) : "overview");
setInterval(() => {
  if (!activeEditableElement() && !recoveryEditing && !recoveryDraftDirty && !editingSettings) loadOverview();
}, 5000);
setInterval(() => {
  if (viewIsActive("recover") && !recoveryEditing && !recoveryDraftDirty && !activeEditableElement()?.closest?.("#recoverView")) loadRecovery();
}, 8000);
setInterval(() => syncTelegramRecoveryQuiet(), 15000);
