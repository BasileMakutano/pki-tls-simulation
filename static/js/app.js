const $ = (sel) => document.querySelector(sel);

let selectedCertId = null;
let certRegistry = {};

async function api(path, opts) {
  const res = await fetch(path, opts);
  return res.json();
}

// ---------------------------------------------------------------- init ---
async function refreshStatus() {
  const status = await api("/api/pki/status");
  $("#btnIssue").disabled = !status.has_intermediate;
  $("#btnTlsPanel").disabled = !status.has_intermediate;
  return status;
}

async function refreshTree() {
  certRegistry = await api("/api/pki/tree");
  const container = $("#ledgerTree");
  const ids = Object.keys(certRegistry);
  if (ids.length === 0) {
    container.innerHTML = '<p class="empty-note">No hierarchy yet. Click <strong>Initialize PKI</strong> to generate the Root and Intermediate CA.</p>';
    return;
  }
  // order: root, intermediate, then leaves
  const order = ["root", "intermediate", "server", "client"];
  const sorted = ids.sort((a, b) => order.indexOf(certRegistry[a].role) - order.indexOf(certRegistry[b].role));

  container.innerHTML = sorted.map((id) => {
    const c = certRegistry[id];
    const revokedClass = c.revoked ? "revoked" : "";
    const selClass = id === selectedCertId ? "selected" : "";
    return `<div class="ledger-node role-${c.role} ${revokedClass} ${selClass}" data-id="${id}">
      <span class="dot"></span>
      <span class="cn">${c.cn}</span>
      <span class="role-label">${c.role}${c.revoked ? " · revoked" : ""}</span>
    </div>`;
  }).join("");

  container.querySelectorAll(".ledger-node").forEach((el) => {
    el.addEventListener("click", () => selectCert(el.dataset.id));
  });
}

async function refreshLogs() {
  const logs = await api("/api/logs");
  const container = $("#logList");
  container.innerHTML = logs.slice().reverse().map((l) => `
    <div class="log-entry ${l.level}">
      <span class="ts">${l.ts.replace("T", " ").slice(0, 19)}</span>
      ${l.message}
    </div>`).join("") || '<p class="empty-note">No events yet.</p>';
}

// -------------------------------------------------------- cert document --
async function selectCert(id) {
  selectedCertId = id;
  await refreshTree();
  const data = await api(`/api/certs/${id}`);
  if (!data.ok) return;

  const doc = $("#certDocument");
  doc.classList.remove("empty");
  doc.innerHTML = `
    <div id="wax" class="wax-seal"></div>
    <div class="cert-doc-head">
      <div>
        <h2>${data.cn}</h2>
        <span class="role-tag">${data.role} certificate</span>
      </div>
    </div>
    <div class="cert-fields">
      <div><span class="field-label">Serial</span><span class="field-value">${data.serial}</span></div>
      <div><span class="field-label">Signature Algorithm</span><span class="field-value">${data.sig_algo}</span></div>
      <div class="span-2"><span class="field-label">Subject</span><span class="field-value">${data.subject}</span></div>
      <div class="span-2"><span class="field-label">Issuer</span><span class="field-value">${data.issuer}</span></div>
      <div><span class="field-label">Valid From</span><span class="field-value">${data.not_before}</span></div>
      <div><span class="field-label">Valid Until</span><span class="field-value">${data.not_after}</span></div>
      <div><span class="field-label">Public Key</span><span class="field-value">RSA ${data.public_key_bits}-bit</span></div>
      <div><span class="field-label">Status</span><span class="field-value">${data.revoked ? "REVOKED" : "Active"}</span></div>
      <div class="span-2"><span class="field-label">SHA-256 Fingerprint</span><span class="field-value">${data.fingerprint_sha256}</span></div>
    </div>
    <div class="cert-doc-footer">
      ${data.role !== "root" ? `<button id="btnRevoke" class="btn btn-ghost">Revoke this certificate</button>` : ""}
    </div>
  `;

  if (data.role !== "root") {
    $("#btnRevoke").addEventListener("click", async () => {
      if (!confirm(`Revoke ${data.cn}? This regenerates the CRL immediately.`)) return;
      await api(`/api/certs/${id}/revoke`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "key compromise (simulated)" }),
      });
      await refreshTree();
      await refreshLogs();
      selectCert(id);
    });
  }

  $("#validationPanel").classList.remove("hidden");
  $("#validationSteps").innerHTML = "";
  $("#wax").className = "wax-seal";
}

// ------------------------------------------------------------ validate --
$("#btnValidate").addEventListener("click", async () => {
  if (!selectedCertId) return;
  const result = await api(`/api/validate/${selectedCertId}`, { method: "POST" });
  const list = $("#validationSteps");
  list.innerHTML = "";
  result.steps.forEach((s, i) => {
    const li = document.createElement("li");
    li.style.animationDelay = `${i * 60}ms`;
    li.innerHTML = `
      <span class="step-icon ${s.passed ? "pass" : "fail"}">${s.passed ? "✓" : "✕"}</span>
      <span class="step-body">
        <span class="step-check">${s.check}</span>
        <span class="step-detail">${s.detail}</span>
      </span>`;
    list.appendChild(li);
  });

  const wax = $("#wax");
  wax.classList.remove("valid", "invalid");
  void wax.offsetWidth; // restart animation
  wax.classList.add(result.valid ? "valid" : "invalid", "show");
  wax.textContent = result.valid ? "Verified" : "Rejected";

  refreshLogs();
});

// --------------------------------------------------------------- init ----
$("#btnInit").addEventListener("click", async () => {
  $("#btnInit").disabled = true;
  $("#btnInit").textContent = "Building...";
  await api("/api/pki/init", { method: "POST" });
  $("#btnInit").textContent = "Rebuild PKI";
  $("#btnInit").disabled = false;
  await refreshStatus();
  await refreshTree();
  await refreshLogs();
});

// ------------------------------------------------------------ issue cert -
$("#btnIssue").addEventListener("click", () => $("#issueModal").classList.remove("hidden"));
$("#issueCancel").addEventListener("click", () => $("#issueModal").classList.add("hidden"));
$("#issueSubmit").addEventListener("click", async () => {
  const body = {
    type: $("#issueType").value,
    cn: $("#issueCn").value,
    sans: $("#issueSans").value,
  };
  const result = await api("/api/certs/issue", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!result.ok) { alert(result.error); return; }
  $("#issueModal").classList.add("hidden");
  $("#issueCn").value = ""; $("#issueSans").value = "";
  await refreshTree();
  await refreshLogs();
  selectCert(result.cert_id);
});

// --------------------------------------------------------------- tls test
$("#btnTlsPanel").addEventListener("click", () => {
  const serverSel = $("#tlsServerSelect");
  const clientSel = $("#tlsClientSelect");
  const servers = Object.values(certRegistry).filter((c) => c.role === "server" && !c.revoked);
  const clients = Object.values(certRegistry).filter((c) => c.role === "client" && !c.revoked);
  serverSel.innerHTML = servers.map((c) => `<option value="${c.id}">${c.cn}</option>`).join("") || "<option disabled>No server certs issued</option>";
  clientSel.innerHTML = clients.map((c) => `<option value="${c.id}">${c.cn}</option>`).join("") || "<option disabled>No client certs issued</option>";
  $("#tlsResult").classList.add("hidden");
  $("#tlsModal").classList.remove("hidden");
});
$("#tlsCancel").addEventListener("click", () => $("#tlsModal").classList.add("hidden"));
$("#tlsMutual").addEventListener("change", (e) => $("#tlsClientRow").classList.toggle("hidden", !e.target.checked));

$("#tlsRun").addEventListener("click", async () => {
  const body = {
    server_cert_id: $("#tlsServerSelect").value,
    client_cert_id: $("#tlsMutual").checked ? $("#tlsClientSelect").value : null,
  };
  $("#tlsRun").disabled = true;
  $("#tlsRun").textContent = "Running handshake...";
  const result = await api("/api/tls-test", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  $("#tlsRun").disabled = false;
  $("#tlsRun").textContent = "Run Handshake";

  const box = $("#tlsResult");
  box.classList.remove("hidden", "ok", "err");
  if (result.ok) {
    box.classList.add("ok");
    box.innerHTML = `
      Handshake succeeded on 127.0.0.1:${result.port_used}<br>
      Protocol: ${result.protocol_version}<br>
      Cipher suite: ${result.cipher_suite ? result.cipher_suite[0] : "n/a"}<br>
      Mutual TLS: ${result.mutual_tls ? "yes - client cert verified" : "no"}<br>
      Server CN: ${result.server_cn}${result.client_cn ? " · Client CN: " + result.client_cn : ""}<br>
      Server replied: "${result.server_reply}"
    `;
  } else {
    box.classList.add("err");
    box.textContent = "Handshake failed: " + result.error;
  }
  refreshLogs();
});

// ---------------------------------------------------------------- capture
$("#btnCapturePanel").addEventListener("click", () => $("#captureModal").classList.remove("hidden"));
$("#captureClose").addEventListener("click", () => $("#captureModal").classList.add("hidden"));

$("#pcapUpload").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("pcap", file);
  $("#pcapOutput").classList.remove("hidden");
  $("#pcapOutput").textContent = "Analyzing...";
  const res = await fetch("/api/capture/analyze", { method: "POST", body: form });
  const data = await res.json();
  $("#pcapOutput").textContent = data.output || data.error || "No output.";
});

// ----------------------------------------------------------------- boot --
(async function boot() {
  await refreshStatus();
  await refreshTree();
  await refreshLogs();
  setInterval(refreshLogs, 8000);
})();
