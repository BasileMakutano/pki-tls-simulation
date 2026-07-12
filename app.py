"""
app.py
Flask backend for the PKI + TLS Simulation dashboard.
Run: python3 app.py   (then open http://127.0.0.1:5000)
"""
import os
import subprocess

from flask import Flask, jsonify, request, render_template, send_from_directory

from pki import ca as pki
from pki import validator, revocation
from tls import handshake_test

app = Flask(__name__)


# ---------------------------------------------------------------- pages ----
@app.route("/")
def index():
    return render_template("index.html")


# --------------------------------------------------------------- PKI api ---
@app.route("/api/pki/status")
def pki_status():
    reg = pki.get_registry()
    return jsonify({
        "initialized": "root-ca" in reg["certs"],
        "has_intermediate": "intermediate-ca" in reg["certs"],
    })


@app.route("/api/pki/init", methods=["POST"])
def pki_init():
    pki.reset_pki()
    root_id = pki.build_root_ca()
    inter_id = pki.build_intermediate_ca()
    return jsonify({"ok": True, "root": root_id, "intermediate": inter_id})


@app.route("/api/certs/issue", methods=["POST"])
def issue_cert():
    body = request.get_json(force=True)
    cn = body.get("cn", "").strip()
    cert_type = body.get("type", "server")
    sans = [s.strip() for s in body.get("sans", "").split(",") if s.strip()] or None
    if not cn:
        return jsonify({"ok": False, "error": "Common Name (cn) is required."}), 400
    try:
        cert_id = pki.issue_leaf_cert(cn, cert_type=cert_type, sans=sans)
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "cert_id": cert_id})


@app.route("/api/pki/tree")
def pki_tree():
    reg = pki.get_registry()
    return jsonify(reg["certs"])


@app.route("/api/certs/<cert_id>")
def cert_detail(cert_id):
    reg = pki.get_registry()
    if cert_id not in reg["certs"]:
        return jsonify({"ok": False, "error": "not found"}), 404
    entry = reg["certs"][cert_id]

    from cryptography import x509
    with open(pki.cert_full_path(entry["cert_path"]), "rb") as f:
        pem = f.read()
    cert = x509.load_pem_x509_certificate(pem)

    fingerprint = cert.fingerprint(__import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256())
    ext_list = []
    for ext in cert.extensions:
        ext_list.append({"oid": ext.oid._name if hasattr(ext.oid, "_name") else str(ext.oid), "critical": ext.critical, "value": str(ext.value)})

    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)

    return jsonify({
        "ok": True,
        "id": cert_id,
        "cn": entry["cn"],
        "role": entry["role"],
        "serial": entry["serial"],
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": str(not_before),
        "not_after": str(not_after),
        "sig_algo": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
        "public_key_bits": cert.public_key().key_size,
        "fingerprint_sha256": fingerprint.hex(":", 1).upper(),
        "extensions": ext_list,
        "revoked": entry.get("revoked", False),
        "pem": pem.decode(),
    })


@app.route("/api/certs/<cert_id>/revoke", methods=["POST"])
def revoke_cert(cert_id):
    reason = request.get_json(force=True).get("reason", "unspecified") if request.data else "unspecified"
    try:
        revocation.revoke(cert_id, reason=reason)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    return jsonify({"ok": True})


@app.route("/api/validate/<cert_id>", methods=["POST"])
def validate_cert(cert_id):
    result = validator.validate_chain(cert_id)
    return jsonify(result)


@app.route("/api/logs")
def logs():
    reg = pki.get_registry()
    return jsonify(reg["events"][-100:])


# --------------------------------------------------------------- TLS api ---
@app.route("/api/tls-test", methods=["POST"])
def tls_test():
    body = request.get_json(force=True)
    server_id = body.get("server_cert_id")
    client_id = body.get("client_cert_id") or None
    if not server_id:
        return jsonify({"ok": False, "error": "server_cert_id required"}), 400
    result = handshake_test.run_handshake(server_id, client_id)
    reg = pki.get_registry()
    pki._log_event(
        reg,
        f"TLS handshake test: server={server_id} mutual={bool(client_id)} -> "
        f"{'OK' if result.get('ok') else 'FAILED: ' + str(result.get('error'))}",
        level="info" if result.get("ok") else "error",
    )
    pki._save_registry(reg)
    return jsonify(result)


# ----------------------------------------------------------- capture api ---
@app.route("/api/capture/script")
def capture_script():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture")
    return send_from_directory(path, "capture_traffic.sh", as_attachment=True)


@app.route("/api/capture/analyze", methods=["POST"])
def capture_analyze():
    if "pcap" not in request.files:
        return jsonify({"ok": False, "error": "no pcap file uploaded"}), 400
    f = request.files["pcap"]
    tmp_path = os.path.join(pki.DATA_DIR, "logs", "uploaded.pcap")
    f.save(tmp_path)

    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture", "parse_pcap.py")
    try:
        proc = subprocess.run(["python3", script, tmp_path], capture_output=True, text=True, timeout=20)
        output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
    except FileNotFoundError:
        output = "tshark is not installed on this machine. Install with: sudo apt install tshark"
    except subprocess.TimeoutExpired:
        output = "Analysis timed out."
    return jsonify({"ok": True, "output": output})


if __name__ == "__main__":
    pki._ensure_dirs()
    # debug=True gives auto-reload while you're editing; turn off for a clean demo run
    app.run(debug=True, port=5000, use_reloader=False)
