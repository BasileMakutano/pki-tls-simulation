"""
tls/handshake_test.py
Spins up a REAL TLS 1.3 server on localhost using the generated server cert,
and a real client that connects to it - optionally with mutual TLS (the
client also presents a cert, and the server verifies it). This is not
simulated: it is an actual socket-level handshake you can capture in
Wireshark on loopback (see capture/capture_traffic.sh).
"""
import os
import socket
import ssl
import threading
import time
from typing import Any, TypedDict

from pki import ca as pki

HOST = "127.0.0.1"


class HandshakeResult(TypedDict, total=False):
    ok: bool
    mutual_tls: bool
    error: str
    protocol_version: str | None
    cipher_suite: tuple[str, str, int] | None
    server_cn: Any
    client_cn: Any
    server_reply: str
    port_used: int
    server_saw_client_cert: bool


def _chain_file(cert_id, reg):
    """Concatenate leaf + intermediate into one PEM for the server to present."""
    entry = reg["certs"][cert_id]
    leaf_pem = open(pki.cert_full_path(entry["cert_path"]), "rb").read()
    inter_pem = open(pki.cert_full_path("intermediate/intermediate.crt"), "rb").read()
    combined_path = pki.cert_full_path(f"leaf/{cert_id}.chain.pem")
    with open(combined_path, "wb") as f:
        f.write(leaf_pem + b"\n" + inter_pem)
    return combined_path


def _ca_bundle():
    root = open(pki.cert_full_path("root/root.crt"), "rb").read()
    inter = open(pki.cert_full_path("intermediate/intermediate.crt"), "rb").read()
    bundle_path = pki.cert_full_path("ca_bundle.pem")
    with open(bundle_path, "wb") as f:
        f.write(root + b"\n" + inter)
    return bundle_path


def run_handshake(server_cert_id, client_cert_id=None, port=0, timeout=5):
    """
    Returns a result dict describing the negotiated handshake, or an error.
    If client_cert_id is given, mutual TLS is used and the server verifies
    the client certificate against the CA bundle too.
    """
    reg = pki.get_registry()
    if server_cert_id not in reg["certs"]:
        return {"ok": False, "error": f"Unknown server cert id {server_cert_id}"}

    server_entry = reg["certs"][server_cert_id]
    server_key = pki.cert_full_path(server_entry["key_path"])
    server_chain = _chain_file(server_cert_id, reg)
    ca_bundle = _ca_bundle()

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.load_cert_chain(certfile=server_chain, keyfile=server_key)

    mutual = client_cert_id is not None
    if mutual:
        server_ctx.verify_mode = ssl.CERT_REQUIRED
        server_ctx.load_verify_locations(cafile=ca_bundle)

    result: HandshakeResult = {"ok": False, "mutual_tls": mutual}
    ready = threading.Event()
    server_state: dict[str, Any] = {}

    def server_thread(sock):
        try:
            sock.listen(1)
            ready.set()
            sock.settimeout(timeout)
            conn, addr = sock.accept()
            with server_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                data = tls_conn.recv(1024)
                tls_conn.send(b"ACK from Tendaji TLS server: " + data)
                server_state["peer_cert"] = tls_conn.getpeercert()
                server_state["cipher"] = tls_conn.cipher()
                server_state["version"] = tls_conn.version()
        except Exception as e:
            server_state["error"] = str(e)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, port))
    bound_port = raw_sock.getsockname()[1]

    t = threading.Thread(target=server_thread, args=(raw_sock,), daemon=True)
    t.start()
    ready.wait(timeout=2)

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    client_ctx.load_verify_locations(cafile=ca_bundle)
    client_ctx.check_hostname = True

    if mutual:
        client_entry = reg["certs"][client_cert_id]
        client_key = pki.cert_full_path(client_entry["key_path"])
        client_chain = _chain_file(client_cert_id, reg)
        client_ctx.load_cert_chain(certfile=client_chain, keyfile=client_key)

    try:
        with socket.create_connection((HOST, bound_port), timeout=timeout) as raw_client:
            with client_ctx.wrap_socket(raw_client, server_hostname="localhost") as tls_client:
                tls_client.send(b"Hello from Tendaji TLS client")
                reply = tls_client.recv(1024)
                result["ok"] = True
                result["protocol_version"] = tls_client.version()
                result["cipher_suite"] = tls_client.cipher()
                result["server_cn"] = server_entry["cn"]
                result["client_cn"] = (
                    reg["certs"][client_cert_id]["cn"] if client_cert_id is not None else None
                )
                result["server_reply"] = reply.decode(errors="replace")
                result["port_used"] = bound_port
    except ssl.SSLError as e:
        result["error"] = f"TLS handshake failed: {e}"
    except Exception as e:
        result["error"] = str(e)

    t.join(timeout=timeout)
    if "error" in server_state and "error" not in result:
        result["error"] = "Server-side: " + server_state["error"]
    if server_state.get("peer_cert") is not None:
        result["server_saw_client_cert"] = True

    return result
