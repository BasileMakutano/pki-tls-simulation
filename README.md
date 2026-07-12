# Tendaji PKI Registry
### Option B — PKI + TLS Simulation (Final Project)

A working mini Certificate Authority with a real two-tier trust chain, an
independent certificate-validation engine, CRL-based revocation, and a
**live TLS 1.3 handshake** between two real sockets using the certificates
you issue — wrapped in a web dashboard instead of a stack of CLI scripts.

---

## 1. What this actually does (not simulated)

| Piece | Real or simulated? |
|---|---|
| Root CA / Intermediate CA keypairs & certs | **Real X.509 certs**, generated with `cryptography` (same primitives OpenSSL uses) |
| Chain-of-trust validation | **Real signature verification**, walked hop-by-hop by hand (not just `ssl.verify`) |
| Revocation | **Real signed CRL**, checked against on every validation run |
| TLS handshake | **Real TLS 1.3 socket handshake** on `127.0.0.1`, one-way or mutual auth |
| Wireshark capture | **Real packet capture** on loopback — genuinely visible in Wireshark |

Nothing here is mocked data or a fake progress bar. The validation engine
in particular deliberately does *not* just call `cert.verify()` and trust
the result — it performs each check (chain completeness, signature math,
`BasicConstraints`, validity window, key usage, revocation) as a discrete,
inspectable step, because that's the point of the assignment.

## 2. Architecture

```
Root CA (RSA-4096, self-signed, 10y)
   └── Intermediate CA (RSA-3072, signed by Root, 5y)
          ├── Server leaf certs (RSA-2048, serverAuth EKU, SAN)
          └── Client leaf certs (RSA-2048, clientAuth EKU)   <- for mutual TLS

pki/ca.py           builds the hierarchy, issues leaf certs
pki/validator.py     independent chain-of-trust validation engine
pki/revocation.py    CRL generation + revocation checks
tls/handshake_test.py  real TLS 1.3 server+client over loopback sockets
capture/              Wireshark/tshark capture + pcap parser (for Kali)
app.py                Flask backend tying it together
templates/, static/   the dashboard UI
```

Everything is stored under `data/` as plain PEM/JSON files, so you can also
inspect it with `openssl x509 -in data/leaf/<id>.crt -text -noout` if you
want to cross-check the dashboard against the raw files for your report.

## 3. Setup (Kali Linux)

```bash
cd pki-tls-project
chmod +x run.sh
./run.sh
```

`run.sh` creates a virtualenv, installs `flask` and `cryptography`, and
starts the server. Then open **http://127.0.0.1:5000**.

If you'd rather do it manually:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

For the Wireshark part you additionally need `tshark` (ships with
Wireshark on Kali, or `sudo apt install tshark` if it isn't already there).

## 4. Demo script (suggested order for your presentation)

1. **Initialize PKI** — builds Root CA and Intermediate CA. Click each in
   the left-hand "Chain of Custody" ledger to show the real certificate
   fields (serial, subject/issuer DN, fingerprint, validity window).
2. **Issue Certificate** — issue one *server* cert (e.g. `api.tendaji.local`)
   and one *client* cert. Point out the different Extended Key Usage
   (`serverAuth` vs `clientAuth`) in the cert detail view.
3. Select the server cert and click **Run Validation** — walk through the
   step-by-step timeline: chain completeness, hop-by-hop signature
   verification, `BasicConstraints`, validity window, key usage, CRL check.
   The wax seal animates green ("Verified").
4. **Revoke** that certificate, then **Run Validation** again — the CRL
   check now fails and the seal turns red ("Rejected"). This is the part
   that's easy to hand-wave in a report and satisfying to show live.
5. **Live TLS Test** — run a one-way handshake, then re-run with
   **mutual TLS** enabled. Point out the negotiated protocol/cipher and
   that the server actually required and verified the client certificate.
6. **Wireshark Capture** — in a terminal: `sudo ./capture/capture_traffic.sh handshake.pcap 20`,
   trigger another Live TLS Test in the browser during that window, then
   upload `handshake.pcap` in the Capture panel (or just open it in
   Wireshark directly) to show the real ClientHello/ServerHello/Certificate
   handshake frames on the wire.

## 5. Design notes for your report

- **Why RSA and not ECDSA?** Kept to RSA throughout for consistency with
  what's typically covered in the course material; swapping to
  `ec.generate_private_key(ec.SECP256R1())` in `pki/ca.py` is a small,
  worthwhile change to mention as a discussion point (smaller keys/certs,
  faster handshake) if you want an extension.
- **Why a hand-rolled validator instead of just trusting Python's `ssl`
  module?** `ssl` will tell you *whether* a chain is valid but not *why* —
  for a course project the value is in showing each check explicitly
  (signature math, extensions, expiry, revocation) as separate, gradable
  steps.
- **Path length constraints**: the Root CA's `BasicConstraints` sets
  `path_length=1` and the Intermediate's sets `path_length=0`, correctly
  preventing the Intermediate from issuing further sub-CAs.
- **CRL vs OCSP**: this project uses CRL (simpler to reason about and to
  demo entirely offline); OCSP is a natural "future work" line for your
  report if you want to note the tradeoff (CRL = periodic/complete but
  can be stale; OCSP = real-time but needs a live responder).

## 6. Known limitations (worth stating up front in your writeup)

- Single-machine demo: the "client" and "server" are both `127.0.0.1`,
  which is honest for a coursework demo but isn't a network-segmented
  deployment.
- CRL only, no OCSP responder.
- Private keys are stored unencrypted under `data/` for simplicity — never
  do this outside a lab exercise.
