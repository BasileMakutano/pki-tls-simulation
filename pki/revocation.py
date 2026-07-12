
import datetime
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import ca as pki

REVOKED_LOG = os.path.join(pki.DATA_DIR, "crl", "revoked.json")
CRL_PATH = os.path.join(pki.DATA_DIR, "crl", "intermediate.crl")


def _load_revoked():
    if os.path.exists(REVOKED_LOG):
        with open(REVOKED_LOG) as f:
            return json.load(f)
    return {}


def _save_revoked(data):
    os.makedirs(os.path.dirname(REVOKED_LOG), exist_ok=True)
    with open(REVOKED_LOG, "w") as f:
        json.dump(data, f, indent=2)


def revoke(cert_id, reason="unspecified"):
    reg = pki.get_registry()
    if cert_id not in reg["certs"]:
        raise ValueError(f"Unknown certificate id: {cert_id}")

    entry = reg["certs"][cert_id]
    revoked = _load_revoked()
    revoked[entry["serial"]] = {
        "cert_id": cert_id, "cn": entry["cn"], "reason": reason,
        "revoked_at": datetime.datetime.utcnow().isoformat() + "Z",
    }
    _save_revoked(revoked)

    reg["certs"][cert_id]["revoked"] = True
    pki._save_registry(reg)
    pki._log_event(reg, f"Certificate {entry['cn']} (serial {entry['serial']}) REVOKED - reason: {reason}", level="warn")
    pki._save_registry(reg)

    _regenerate_crl()
    return True


def is_revoked(serial):
    revoked = _load_revoked()
    if serial in revoked:
        return True, revoked[serial]["reason"]
    return False, None


def list_revoked():
    return _load_revoked()


def _regenerate_crl():
    """Sign a fresh CRL with the Intermediate CA key, listing all revoked serials."""
    inter_key_path = pki.cert_full_path("intermediate/intermediate.key")
    inter_cert_path = pki.cert_full_path("intermediate/intermediate.crt")
    if not (os.path.exists(inter_key_path) and os.path.exists(inter_cert_path)):
        return  # PKI not built yet

    with open(inter_key_path, "rb") as f:
        inter_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(inter_cert_path, "rb") as f:
        inter_cert = x509.load_pem_x509_certificate(f.read())

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(inter_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )

    for serial_str, info in _load_revoked().items():
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial_str))
            .revocation_date(datetime.datetime.fromisoformat(info["revoked_at"].replace("Z", "")))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(private_key=inter_key, algorithm=hashes.SHA256())
    os.makedirs(os.path.dirname(CRL_PATH), exist_ok=True)
    with open(CRL_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    return CRL_PATH
