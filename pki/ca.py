"""
pki/ca.py
Builds a two-tier PKI hierarchy: Root CA -> Intermediate CA -> Leaf certs.
All key material lives under data/ as PEM files so the whole hierarchy can be
inspected with plain `openssl` commands too, not just this app.
"""
import datetime
import ipaddress
import json
import os
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
REGISTRY_PATH = os.path.join(DATA_DIR, "registry.json")

ROOT_VALID_DAYS = 3650       # 10 years - root is long-lived, kept "offline"
INTERMEDIATE_VALID_DAYS = 1825  # 5 years
LEAF_VALID_DAYS = 397        # matches real-world CA/Browser Forum max leaf lifetime


def _ensure_dirs():
    for sub in ("root", "intermediate", "leaf", "crl", "logs"):
        os.makedirs(os.path.join(DATA_DIR, sub), exist_ok=True)


def _new_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def _save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _load_registry():
    if os.path.exists(REGISTRY_PATH):
        with open(REGISTRY_PATH) as f:
            return json.load(f)
    return {"certs": {}, "events": []}


def _save_registry(reg):
    with open(REGISTRY_PATH, "w") as f:
        json.dump(reg, f, indent=2, default=str)


def _log_event(reg, message, level="info"):
    reg["events"].append({
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "level": level,
        "message": message,
    })


def _name(cn, org="Tendaji Labs", ou="Cybersecurity", country="KE"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def reset_pki():
    """Wipe all generated material and start a fresh hierarchy."""
    import shutil
    if os.path.exists(DATA_DIR):
        shutil.rmtree(DATA_DIR)
    _ensure_dirs()
    _save_registry({"certs": {}, "events": []})


def build_root_ca():
    _ensure_dirs()
    reg = _load_registry()

    key = _new_key(4096)
    subject = issuer = _name("Tendaji Root CA", ou="Root Certificate Authority")
    serial = x509.random_serial_number()
    now = datetime.datetime.utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=ROOT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=False, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())

    _save_key(key, os.path.join(DATA_DIR, "root", "root.key"))
    _save_cert(cert, os.path.join(DATA_DIR, "root", "root.crt"))

    cert_id = "root-ca"
    reg["certs"][cert_id] = {
        "id": cert_id, "role": "root", "cn": "Tendaji Root CA",
        "serial": str(serial), "key_path": "root/root.key", "cert_path": "root/root.crt",
        "issuer_id": None, "revoked": False,
    }
    _log_event(reg, "Root CA generated (RSA-4096, self-signed, 10yr validity).")
    _save_registry(reg)
    return cert_id


def build_intermediate_ca():
    reg = _load_registry()
    if "root-ca" not in reg["certs"]:
        raise RuntimeError("Root CA must be built first.")

    root_key = _load_private_key(os.path.join(DATA_DIR, "root", "root.key"))
    root_cert = _load_cert(os.path.join(DATA_DIR, "root", "root.crt"))

    key = _new_key(3072)
    subject = _name("Tendaji Intermediate CA", ou="Intermediate Certificate Authority")
    serial = x509.random_serial_number()
    now = datetime.datetime.utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=INTERMEDIATE_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://localhost:5000/crl/intermediate.crl")],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            critical=False,
        )
    )
    cert = builder.sign(root_key, hashes.SHA256())

    _save_key(key, os.path.join(DATA_DIR, "intermediate", "intermediate.key"))
    _save_cert(cert, os.path.join(DATA_DIR, "intermediate", "intermediate.crt"))

    cert_id = "intermediate-ca"
    reg["certs"][cert_id] = {
        "id": cert_id, "role": "intermediate", "cn": "Tendaji Intermediate CA",
        "serial": str(serial), "key_path": "intermediate/intermediate.key",
        "cert_path": "intermediate/intermediate.crt",
        "issuer_id": "root-ca", "revoked": False,
    }
    _log_event(reg, "Intermediate CA generated and signed by Root CA (RSA-3072).")
    _save_registry(reg)
    return cert_id


def issue_leaf_cert(cn, cert_type="server", sans=None, key_bits=2048):
    """cert_type: 'server' or 'client'."""
    reg = _load_registry()
    if "intermediate-ca" not in reg["certs"]:
        raise RuntimeError("Intermediate CA must be built first.")

    inter_key = _load_private_key(os.path.join(DATA_DIR, "intermediate", "intermediate.key"))
    inter_cert = _load_cert(os.path.join(DATA_DIR, "intermediate", "intermediate.crt"))

    key = _new_key(key_bits)
    subject = _name(cn, ou="Server" if cert_type == "server" else "Client")
    serial = x509.random_serial_number()
    now = datetime.datetime.utcnow()

    eku = ExtendedKeyUsageOID.SERVER_AUTH if cert_type == "server" else ExtendedKeyUsageOID.CLIENT_AUTH

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(inter_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=LEAF_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=True, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),
            critical=False,
        )
    )

    if cert_type == "server":
        san_list = [x509.DNSName(s) for s in (sans or ["localhost"])]
        san_list.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    cert = builder.sign(inter_key, hashes.SHA256())

    cert_id = f"{cert_type}-{uuid.uuid4().hex[:8]}"
    key_path = os.path.join(DATA_DIR, "leaf", f"{cert_id}.key")
    cert_path = os.path.join(DATA_DIR, "leaf", f"{cert_id}.crt")
    _save_key(key, key_path)
    _save_cert(cert, cert_path)

    reg["certs"][cert_id] = {
        "id": cert_id, "role": cert_type, "cn": cn,
        "serial": str(serial), "key_path": f"leaf/{cert_id}.key", "cert_path": f"leaf/{cert_id}.crt",
        "issuer_id": "intermediate-ca", "revoked": False,
    }
    _log_event(reg, f"Leaf {cert_type} certificate issued for CN={cn} (serial {serial}).")
    _save_registry(reg)
    return cert_id


def _load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def get_registry():
    return _load_registry()


def cert_full_path(rel_path):
    return os.path.join(DATA_DIR, rel_path)
