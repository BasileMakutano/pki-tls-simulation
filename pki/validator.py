
import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

from . import ca as pki
from . import revocation


def _load_cert(rel_path):
    with open(pki.cert_full_path(rel_path), "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _step(name, ok, detail):
    return {"check": name, "passed": ok, "detail": detail}


def validate_chain(cert_id):
    reg = pki.get_registry()
    if cert_id not in reg["certs"]:
        return {"valid": False, "steps": [_step("lookup", False, f"No such certificate: {cert_id}")]}

    steps = []
    overall_ok = True

    entry = reg["certs"][cert_id]
    cert = _load_cert(entry["cert_path"])
    steps.append(_step("Certificate loaded", True, f"CN={entry['cn']}, serial={entry['serial']}"))

    # Build the chain: leaf -> intermediate -> root
    chain_ids = [cert_id]
    cursor = entry
    while cursor.get("issuer_id"):
        chain_ids.append(cursor["issuer_id"])
        cursor = reg["certs"][cursor["issuer_id"]]

    chain_certs = [_load_cert(reg["certs"][cid]["cert_path"]) for cid in chain_ids]

    # 1. Chain completeness - does it terminate at a self-signed root?
    root_cert = chain_certs[-1]
    terminates_at_root = root_cert.issuer == root_cert.subject
    steps.append(_step(
        "Chain terminates at a self-signed root",
        terminates_at_root,
        f"Chain depth {len(chain_certs)}: " + " -> ".join(reg["certs"][c]["cn"] for c in chain_ids),
    ))
    overall_ok &= terminates_at_root

    # 2. Signature verification, hop by hop (child signed by parent's private key)
    for i in range(len(chain_certs) - 1):
        child, parent = chain_certs[i], chain_certs[i + 1]
        try:
            parent_pub = parent.public_key()
            parent_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
            steps.append(_step(
                f"Signature valid: {reg['certs'][chain_ids[i]]['cn']} <- signed by <- {reg['certs'][chain_ids[i+1]]['cn']}",
                True, "Signature cryptographically verified with issuer's public key.",
            ))
        except InvalidSignature:
            steps.append(_step(
                f"Signature check for {reg['certs'][chain_ids[i]]['cn']}",
                False, "INVALID - signature does not match issuer's public key.",
            ))
            overall_ok = False

    # Root self-signature
    try:
        root_cert.public_key().verify(
            root_cert.signature, root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), root_cert.signature_hash_algorithm,
        )
        steps.append(_step("Root self-signature valid", True, "Root CA's self-signature verified against its own public key."))
    except InvalidSignature:
        steps.append(_step("Root self-signature valid", False, "Root certificate is corrupt or tampered."))
        overall_ok = False

    # 3. BasicConstraints / path length on every CA in the chain
    for cid in chain_ids[1:]:
        c = _load_cert(reg["certs"][cid]["cert_path"])
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
            ok = bc.ca is True
            steps.append(_step(
                f"BasicConstraints CA=True for {reg['certs'][cid]['cn']}",
                ok, f"ca={bc.ca}, path_length={bc.path_length}",
            ))
            overall_ok &= ok
        except x509.ExtensionNotFound:
            steps.append(_step(f"BasicConstraints present for {reg['certs'][cid]['cn']}", False, "Extension missing."))
            overall_ok = False

    # 4. Validity window for every cert in the chain
    now = datetime.datetime.utcnow()
    for cid in chain_ids:
        c = _load_cert(reg["certs"][cid]["cert_path"])
        not_before = c.not_valid_before_utc.replace(tzinfo=None) if hasattr(c, "not_valid_before_utc") else c.not_valid_before
        not_after = c.not_valid_after_utc.replace(tzinfo=None) if hasattr(c, "not_valid_after_utc") else c.not_valid_after
        ok = not_before <= now <= not_after
        steps.append(_step(
            f"Validity window OK for {reg['certs'][cid]['cn']}",
            ok, f"Valid {not_before.date()} to {not_after.date()}, checked at {now.date()}",
        ))
        overall_ok &= ok

    # 5. Key usage sanity on the leaf
    leaf = chain_certs[0]
    try:
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        ok = ku.digital_signature
        steps.append(_step("Leaf KeyUsage includes digitalSignature", ok, str(ku)))
        overall_ok &= ok
    except x509.ExtensionNotFound:
        steps.append(_step("Leaf KeyUsage present", False, "Extension missing."))
        overall_ok = False

    # 6. Revocation check against CRL for every cert in the chain (except root)
    for cid in chain_ids[:-1]:
        c_entry = reg["certs"][cid]
        revoked, reason = revocation.is_revoked(c_entry["serial"])
        steps.append(_step(
            f"CRL check for {c_entry['cn']}",
            not revoked,
            ("REVOKED - " + reason) if revoked else "Serial not present on current CRL.",
        ))
        overall_ok &= (not revoked)

    return {"valid": overall_ok, "chain": [reg["certs"][c]["cn"] for c in chain_ids], "steps": steps}
