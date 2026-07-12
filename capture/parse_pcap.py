#!/usr/bin/env python3
"""
parse_pcap.py
Reads a pcap captured by capture_traffic.sh and produces a human-readable
TLS handshake summary: ClientHello, ServerHello, Certificate exchange,
negotiated cipher suite, and a plain packet count. Uses tshark as a
subprocess (no extra Python deps needed on Kali - tshark ships with
Wireshark).

Usage: python3 parse_pcap.py capture.pcap
"""
import json
import subprocess
import sys


HANDSHAKE_TYPES = {
    "1": "ClientHello", "2": "ServerHello", "11": "Certificate",
    "12": "ServerKeyExchange", "13": "CertificateRequest",
    "14": "ServerHelloDone", "15": "CertificateVerify",
    "16": "ClientKeyExchange", "20": "Finished",
}


def run_tshark_fields(pcap, display_filter, fields):
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    return [line.split("\t") for line in out.stdout.strip().splitlines() if line.strip()]


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_pcap.py <capture.pcap>")
        sys.exit(1)
    pcap = sys.argv[1]

    print(f"=== TLS handshake summary for {pcap} ===\n")

    rows = run_tshark_fields(
        pcap, "tls.handshake",
        ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tls.handshake.type"],
    )
    if not rows:
        print("No TLS handshake frames found in this capture.")
        print("Make sure the capture was running while the dashboard's")
        print("'Run TLS Test' button was clicked, and that the interface (lo) is correct.")
        return

    for r in rows:
        frame, t, src, dst, sport, dport, htype = (r + [""] * 7)[:7]
        label = HANDSHAKE_TYPES.get(htype, f"type {htype}")
        print(f"  frame {frame:>4}  t+{float(t or 0):6.3f}s  {src}:{sport} -> {dst}:{dport}   {label}")

    print("\n=== Negotiated parameters ===")
    cipher_rows = run_tshark_fields(pcap, "tls.handshake.type==2", ["tls.handshake.ciphersuite", "tls.handshake.version"])
    if cipher_rows:
        print(f"  Cipher suite : {cipher_rows[0][0]}")
        print(f"  TLS version  : {cipher_rows[0][1]}")
    else:
        print("  ServerHello not found in capture.")

    cert_count = len(run_tshark_fields(pcap, "tls.handshake.type==11", ["frame.number"]))
    print(f"  Certificate messages seen: {cert_count}")

    print("\nTip: open the same file in Wireshark GUI and filter on 'tls' for the full picture.")


if __name__ == "__main__":
    main()
