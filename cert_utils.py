"""
Certificate format detection and conversion utilities.
Supports: PEM, DER, PKCS#12/PFX, PKCS#7/P7B/P7C, CER, CRT
Everything happens in memory — no files are written to disk.

Password handling:
- Encrypted PKCS#12 / PFX uploads can be opened with a supplied password.
- PKCS#12 / PFX output can be encrypted with a supplied password.
"""
import re
import shutil
import subprocess
from typing import Tuple, Optional, List

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import OpenSSL.crypto as ossl

from security import MAX_CERTS_IN_CHAIN

# ---------------------------------------------------------------------------
# Format metadata
# ---------------------------------------------------------------------------

FORMAT_EXTENSIONS = {
    "PEM": "pem", "DER": "der", "PKCS12": "p12", "PFX": "pfx",
    "P7B": "p7b", "P7C": "p7c", "CER": "cer", "CRT": "crt",
}

FORMAT_DESCRIPTIONS = {
    "PEM": "PEM (Base64 ASCII)",
    "DER": "DER (Binary)",
    "PKCS12": "PKCS#12 / P12",
    "PFX": "PFX (PKCS#12 variant)",
    "P7B": "PKCS#7 / P7B",
    "P7C": "PKCS#7 / P7C",
    "CER": "CER (DER or PEM)",
    "CRT": "CRT (PEM or DER)",
}

MIME_TYPES = {
    "PEM": "application/x-pem-file",
    "DER": "application/x-x509-ca-cert",
    "PKCS12": "application/x-pkcs12",
    "PFX": "application/x-pkcs12",
    "P7B": "application/x-pkcs7-certificates",
    "P7C": "application/pkcs7-mime",
    "CER": "application/x-x509-ca-cert",
    "CRT": "application/x-x509-ca-cert",
}

_PKCS7_FORMATS = {"P7B", "P7C"}
_PKCS12_FORMATS = {"PKCS12", "PFX"}

_OPENSSL = shutil.which("openssl")

_CERT_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)

# DER object identifier for pkcs7-data (1.2.840.113549.1.7.1)
_PKCS7_DATA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _is_pem(data: bytes) -> bool:
    return b"-----BEGIN " in data

def _looks_like_pkcs12(data: bytes) -> bool:
    """Structural DER check for PKCS#12 PFX (works even when encrypted)."""
    if _is_pem(data):
        return False
    if data[:1] != b"\x30":
        return False
    if b"\x02\x01\x03" not in data[:24]:
        return False
    return _PKCS7_DATA_OID in data[:80]

def _is_pkcs7_der(data: bytes) -> bool:
    if _is_pem(data):
        return False
    try:
        ossl.load_pkcs7_data(ossl.FILETYPE_ASN1, data)
        return True
    except Exception:
        return False

def _is_der_cert(data: bytes) -> bool:
    if _is_pem(data):
        return False
    try:
        x509.load_der_x509_certificate(data)
        return True
    except Exception:
        return False


def detect_format(data: bytes, filename: str = "") -> Tuple[Optional[str], str, Optional[str]]:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if b"-----BEGIN PKCS7-----" in data:
        key = "P7C" if ext == "p7c" else "P7B"
        return key, FORMAT_DESCRIPTIONS[key], None

    if _is_pem(data):
        if b"BEGIN CERTIFICATE" in data or b"BEGIN X509" in data:
            if ext == "cer":
                return "CER", FORMAT_DESCRIPTIONS["CER"], None
            if ext == "crt":
                return "CRT", FORMAT_DESCRIPTIONS["CRT"], None
            return "PEM", FORMAT_DESCRIPTIONS["PEM"], None
        return None, "", "Unrecognised PEM block (expected CERTIFICATE or PKCS7)."

    if _looks_like_pkcs12(data):
        key = "PFX" if ext == "pfx" else "PKCS12"
        return key, FORMAT_DESCRIPTIONS[key], None

    if _is_pkcs7_der(data):
        key = "P7C" if ext == "p7c" else "P7B"
        return key, FORMAT_DESCRIPTIONS[key], None

    if _is_der_cert(data):
        if ext == "cer":
            return "CER", FORMAT_DESCRIPTIONS["CER"], None
        if ext == "crt":
            return "CRT", FORMAT_DESCRIPTIONS["CRT"], None
        return "DER", FORMAT_DESCRIPTIONS["DER"], None

    return None, "", ("Could not identify this as a certificate. "
                      "Supported: PEM, DER, PKCS#12/PFX, PKCS#7/P7B/P7C, CER, CRT.")


def is_encrypted_pkcs12(data: bytes) -> bool:
    """True if the file is a PKCS#12 that cannot be opened without a password."""
    if not _looks_like_pkcs12(data):
        return False
    for pwd in (b"", None):
        try:
            pkcs12.load_key_and_certificates(data, pwd)
            return False
        except Exception:
            continue
    return True


# ---------------------------------------------------------------------------
# Load certs
# ---------------------------------------------------------------------------

class PasswordRequired(Exception):
    """Raised when an encrypted PKCS#12 needs a password that wasn't supplied/correct."""


def _load_certs(data: bytes, src_fmt: str,
                password: Optional[bytes] = None) -> List[x509.Certificate]:
    certs: List[x509.Certificate] = []

    if src_fmt in ("PEM", "CER", "CRT"):
        for block in _CERT_BLOCK.findall(data):
            certs.append(x509.load_pem_x509_certificate(block))
            if len(certs) > MAX_CERTS_IN_CHAIN:
                raise ValueError("Too many certificates in file.")
        if not certs:
            certs.append(x509.load_pem_x509_certificate(data))

    elif src_fmt == "DER":
        certs.append(x509.load_der_x509_certificate(data))

    elif src_fmt in _PKCS12_FORMATS:
        candidates = [password] if password else [b"", None]
        loaded = None
        for pwd in candidates:
            try:
                loaded = pkcs12.load_key_and_certificates(data, pwd)
                break
            except Exception:
                continue
        if loaded is None:
            if _looks_like_pkcs12(data):
                raise PasswordRequired(
                    "This PKCS#12/PFX is password-protected or the password is incorrect."
                )
            raise ValueError("Could not read the PKCS#12/PFX file.")
        _, cert, chain = loaded
        if cert:
            certs.append(cert)
        if chain:
            certs.extend(chain[:MAX_CERTS_IN_CHAIN])

    elif src_fmt in _PKCS7_FORMATS:
        if not _OPENSSL:
            raise ValueError("Server missing openssl; cannot read PKCS#7.")
        proc = subprocess.run(
            [_OPENSSL, "pkcs7", "-print_certs"],
            input=data, capture_output=True, timeout=10,
        )
        if proc.returncode == 0 and proc.stdout:
            for block in _CERT_BLOCK.findall(proc.stdout):
                certs.append(x509.load_pem_x509_certificate(block))
                if len(certs) > MAX_CERTS_IN_CHAIN:
                    raise ValueError("Too many certificates in file.")

    if not certs:
        raise ValueError("No certificates found in file.")
    return certs


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

def convert_certificate(
    data: bytes,
    src_fmt: str,
    tgt_fmt: str,
    password: Optional[bytes] = None,
    output_password: Optional[bytes] = None,
) -> Tuple[Optional[bytes], str, Optional[str]]:
    """Returns (converted_bytes, mime_type, error_or_None)."""
    try:
        certs = _load_certs(data, src_fmt, password)
    except PasswordRequired as e:
        return None, "", str(e)
    except ValueError as e:
        return None, "", str(e)
    except Exception:
        return None, "", "Failed to parse the certificate."

    primary = certs[0]
    mime = MIME_TYPES[tgt_fmt]

    try:
        if tgt_fmt in ("PEM", "CER", "CRT"):
            out = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
            return out, mime, None

        if tgt_fmt == "DER":
            return primary.public_bytes(serialization.Encoding.DER), mime, None

        if tgt_fmt in _PKCS12_FORMATS:
            enc = (serialization.BestAvailableEncryption(output_password)
                   if output_password else serialization.NoEncryption())
            p12 = pkcs12.serialize_key_and_certificates(
                name=None, key=None, cert=primary,
                cas=certs[1:] if len(certs) > 1 else None,
                encryption_algorithm=enc,
            )
            return p12, mime, None

        if tgt_fmt in _PKCS7_FORMATS:
            if not _OPENSSL:
                return None, "", "Server missing openssl; cannot create PKCS#7."
            pem_chain = b"".join(
                c.public_bytes(serialization.Encoding.PEM) for c in certs
            )
            proc = subprocess.run(
                [_OPENSSL, "crl2pkcs7", "-nocrl", "-certfile", "/dev/stdin"],
                input=pem_chain, capture_output=True, timeout=10,
            )
            if proc.returncode == 0:
                return proc.stdout, mime, None
            return None, "", "PKCS#7 conversion failed."

    except Exception:
        return None, "", "Conversion failed."

    return None, "", f"Conversion to {tgt_fmt} is not supported."
