#!/usr/bin/env python3
"""Build a Matter Certification Declaration (CD) for a test device, signed with the public connectedhomeip
test CD signing key. Stdlib only (Python 3.8+); ECDSA P-256 with RFC 6979 deterministic nonces is
implemented here, so the output is byte-reproducible.

TEST MATERIAL ONLY. The signing key is the well-known connectedhomeip key
credentials/test/certification-declaration/Chip-Test-CD-Signing-Key.pem (CD signer SKI 62:FA:82:...).
A CD made with it certifies nothing; controllers treat the device as uncertified/test.

Wire format: Matter 1.3 core spec section 6.3.5 (CD TLV fields), 6.3.4 (CMS SignedData: version 3, SKI signer
identifier, SHA-256, ecdsa-with-SHA256, no signed attributes, no certificates, content = the TLV).
Layout matches the CD in connectedhomeip examples (kCdForAllExamples).

  matter_test_cd.py --key Chip-Test-CD-Signing-Key.pem --cert Chip-Test-CD-Signing-Cert.pem \
      --vid 0xFFF1 --pid 0x8000 --device-type 0x0301 -o cd.der
  matter_test_cd.py --parse cd.der [--cert signer.pem]       # decode + verify the signature
"""
import argparse
import base64
import hashlib
import hmac
import sys

from matter_p256 import G, N, point_add as _add, point_mul as _mul


def _bits2int(b):
    return int.from_bytes(b, "big")


def _rfc6979_k(d, h):
    x = d.to_bytes(32, "big")
    h1 = (_bits2int(h) % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        c = _bits2int(v)
        if 1 <= c < N:
            return c
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(d, msg):
    h = hashlib.sha256(msg).digest()
    z = _bits2int(h)
    k = _rfc6979_k(d, h)
    r = _mul(k, G)[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    return r, s


def ecdsa_verify(pub, msg, r, s):
    if not (0 < r < N and 0 < s < N):
        return False
    z = _bits2int(hashlib.sha256(msg).digest())
    w = pow(s, -1, N)
    pt = _add(_mul(z * w % N, G), _mul(r * w % N, pub))
    return pt is not None and pt[0] % N == r


# ---- DER --------------------------------------------------------------------------------------------------
def der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(nb)]) + nb
    return bytes([tag]) + ln + body


def der_read(buf, off=0):
    """-> (tag, body_start, body_end)"""
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        cnt = n & 0x7F
        n = int.from_bytes(buf[off:off + cnt], "big")
        off += cnt
    return tag, off, off + n


def der_uint(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return der(0x02, b)


def pem_to_der(path):
    txt = open(path).read().splitlines()
    return base64.b64decode("".join(l for l in txt if l and not l.startswith("-----")))


def ec_private_scalar(der_or_pem_path):
    """Private scalar from an EC key file (SEC1 ECPrivateKey or PKCS#8, DER or PEM)."""
    raw = open(der_or_pem_path, "rb").read()
    if raw.startswith(b"-----"):
        raw = pem_to_der(der_or_pem_path)
    tag, s, e = der_read(raw)
    assert tag == 0x30
    t, s2, e2 = der_read(raw, s)            # version
    s2 = e2
    t, s3, e3 = der_read(raw, s2)
    if t == 0x04:                           # SEC1: OCTET STRING privateKey follows version
        return int.from_bytes(raw[s3:e3], "big")
    # PKCS#8: AlgorithmIdentifier SEQ, then OCTET STRING containing SEC1
    t, s4, e4 = der_read(raw, e3)
    return ec_private_scalar_sec1(raw[s4:e4])


def ec_private_scalar_sec1(raw):
    tag, s, e = der_read(raw)
    t, s2, e2 = der_read(raw, s)
    t, s3, e3 = der_read(raw, e2)
    assert t == 0x04
    return int.from_bytes(raw[s3:e3], "big")


def cert_ski_and_pub(cert_path):
    """(subjectKeyIdentifier 20 bytes, (x, y)) from an X.509 cert (DER or PEM)."""
    raw = open(cert_path, "rb").read()
    if raw.startswith(b"-----"):
        raw = pem_to_der(cert_path)
    oid_ski = bytes.fromhex("0603551d0e")
    i = raw.index(oid_ski)
    j = raw.index(b"\x04\x14", i)           # OCTET STRING { OCTET STRING(20) }
    ski = raw[j + 2:j + 22]
    k = raw.rindex(b"\x03\x42\x00\x04", 0, len(raw))
    pt = raw[k + 4:k + 4 + 64]
    return ski, (int.from_bytes(pt[:32], "big"), int.from_bytes(pt[32:], "big"))


# ---- CD ---------------------------------------------------------------------------------------------------
OID_SIGNED_DATA = bytes.fromhex("06092a864886f70d010702")
OID_DATA = bytes.fromhex("06092a864886f70d010701")
ALG_SHA256 = bytes.fromhex("300b0609608648016503040201")
ALG_ECDSA_SHA256 = bytes.fromhex("300a06082a8648ce3d040302")


def tlv_uint(tag, v):
    if v < 0x100:
        return bytes([0x24, tag, v])
    if v < 0x10000:
        return bytes([0x25, tag]) + v.to_bytes(2, "little")
    return bytes([0x26, tag]) + v.to_bytes(4, "little")


def cd_tlv(vid, pids, device_type, cert_id, cert_type, version=1, sec_level=0, sec_info=0,
           dac_origin=None, paa_list=()):
    """Spec 6.3.5. Context tags: 0 format_version, 1 vendor_id, 2 product_id_array, 3 device_type_id,
    4 certificate_id (string, 19 chars), 5 security_level, 6 security_information, 7 version_number,
    8 certification_type, 9/10 dac_origin_vendor/product_id (optional), 11 authorized_paa_list (optional)."""
    assert len(cert_id) == 19 and 1 <= len(pids) <= 100
    out = bytearray(b"\x15")
    out += tlv_uint(0, 1)
    out += tlv_uint(1, vid)
    out += bytes([0x36, 2]) + b"".join(tlv_uint_anon(p) for p in pids) + b"\x18"
    out += tlv_uint(3, device_type)
    out += bytes([0x2C, 4, len(cert_id)]) + cert_id.encode("ascii")
    out += tlv_uint(5, sec_level) + tlv_uint(6, sec_info) + tlv_uint(7, version) + tlv_uint(8, cert_type)
    if dac_origin:
        out += tlv_uint(9, dac_origin[0]) + tlv_uint(10, dac_origin[1])
    if paa_list:
        out += bytes([0x36, 11]) + b"".join(bytes([0x10, 20]) + s for s in paa_list) + b"\x18"
    out += b"\x18"
    return bytes(out)


def tlv_uint_anon(v):
    return bytes([0x05]) + v.to_bytes(2, "little")      # anonymous uint16 (control 0x05)


def cms_sign(content, ski, d):
    r, s = ecdsa_sign(d, content)
    sig = der(0x30, der_uint(r) + der_uint(s))
    signer = der(0x30, der_uint(3) + der(0x80, ski) + ALG_SHA256 + ALG_ECDSA_SHA256 + der(0x04, sig))
    sd = der(0x30, der_uint(3) + der(0x31, ALG_SHA256)
             + der(0x30, OID_DATA + der(0xA0, der(0x04, content))) + der(0x31, signer))
    return der(0x30, OID_SIGNED_DATA + der(0xA0, sd))


def cms_parse(buf):
    """-> (content_tlv, signer_ski, r, s). Accepts only the Matter CD layout."""
    t, s, e = der_read(buf)
    assert t == 0x30 and e == len(buf), "trailing data or not a SEQUENCE"
    assert buf[s:s + len(OID_SIGNED_DATA)] == OID_SIGNED_DATA, "not signedData"
    p = s + len(OID_SIGNED_DATA)
    t, p, _ = der_read(buf, p)              # [0]
    t, p, _ = der_read(buf, p)              # SignedData SEQ
    t, a, b = der_read(buf, p)              # version
    assert buf[a:b] == b"\x03"
    t, a, b = der_read(buf, b)              # digestAlgorithms SET
    t, a2, b2 = der_read(buf, b)            # encapContentInfo SEQ
    assert buf[a2:a2 + len(OID_DATA)] == OID_DATA
    q = a2 + len(OID_DATA)
    t, q, _ = der_read(buf, q)              # [0]
    t, qa, qb = der_read(buf, q)            # OCTET STRING
    content = buf[qa:qb]
    t, a3, b3 = der_read(buf, b2)
    if t == 0xA0:                           # optional certificates: skip
        t, a3, b3 = der_read(buf, b3)
    assert t == 0x31, "signerInfos missing"
    t, si, sie = der_read(buf, a3)
    t, a, b = der_read(buf, si)             # version
    assert buf[a:b] == b"\x03"
    t, a, b = der_read(buf, b)
    assert t == 0x80, "signer identifier is not an SKI"
    ski = buf[a:b]
    t, a, b = der_read(buf, b)              # digestAlgorithm
    assert buf[a - 2:b] == ALG_SHA256
    t, a, b = der_read(buf, b)              # signatureAlgorithm
    assert buf[a - 2:b] == ALG_ECDSA_SHA256
    t, a, b = der_read(buf, b)              # signature OCTET STRING
    assert t == 0x04
    t, ra, rb = der_read(buf, a)            # ECDSA-Sig-Value SEQ
    t, x, y = der_read(buf, ra)
    r = int.from_bytes(buf[x:y], "big")
    t, x, y = der_read(buf, y)
    s_ = int.from_bytes(buf[x:y], "big")
    return content, ski, r, s_


def cd_decode(tlv):
    """Minimal decoder for the CD struct -> dict (context tags only, array of u16 / bytes / string)."""
    assert tlv[0] == 0x15 and tlv[-1] == 0x18
    i, out = 1, {}
    while tlv[i] != 0x18:
        ctl, tag = tlv[i], tlv[i + 1]
        i += 2
        et = ctl & 0x1F
        if et in (4, 5, 6):                  # uint 1/2/4
            n = {4: 1, 5: 2, 6: 4}[et]
            out[tag] = int.from_bytes(tlv[i:i + n], "little")
            i += n
        elif et == 0x0C:                     # utf8 string, 1-byte length
            n = tlv[i]
            out[tag] = tlv[i + 1:i + 1 + n].decode()
            i += 1 + n
        elif et == 0x16:                     # array
            arr = []
            while tlv[i] != 0x18:
                c = tlv[i]
                if c == 0x05:
                    arr.append(int.from_bytes(tlv[i + 1:i + 3], "little"))
                    i += 3
                elif c == 0x04:
                    arr.append(tlv[i + 1])
                    i += 2
                elif c == 0x10:
                    arr.append(bytes(tlv[i + 2:i + 2 + tlv[i + 1]]))
                    i += 2 + tlv[i + 1]
                else:
                    raise ValueError("array element %02x" % c)
            i += 1
            out[tag] = arr
        else:
            raise ValueError("TLV control %02x" % ctl)
    return out


NAMES = {0: "format_version", 1: "vendor_id", 2: "product_id_array", 3: "device_type_id", 4: "certificate_id",
         5: "security_level", 6: "security_information", 7: "version_number", 8: "certification_type",
         9: "dac_origin_vendor_id", 10: "dac_origin_product_id", 11: "authorized_paa_list"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", help="CD signing private key (PEM/DER, SEC1 or PKCS#8)")
    ap.add_argument("--cert", help="CD signer certificate (PEM/DER): SKI for signing, public key for --parse")
    ap.add_argument("--vid", type=lambda x: int(x, 0), default=0xFFF1)
    ap.add_argument("--pid", type=lambda x: int(x, 0), action="append", help="repeatable; default 0x8000")
    ap.add_argument("--device-type", type=lambda x: int(x, 0), default=0x0301)
    ap.add_argument("--cert-id", default="CSA00000SWC00000-00")
    ap.add_argument("--cert-type", type=int, default=0, help="0 test (default), 1 provisional, 2 official")
    ap.add_argument("-o", "--out")
    ap.add_argument("--parse", metavar="CD.der", help="decode a CD and verify its signature (needs --cert)")
    a = ap.parse_args()

    if a.parse:
        buf = open(a.parse, "rb").read()
        content, ski, r, s = cms_parse(buf)
        print("signer SKI:", ski.hex())
        for k, v in sorted(cd_decode(content).items()):
            if isinstance(v, list) and len(v) > 4:
                v = "[%s .. %s] (%d entries)" % (hex(v[0]), hex(v[-1]), len(v))
            print("  %-22s %s" % (NAMES.get(k, k), hex(v) if isinstance(v, int) else v))
        if a.cert:
            cski, pub = cert_ski_and_pub(a.cert)
            ok = cski == ski and ecdsa_verify(pub, content, r, s)
            print("signature:", "OK" if ok else "BAD (SKI %s)" % ("match" if cski == ski else "mismatch"))
            return 0 if ok else 1
        return 0

    if not (a.key and a.cert and a.out):
        ap.error("--key, --cert and -o are required to build a CD")
    ski, _ = cert_ski_and_pub(a.cert)
    tlv = cd_tlv(a.vid, a.pid or [0x8000], a.device_type, a.cert_id, a.cert_type)
    cd = cms_sign(tlv, ski, ec_private_scalar(a.key))
    open(a.out, "wb").write(cd)
    print("wrote %s (%d bytes), signer SKI %s" % (a.out, len(cd), ski.hex()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
