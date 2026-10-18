#!/usr/bin/env python3
"""Generate HomeKit setup credentials: setup code, setup ID, SRP-6a salt + verifier, X-HM:// payload.

Writes a C header with the salt/verifier (secret-adjacent: the verifier lets an attacker brute-force the
8-digit code offline, so keep it out of version control) and prints the setup code and URI to stdout.

  tools/hap_setup.py out.h [--category 8] [--adk vendor/HomeKitADK]

Self-check always runs: verifier recomputed client-side, group sanity, payload decode round trip. With --adk
(and a host cc) the payload and code validity are also compared against the ADK's own C implementation.
Python 3 standard library only.
"""
import argparse, hashlib, os, secrets, subprocess, sys, tempfile

# RFC 5054 3072-bit group (same prime as the ADK's N_3072), generator 5.
N_HEX = (
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33"
    "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864"
    "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2"
    "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"
)
N = int(N_HEX, 16)
G = 5
SALT_BYTES, VERIFIER_BYTES = 16, 384
USERNAME = "Pair-Setup"


def sha512(*parts):
    return hashlib.sha512(b"".join(parts)).digest()


def srp_x(salt, code):
    return int.from_bytes(sha512(salt, sha512(USERNAME.encode() + b":" + code.encode())), "big")


def srp_verifier(salt, code):
    return pow(G, srp_x(salt, code), N).to_bytes(VERIFIER_BYTES, "big")


def valid_setup_code(code):
    """Mirrors HAPAccessorySetupIsValidSetupCode."""
    if len(code) != 10 or code[3] != "-" or code[6] != "-":
        return False
    d = code.replace("-", "")
    if not d.isdigit() or not d.isascii():
        return False
    eq = sum(d[i] == d[i - 1] for i in range(1, 8))
    asc = sum(ord(d[i]) == ord(d[i - 1]) + 1 for i in range(1, 8))
    desc = sum(ord(d[i]) == ord(d[i - 1]) - 1 for i in range(1, 8))
    # The ADK counts the first digit against previous '\0', which never matches; same here.
    return eq != 7 and not (d[0] == "1" and asc == 7) and not (d[0] == "8" and desc == 7)


def random_setup_code():
    while True:
        d = "%08d" % secrets.randbelow(10**8)
        code = "%s-%s-%s" % (d[:3], d[3:5], d[5:])
        if valid_setup_code(code):
            return code


def random_setup_id():
    return "".join(secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(4))


def setup_payload(code, setup_id, category, ip=True, ble=False):
    """Mirrors HAPAccessorySetupGetSetupPayload (unpaired)."""
    v = (category & 0xFF) << 31 | int(ble) << 29 | int(ip) << 28 | int(code.replace("-", ""))
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    s = ""
    for _ in range(9):
        v, r = divmod(v, 36)
        s = digits[r] + s
    return "X-HM://" + s + setup_id


def decode_payload(uri):
    v = int(uri[7:16], 36)
    return {"code": "%08d" % (v & (2**27 - 1)), "ip": bool(v >> 28 & 1), "ble": bool(v >> 29 & 1),
            "paired": bool(v >> 27 & 1), "category": v >> 31 & 0xFF, "version": v >> 43, "id": uri[16:]}


def is_probable_prime(n, rounds=8):
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = pow(2 + secrets.randbelow(n - 4), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def self_check(code, setup_id, category, salt, verifier, uri):
    # Group: right size, probable prime, RFC 5054/3526 structure (top and bottom 64 bits all ones).
    assert N.bit_length() == 3072 and N >> 3008 == 2**64 - 1 and N & (2**64 - 1) == 2**64 - 1
    assert is_probable_prime(N) and is_probable_prime((N - 1) // 2, 4), "group is not a safe prime"
    # Client side of SRP-6a: x from the password, A = g^a, S = (B - k g^x)^(a + u x), must equal the
    # server's S = (A v^u)^b computed from the stored verifier only.
    pad = lambda n: n.to_bytes(VERIFIER_BYTES, "big")
    k = int.from_bytes(sha512(pad(N), pad(G)), "big")
    x = srp_x(salt, code)
    a, b = secrets.randbits(256), secrets.randbits(256)
    A = pow(G, a, N)
    v = int.from_bytes(verifier, "big")
    B = (k * v + pow(G, b, N)) % N
    u = int.from_bytes(sha512(pad(A), pad(B)), "big")
    client = pow((B - k * pow(G, x, N)) % N, a + u * x, N)
    server = pow(A * pow(v, u, N) % N, b, N)
    assert client == server, "SRP client/server secrets differ"
    assert len(salt) == SALT_BYTES and len(verifier) == VERIFIER_BYTES
    # Payload round trip.
    d = decode_payload(uri)
    assert d == {"code": code.replace("-", ""), "ip": True, "ble": False, "paired": False,
                 "category": category, "version": 0, "id": setup_id}, d
    # Code validity rules.
    for bad in ("000-00-000", "111-11-111", "123-45-678", "876-54-321", "999-99-999", "12-345-678", "abc-de-fgh"):
        assert not valid_setup_code(bad), bad
    assert valid_setup_code("518-20-410") and valid_setup_code("123-45-679")


HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include "HAPPlatform.h"
#include "HAPAccessorySetup.h"
int main(int argc, char** argv) {
    HAPSetupCode code; HAPSetupID id; HAPSetupPayload p;
    snprintf(code.stringValue, sizeof code.stringValue, "%s", argv[1]);
    snprintf(id.stringValue, sizeof id.stringValue, "%s", argv[2]);
    HAPAccessorySetupGetSetupPayload(&p, &code, &id,
        (HAPAccessorySetupSetupPayloadFlags) { .ipSupported = true }, (HAPAccessoryCategory) atoi(argv[3]));
    printf("%d %d %s\n", HAPAccessorySetupIsValidSetupCode(argv[1]), HAPAccessorySetupIsValidSetupID(argv[2]),
           p.stringValue);
    return 0;
}
'''


def adk_check(adk, code, setup_id, category, uri):
    """Compile the ADK's HAPAccessorySetup.c natively and compare with this tool's output."""
    with tempfile.TemporaryDirectory() as tmp:
        h = os.path.join(tmp, "h.c")
        open(h, "w").write(HARNESS)
        stub = os.path.join(tmp, "stub.c")
        open(stub, "w").write('#include "HAPPlatform.h"\nvoid HAPPlatformRandomNumberFill(void* b, size_t n){(void)b;(void)n;}\n')
        pal = os.path.join(adk, "PAL")
        srcs = [os.path.join(adk, "HAP", "HAPAccessorySetup.c")] + sorted(
            os.path.join(pal, f) for f in os.listdir(pal) if f.startswith("HAPBase") and f.endswith(".c"))
        # Crypto, log and abort symbols are unresolved but never called by the code under test.
        ignore = "-Wl,-undefined,dynamic_lookup" if sys.platform == "darwin" else "-Wl,--unresolved-symbols=ignore-all"
        exe = os.path.join(tmp, "h")
        cmd = ["cc", "-w", "-DHAP_LOG_LEVEL=0", "-I" + pal, "-I" + os.path.join(adk, "HAP")] + [
            "-I" + os.path.join(adk, "External", d) for d in ("HTTP", "JSON", "Base64")] + [h, stub] + srcs + [ignore, "-o", exe]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            print("ADK cross-check skipped (host build failed):\n" + r.stderr[-600:], file=sys.stderr)
            return False
        out = subprocess.run([exe, code, setup_id, str(category)], capture_output=True, text=True).stdout.split()
        assert out == ["1", "1", uri], "ADK says %s, tool says %s" % (out, uri)
        for bad in ("000-00-000", "111-11-111", "123-45-678", "876-54-321", "999-99-999", "123-45-679", code):
            got = subprocess.run([exe, bad, "AB12", "8"], capture_output=True, text=True).stdout.split()[0] == "1"
            assert got == valid_setup_code(bad), "code validity differs for " + bad
        return True


def c_bytes(data):
    """Brace list for a byte array, one line per 12 bytes, continued for use inside a #define."""
    lines = ["        " + ", ".join("0x%02x" % b for b in data[i:i + 12]) + ", \\" for i in range(0, len(data), 12)]
    return "{ \\\n%s\n    }" % "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("header", help="C header to write")
    ap.add_argument("--category", type=int, default=8, help="HAP accessory category (default 8 = switch)")
    ap.add_argument("--adk", help="HomeKitADK directory, enables the native cross-check")
    args = ap.parse_args()

    code, setup_id = random_setup_code(), random_setup_id()
    salt = secrets.token_bytes(SALT_BYTES)
    verifier = srp_verifier(salt, code)
    uri = setup_payload(code, setup_id, args.category)
    self_check(code, setup_id, args.category, salt, verifier, uri)
    adk = adk_check(args.adk, code, setup_id, args.category, uri) if args.adk else False

    with open(args.header, "w") as f:
        f.write("// Generated by tools/hap_setup.py. Contains SRP verifier: do not commit.\n"
                "#ifndef HAP_SETUP_INFO_H\n#define HAP_SETUP_INFO_H\n\n"
                '#define HAP_SETUP_ID "%s"\n\n' % setup_id)
        f.write("// Initializer for a const HAPSetupInfo.\n#define HAP_SETUP_INFO_INIT { \\\n    .salt = %s, \\\n"
                "    .verifier = %s \\\n}\n" % (c_bytes(salt), c_bytes(verifier)))
        f.write("\n#endif\n")
    os.chmod(args.header, 0o600)
    print("setup code: %s\nsetup id:   %s\npayload:    %s" % (code, setup_id, uri))
    print("self-check ok%s" % ("; ADK cross-check ok" if adk else ""), file=sys.stderr)


if __name__ == "__main__":
    main()
