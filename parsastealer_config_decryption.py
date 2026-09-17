#!/usr/bin/env python3
"""Static config recovery for the UMPDC / ParsaStealer Rust infostealer family.

Auto-discovers the config-obfuscation scheme, its key and its call sites, so
one tool covers every build generation observed in the wild. Five schemes are
supported, tried in the order below:

  ascii-hex + single-byte XOR   config stored as a hex string in .rdata,
                                hex-decoded then XORed with one byte
  raw bytes, subtract + XOR     same wrapper thunks, no hex layer
  AES-256-GCM                   32-byte key baked in, 12-byte nonce per string
  ChaCha20-Poly1305             same calling convention as AES-GCM
  word-xor16                    not a cipher: plain[i] = blob[2i] ^ blob[2i+1]

Later builds moved most of the target list out of the encrypted blob into bare
Rust &str literals, so a plaintext-literal pass always runs as well and its
results are merged into the same report, tagged with a different source.

Output is one fixed schema regardless of which scheme matched: the same
category sections in the same order every run, counts always shown, empty
categories still printed. Diagnostics go to stderr, so stdout stays parseable.
--json emits the identical data as a single object.

Usage:
    parsastealer_config.py <sample.dll> [--json] [--scan-only]
                           [--key HEX] [--func 0xVA] [--cipher NAME]

Requires: capstone (call-site discovery), cryptography (AEAD schemes).
Both are optional; without them the non-AEAD schemes still work.
"""

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import OrderedDict

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

TOOL = "parsastealer-config"
VERSION = "1.0"


def log(msg):
    """Diagnostics go to stderr so stdout stays a clean, parseable report."""
    print(msg, file=sys.stderr)

CIPHERS = {}
if HAVE_CRYPTOGRAPHY:
    CIPHERS = {
        "aes-gcm": AESGCM,
        "chacha20-poly1305": ChaCha20Poly1305,
    }


# ---------------------------------------------------------------------------
# Scheme: ASCII-hex + single-byte XOR
# ---------------------------------------------------------------------------
# Config items are stored in .rdata as ASCII hex, hex-decoded at runtime and
# XORed with one constant byte, then split on NUL into a Vec<String>. Each item
# gets its own wrapper thunk with the arguments baked in as immediates, which
# is what makes it statically recoverable:
#
#   488D15 <disp32>   LEA  RDX, [rip+disp]   ; -> ASCII hex blob
#   41B8   <imm32>    MOV  R8D, hex_len
#   41B1   <imm8>     MOV  R9B, xor_key
#   E8     <rel32>    CALL decoder
#
# The AEAD fingerprint never matches this: R9B holds an immediate byte, not a
# pointer to a 12-byte nonce. The MOV R8D length immediate also gives the exact
# blob boundary, which matters because Rust packs adjacent literals with no
# separator - without it a greedy scan welds a plaintext URL onto the encrypted
# blob that follows it and reports the concatenation as a C2 address.
#
# Two recovery paths, so a rebuild that inlines the thunks still decodes:
#   find_hexxor_thunks()   instruction-pattern scan; exact length and true key
#   brute_hexxor_blobs()   any unclaimed ASCII-hex run, all 256 keys, keep the
#                          one whose plaintext scores as real config text

def _safe(s):
    r"""Escape control characters before printing.

    Not cosmetic: the config contains a literal carriage return in
    "%AppData%\FileZilla\<CR>recentservers.xml" - a malware-author bug (a Rust
    "\r" where "\\r" was meant, so the path can never match the real file).
    Printed raw the terminal overwrites the line and it silently reads as
    "...\ecentservers.xml". The hex+XOR and plaintext-literal decoders both
    produce it identically, which is a useful cross-check that they agree.
    """
    return (s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
            if any(c in s for c in "\r\n\t") else s)


HEX_CHARS = frozenset(b"0123456789abcdefABCDEF")

# printable + NUL (the record separator this scheme uses) + tab/newline
_GOOD_PLAIN = frozenset(range(0x20, 0x7F)) | {0x00, 0x09, 0x0A, 0x0D}
# characters that actually show up in this family's config strings
_CONFIG_CHARS = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b"%\\/.*_-: ()[]{}@+#'\"?=,;!$&~|" + b"\x00"
)


def _hex_run_len(raw, off, limit=None):
    """Length of the ASCII-hex run starting at file offset `off`."""
    n = 0
    end = len(raw) if limit is None else min(len(raw), off + limit)
    while off + n < end and raw[off + n] in HEX_CHARS:
        n += 1
    return n


def _hexxor_decode(raw, sections, blob_rva, hex_len, key):
    off = rva_to_offset(sections, blob_rva)
    if off is None:
        return None
    hex_len -= hex_len & 1                      # must be an even number of nibbles
    chunk = raw[off:off + hex_len]
    if len(chunk) != hex_len or not chunk:
        return None
    if any(c not in HEX_CHARS for c in chunk):
        return None
    try:
        data = bytes.fromhex(chunk.decode("ascii"))
    except ValueError:
        return None
    return bytes(b ^ key for b in data)


def score_hexxor_plaintext(buf):
    """0..1 confidence that `buf` is decoded config text rather than noise."""
    if not buf:
        return 0.0
    good = sum(1 for b in buf if b in _GOOD_PLAIN)
    if good != len(buf):                        # any non-printable byte -> wrong key
        return 0.0
    conf = sum(1 for b in buf if b in _CONFIG_CHARS) / len(buf)
    alnum = sum(1 for b in buf if chr(b).isalnum()) / len(buf)
    # real config is mostly alphanumeric with path punctuation; random
    # single-byte-XOR collisions land in dense punctuation instead.
    return 0.0 if alnum < 0.35 else (conf * 0.5 + alnum * 0.5)


# ---------------------------------------------------------------------------
# Scheme: raw bytes, subtract then XOR
# ---------------------------------------------------------------------------
# A later generation keeps the identical thunk shape but drops the ASCII-hex
# layer and adds an arithmetic step:
#
#     plaintext[i] = ((blob[i] - 0x11) & 0xff) ^ key
#
# The blob is raw bytes, so the "must look like ASCII hex" precondition above
# rejects these thunks and the sample falls through to the plaintext-literal
# pass - which recovers the exfil paths but makes the build look as though it
# has no Telegram channel at all. It has one, and it is the same bot token the
# rest of the family uses.
#
# The constant and the operation order are solved per binary rather than
# hardcoded, since a rebuild can change either: the key comes from the thunk's
# own immediate, and (order, offset) is chosen by scoring the result.
#
# Unexplained discrepancy, recorded deliberately: the compiled decoder loop
# disassembles as XOR bpl,bl / ADD bpl,0x11, i.e. ((s ^ key) + 0x11), which is
# not the inverse of how the data is actually encoded and yields garbage. The
# inverse order, ((s - 0x11) ^ key), yields clean text for every blob in every
# sample of this cluster, including a bot token byte-identical to sibling
# builds. The empirical result is used here; do not quote the on-disk
# instruction order as the algorithm without re-deriving it.

def _apply_transform(data, key, offset, order):
    if order == "sub-xor":
        return bytes((((b - offset) & 0xFF) ^ key) for b in data)
    if order == "xor-add":
        return bytes((((b ^ key) + offset) & 0xFF) for b in data)
    if order == "xor-only":
        return bytes((b ^ key) for b in data)
    raise ValueError(order)


_TRANSFORM_ORDERS = ("xor-only", "sub-xor", "xor-add")


def solve_transform_global(blobs):
    """Solve (order, offset) ONCE across every blob in the binary.

    Solving per blob does not work: short blobs ("sendPhoto", a 10-digit chat
    ID) are printable under many (order, offset) combinations, so each one
    picks its own plausible-looking but wrong constant and the output comes out
    as near-miss mojibake ("kwwsv=22dsl1whohjudp1ruj2erw" instead of
    "https://api.telegram.org/bot"). The constant is a build-wide property, so
    it must be chosen by aggregate score over all blobs - the long blobs then
    dominate and pin down the right value for the short ones.

    `blobs` is a list of (data, key). Returns (order, offset) or None.
    """
    best = None
    for order in _TRANSFORM_ORDERS:
        offsets = (0,) if order == "xor-only" else range(256)
        for off in offsets:
            total = 0.0
            ok = 0
            for data, key in blobs:
                sc = score_hexxor_plaintext(_apply_transform(data, key, off, order))
                if sc <= 0:
                    total = -1
                    break
                total += sc * len(data)      # weight by length
                ok += 1
            if total > 0 and ok == len(blobs) and (best is None or total > best[0]):
                best = (total, order, off)
    return (best[1], best[2]) if best else None


def find_raw_xor_thunks(raw, sections, image_base, text_sec):
    """Recover config blobs stored as raw XOR+offset bytes (GOTCHA #7).

    Matches the strict thunk encoding emitted for these builds:
        48 8D 15 <disp32>   LEA RDX, [rip+blob]
        41 B8   <imm32>     MOV R8D, length
        41 B1   <imm8>      MOV R9B, key
        E8      <rel32>     CALL decoder
    Being strict here is deliberate: the blob is arbitrary binary, so there is
    no "looks like hex" sanity check available to reject coincidental matches,
    and the decoded-text score is the only filter left.
    """
    base = image_base + text_sec["vaddr"]
    off0 = text_sec["rawptr"]
    code = raw[off0:off0 + text_sec["rawsize"]]

    cands = OrderedDict()
    for i in range(len(code) - 25):
        if code[i] != 0x48 or code[i + 1] != 0x8D or code[i + 2] != 0x15:
            continue
        if code[i + 7] != 0x41 or code[i + 8] != 0xB8:
            continue
        if code[i + 13] != 0x41 or code[i + 14] != 0xB1:
            continue
        if code[i + 16] != 0xE8:
            continue

        blob_va = base + i + 7 + struct.unpack_from("<i", code, i + 3)[0]
        length = struct.unpack_from("<I", code, i + 9)[0]
        key = code[i + 15]
        decoder_va = base + i + 21 + struct.unpack_from("<i", code, i + 17)[0]

        if not (2 <= length <= 8192):
            continue
        off = rva_to_offset(sections, blob_va - image_base)
        if off is None:
            continue
        data = raw[off:off + length]
        if len(data) != length:
            continue
        cands[(blob_va, length, key)] = (base + i, decoder_va, data)

    if not cands:
        return []

    # All thunks in a build share one decoder, so they share one transform.
    solved = solve_transform_global([(v[2], k[2]) for k, v in cands.items()])
    if solved is None:
        return []
    order, offset = solved

    out = []
    for (blob_va, length, key), (site_va, decoder_va, data) in cands.items():
        out.append({
            "site_va": site_va,
            "blob_va": blob_va,
            "blob_rva": blob_va - image_base,
            "hex_len": length,
            "key": key,
            "plain": _apply_transform(data, key, offset, order),
            "how": f"raw:{order}"
                   + (f"-0x{offset:02x}" if order != "xor-only" else "")
                   + f" via {hex(decoder_va)}",
        })
    return out


def find_hexxor_thunks(raw, sections, image_base, text_sec):
    """Recover (blob_rva, hex_len, key) triples from the per-item wrapper thunks.

    Scans for the rip-relative LEA that points at an ASCII-hex run and then
    looks ahead a short window for the MOV r8d,imm32 length and MOV r9b,imm8
    key. Anchoring on the LEA (rather than on the CALL, as v9 did) keeps this
    resync-safe against the inline data Rust embeds in .text, and does not
    require resolving the decoder function at all.
    """
    base = image_base + text_sec["vaddr"]
    off0 = text_sec["rawptr"]
    code = raw[off0:off0 + text_sec["rawsize"]]
    found = OrderedDict()

    for i in range(len(code) - 24):
        # REX.W LEA reg, [rip+disp32]   (48/4C 8D /5)
        if code[i] not in (0x48, 0x4C) or code[i + 1] != 0x8D:
            continue
        if (code[i + 2] & 0xC7) != 0x05:
            continue
        disp = struct.unpack_from("<i", code, i + 3)[0]
        blob_va = base + i + 7 + disp
        blob_rva = blob_va - image_base
        blob_off = rva_to_offset(sections, blob_rva)
        if blob_off is None:
            continue
        # cheap reject: must look like ASCII hex straight away
        if _hex_run_len(raw, blob_off, 16) < 16:
            continue
        run = _hex_run_len(raw, blob_off)

        # look ahead for MOV r8d/r8b (length) and MOV r9b/r9d (key)
        window = code[i + 7:i + 7 + 24]
        hex_len = key = None
        j = 0
        while j < len(window) - 2:
            if window[j] == 0x41 and window[j + 1] == 0xB8 and j + 6 <= len(window):
                hex_len = struct.unpack_from("<I", window, j + 2)[0]
                j += 6
                continue
            if window[j] == 0x41 and window[j + 1] == 0xB1:      # MOV R9B, imm8
                key = window[j + 2]
                j += 3
                continue
            if window[j] == 0x41 and window[j + 1] == 0xB9 and j + 6 <= len(window):
                key = struct.unpack_from("<I", window, j + 2)[0] & 0xFF
                j += 6
                continue
            j += 1

        if hex_len is None or key is None:
            continue
        if hex_len < 4 or hex_len > run:
            # length immediate must not overrun the actual hex run; if it does
            # this LEA/MOV coincidence is not a real config thunk.
            continue
        pt = _hexxor_decode(raw, sections, blob_rva, hex_len, key)
        if pt is None or score_hexxor_plaintext(pt) < 0.55:
            continue
        found[(blob_rva, hex_len, key)] = {
            "site_va": base + i,
            "blob_va": blob_va,
            "blob_rva": blob_rva,
            "hex_len": hex_len,
            "key": key,
            "plain": pt,
            "how": "thunk",
        }
    return list(found.values())


def brute_hexxor_blobs(raw, sections, claimed, min_hex=64):
    """Fallback: brute force any ASCII-hex run not already claimed by a thunk.

    `claimed` is the set of (rva, hex_len) ranges recovered from thunks. Used
    when a rebuild inlines the wrapper thunk so no length/key immediate pair
    survives to be read directly.
    """
    out = []
    taken = []
    for c in claimed:
        taken.append((c["blob_rva"], c["blob_rva"] + c["hex_len"]))

    for s in sections:
        if s["name"] not in (".rdata", ".data"):
            continue
        start, end = s["rawptr"], s["rawptr"] + s["rawsize"]
        i = start
        while i < end:
            if raw[i] not in HEX_CHARS:
                i += 1
                continue
            n = _hex_run_len(raw, i, end - i)
            if n >= min_hex:
                rva = s["vaddr"] + (i - s["rawptr"])
                if not any(a <= rva < b for a, b in taken):
                    best = None
                    for k in range(256):
                        pt = _hexxor_decode(raw, sections, rva, n, k)
                        if pt is None:
                            continue
                        sc = score_hexxor_plaintext(pt)
                        if sc >= 0.60 and (best is None or sc > best[0]):
                            best = (sc, k, pt)
                    if best:
                        sc, k, pt = best
                        out.append({
                            "site_va": None,
                            "blob_va": None,
                            "blob_rva": rva,
                            "hex_len": n - (n & 1),
                            "key": k,
                            "plain": pt,
                            "how": f"brute(score={sc:.2f})",
                        })
            i += max(n, 1)
    return out


# ---------------------------------------------------------------------------
# Plaintext Rust &str literal recovery
# ---------------------------------------------------------------------------
# Some builds encrypt only the Telegram credentials and leave the entire
# exfiltration target list - several hundred %AppData%\... glob patterns - as
# plain Rust &str literals. Those show up in a `strings` dump but are useless
# as-is: Rust packs adjacent literals back-to-back with no terminator, so
#     "%AppData%\FileZilla\sitemanager.xml" "%AppData%\recentservers.xml"
# is one unbroken byte run and any regex extraction welds them together.
#
# The lengths are not in the data at all - they are in the code. Rust
# materialises a &str as a (pointer, length) register pair:
#
#     488D0D <disp32>   LEA  RCX, [rip+disp]   ; -> literal bytes
#     41B8   <imm32>    MOV  R8D, 0x23         ; -> exact length
#
# so walking every rip-relative LEA in .text that lands in a data section and
# reading the following length immediate recovers each literal with its true
# boundary. This pass runs on every sample, including ones where an encrypted
# scheme already matched, because both are used side by side in one build.

# MOV r32, imm32 is B8+rd (eax..edi) or 41 B8+rd (r8d..r15d)
_MAX_LITERAL = 512
_MIN_LITERAL = 4
_PRINTABLE_LITERAL = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def find_rust_str_literals(raw, sections, image_base, text_sec, window=22):
    """Recover Rust &str literals as exact (address, length, text) triples."""
    base = image_base + text_sec["vaddr"]
    off0 = text_sec["rawptr"]
    code = raw[off0:off0 + text_sec["rawsize"]]
    out = OrderedDict()

    for i in range(len(code) - (7 + window)):
        if code[i] not in (0x48, 0x4C) or code[i + 1] != 0x8D:
            continue
        if (code[i + 2] & 0xC7) != 0x05:
            continue
        target_rva = (base + i + 7 + struct.unpack_from("<i", code, i + 3)[0]) - image_base
        off = rva_to_offset(sections, target_rva)
        if off is None:
            continue

        # first MOV r32, imm32 in the trailing window is the length operand
        w = code[i + 7:i + 7 + window]
        length = None
        j = 0
        while j < len(w) - 4:
            if w[j] == 0x41 and 0xB8 <= w[j + 1] <= 0xBF and j + 6 <= len(w):
                length = struct.unpack_from("<I", w, j + 2)[0]
                break
            if 0xB8 <= w[j] <= 0xBF and j + 5 <= len(w):
                length = struct.unpack_from("<I", w, j + 1)[0]
                break
            j += 1
        if length is None or not (_MIN_LITERAL <= length <= _MAX_LITERAL):
            continue

        blob = raw[off:off + length]
        if len(blob) != length:
            continue
        # NUL is legal inside a Rust &str but never appears in this family's
        # config literals, and letting it through makes the output a "binary
        # file" to grep/less. Require strictly printable text.
        if any(b not in _PRINTABLE_LITERAL for b in blob):
            continue
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            continue
        out.setdefault(text, {"va": image_base + target_rva, "len": length, "text": text})
    return list(out.values())


# Literals worth reporting: env-var paths, globs, URLs, Telegram artefacts.
# Everything else in a Rust binary is panic messages, source paths and (for
# this DLL's PdcXxx export-forwarding stub) Windows API names - noise.
_ENVVAR_RE = re.compile(r"%(?:AppData|LocalAppData|UserProfile|ProgramData|"
                        r"ProgramFiles(?:\(x86\))?|SystemDrive|Public|Temp|"
                        r"HomePath|OneDrive)%", re.IGNORECASE)


def looks_like_config_literal(text):
    if _ENVVAR_RE.search(text):
        return True
    if TELEGRAM_TOKEN_RE.match(text):
        return True
    if text.startswith(("http://", "https://")) and "." in text.split("//", 1)[1]:
        return True
    if "*" in text and ("." in text or "\\" in text or "/" in text):
        return True
    low = text.lower()
    if low.endswith((".sqlite", ".db", ".kdbx", ".ovpn", ".rdp", ".pem", ".ppk",
                     ".json", ".ini", ".xml", ".key")) and " " not in low:
        return True
    return False


def split_hexxor_records(plain):
    """This scheme uses NUL as the record separator inside one blob."""
    parts = [p for p in plain.split(b"\x00") if p]
    return [p.decode("utf-8", "replace") for p in parts]


def parse_pe(data):
    if data[0:2] != b"MZ":
        raise ValueError("not a PE file (missing MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE file (missing PE signature)")
    coff_off = e_lfanew + 4
    machine, num_sections = struct.unpack_from("<HH", data, coff_off)
    size_opt_hdr = struct.unpack_from("<H", data, coff_off + 16)[0]
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
    sec_off = opt_off + size_opt_hdr
    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "rawsize": rawsize, "rawptr": rawptr,
        })
    return sections, image_base


def rva_to_offset(sections, rva):
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + (rva - s["vaddr"])
    return None


def _regs_written_by_insn(insn):
    regs = set()
    try:
        _, regs_w = insn.regs_access()
        for r in regs_w:
            regs.add(insn.reg_name(r).upper())
    except Exception:
        pass
    return regs


def _norm(regname):
    regname = regname.upper()
    mapping = {
        "R8D": "R8", "R8W": "R8", "R8B": "R8",
        "R9D": "R9", "R9W": "R9", "R9B": "R9",
        "EDX": "RDX", "DX": "RDX", "DL": "RDX",
    }
    return mapping.get(regname, regname)


def _disasm_window(md, raw, base, end_off, back_bytes):
    """Disassemble an independent local window ending exactly at end_off.
    Returns the instruction list, or None if the last decoded instruction
    doesn't land exactly on end_off (didn't resync)."""
    start_off = max(0, end_off - back_bytes)
    chunk = raw[start_off:end_off]
    if not chunk:
        return None
    insns = list(md.disasm(chunk, base + start_off))
    if not insns:
        return None
    last = insns[-1]
    if last.address + last.size != base + end_off:
        return None
    return insns


DIRECT_CALL_OPCODE = 0xE8
# indirect CALL r/m64 (FF /2): ModRM reg field == 2
def find_decrypt_call_sites(raw, sections, image_base, text_vaddr):
    """Map decrypt-call target VA -> [{call_va, data_rva, size, nonce_rva}].

    `raw` is the .text bytes only, so offsets are relative to the start of
    .text, not the image. .text is not at RVA 0 (0x1000 is typical), so an
    instruction at offset `off` is at image_base + text_vaddr + off. Using
    image_base alone points every recovered ciphertext/nonce/key address
    text_vaddr bytes short, and verification then fails on ordinary samples.

    Only direct (E8) calls are scanned. Indirect FF /2 dispatch cannot be
    grouped by target, and bucketing it produces false positives that drown
    out the real candidate."""
    by_target = {}
    va_base = image_base + text_vaddr

    if not HAVE_CAPSTONE:
        return _find_decrypt_call_sites_fallback(raw, sections, image_base, text_vaddr)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    call_offsets = [i for i in range(len(raw) - 5) if raw[i] == DIRECT_CALL_OPCODE]

    for off in call_offsets:
        window = None
        for back in (80, 160, 320):
            w = _disasm_window(md, raw, va_base, off, back)
            if w is not None:
                window = w
                break
        if window is None:
            continue

        rdx_val = None
        r8_val = None
        r9_val = None
        for insn in reversed(window[:-1]):
            written = {_norm(r) for r in _regs_written_by_insn(insn)}
            mnem = insn.mnemonic
            ops = insn.op_str

            if r9_val is None and "R9" in written and mnem == "lea":
                m = re.search(r"\[rip\s*\+\s*(0x[0-9a-f]+)\]", ops)
                if m:
                    r9_val = insn.address + insn.size + int(m.group(1), 16)

            if r8_val is None and "R8" in written and mnem == "mov":
                m = re.search(r",\s*(0x[0-9a-f]+)$", ops)
                if m:
                    r8_val = int(m.group(1), 16)

            if rdx_val is None and "RDX" in written and mnem == "lea":
                m = re.search(r"\[rip\s*\+\s*(0x[0-9a-f]+)\]", ops)
                if m:
                    rdx_val = insn.address + insn.size + int(m.group(1), 16)

            if rdx_val is not None and r8_val is not None and r9_val is not None:
                break

        if rdx_val is None or r8_val is None or r9_val is None:
            continue
        if not (0 < r8_val < 2000):
            continue

        call_va = va_base + off
        rel = struct.unpack_from("<i", raw, off + 1)[0]
        target = va_base + off + 5 + rel

        by_target.setdefault(target, []).append({
            "call_va": call_va, "data_rva": rdx_val - image_base,
            "size": r8_val, "nonce_rva": r9_val - image_base,
        })

    return by_target


def _find_decrypt_call_sites_fallback(raw, sections, image_base, text_vaddr):
    """No-capstone fallback: fixed 60-byte byte-pattern heuristic, direct
    calls only."""
    by_target = {}
    va_base = image_base + text_vaddr
    for i in range(len(raw) - 5):
        if raw[i] != DIRECT_CALL_OPCODE:
            continue
        rel = struct.unpack_from("<i", raw, i + 1)[0]
        target = va_base + i + 5 + rel
        rdx_val = r8_val = r9_val = None
        window = raw[max(0, i - 60):i]
        for pos in range(len(window) - 7, -1, -1):
            b0, b1, b2 = window[pos], window[pos + 1] if pos + 1 < len(window) else 0, window[pos + 2] if pos + 2 < len(window) else 0
            if rdx_val is None and b0 == 0x48 and b1 == 0x8D and b2 == 0x15:
                disp = struct.unpack_from("<i", window, pos + 3)[0]
                rdx_val = va_base + (i - len(window) + pos) + 7 + disp
            if r9_val is None and b0 == 0x4C and b1 == 0x8D and b2 == 0x0D:
                disp = struct.unpack_from("<i", window, pos + 3)[0]
                r9_val = va_base + (i - len(window) + pos) + 7 + disp
            if r8_val is None and b0 == 0x41 and b1 == 0xB8:
                r8_val = struct.unpack_from("<I", window, pos + 2)[0]
        if rdx_val is None or r8_val is None or r9_val is None:
            continue
        if not (0 < r8_val < 2000):
            continue
        by_target.setdefault(target, []).append({
            "call_va": va_base + i, "data_rva": rdx_val - image_base,
            "size": r8_val, "nonce_rva": r9_val - image_base,
        })
    return by_target


def pick_decrypt_function(by_target, min_calls=2):
    ranked = sorted(by_target.items(), key=lambda kv: -len(kv[1]))
    return [(t, entries) for t, entries in ranked if len(entries) >= min_calls]


def _read(raw, sections, rva, length):
    off = rva_to_offset(sections, rva)
    if off is None or off + length > len(raw):
        return None
    return raw[off:off + length]


def try_key_at(raw, sections, key32, sample_entries, max_tries=5):
    """Returns (success_count, cipher_name)."""
    for cipher_name, cls in CIPHERS.items():
        ok = 0
        try:
            aead = cls(key32)
        except Exception:
            continue
        for entry in sample_entries[:max_tries]:
            ct = _read(raw, sections, entry["data_rva"], entry["size"])
            nonce = _read(raw, sections, entry["nonce_rva"], 12)
            if ct is None or nonce is None:
                continue
            try:
                aead.decrypt(nonce, ct, None)
                ok += 1
            except Exception:
                pass
        if ok >= 1:
            return ok, cipher_name
    return 0, None


def offset_to_va(sections, image_base, file_off):
    """Inverse of rva_to_offset: map a file offset back to an absolute VA."""
    for s in sections:
        if s["rawptr"] <= file_off < s["rawptr"] + s["rawsize"]:
            return image_base + s["vaddr"] + (file_off - s["rawptr"])
    return None


def _find_rip_constant_refs(raw, sections, target_va, image_base,
                             max_scan=400, max_refs=6):
    """Scan forward from a candidate decrypt function's start for
    RIP-relative references to flat memory constants in its prologue:
      LEA    r64, [rip+disp32]          48/4C 8D /r  (mod=00,rm=101)
      MOVAPS xmm, [rip+disp32]          0F 28 /r
      MOVUPS xmm, [rip+disp32]          0F 10 /r
      MOVAPS/MOVUPS with 66 prefix variants
    These are how a compiler loads a 16-byte AES/ChaCha key half from
    .rdata - NOT via `mov r64, imm64` immediates (an earlier version of this
    function guessed the latter after mis-reading Ghidra's decompiler, which
    constant-folds these loads into hex literals in the pseudo-C and makes
    them look like inline immediates when they're actually flat XMM loads;
    confirmed by disassembling the real bytes directly).

    Returns the list of resolved absolute addresses in encounter order,
    bounded and using only local decode (short window, byte-pattern keyed,
    not a dependent linear sweep - safe against misalignment)."""
    off = rva_to_offset(sections, target_va - image_base)
    if off is None:
        return []
    refs = []
    end = min(off + max_scan, len(raw))
    i = off
    while i < end - 7 and len(refs) < max_refs:
        b0, b1 = raw[i], raw[i + 1]
        matched = False
        # LEA r64, [rip+disp32]: REX.W (48/4C/49/4D) + 8D + modrm(mod=00,rm=101)
        if b0 in (0x48, 0x4C, 0x49, 0x4D) and b1 == 0x8D and i + 2 < end:
            modrm = raw[i + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", raw, i + 3)[0]
                next_insn_off = i + 7
                next_insn_va = offset_to_va(sections, image_base, next_insn_off)
                if next_insn_va is not None:
                    refs.append(next_insn_va + disp)
                i += 7
                matched = True
        # MOVAPS/MOVUPS xmm, [rip+disp32]: optional 66/REX + 0F 28/29/10/11 + modrm
        if not matched and b0 == 0x0F and b1 in (0x28, 0x29, 0x10, 0x11) and i + 2 < end:
            modrm = raw[i + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", raw, i + 3)[0]
                next_insn_off = i + 7
                next_insn_va = offset_to_va(sections, image_base, next_insn_off)
                if next_insn_va is not None:
                    refs.append(next_insn_va + disp)
                i += 7
                matched = True
        if not matched:
            i += 1
    return refs


def _key_candidates_from_refs(raw, sections, image_base, refs):
    """For each RIP-relative constant reference found in the prologue, try
    the 32 bytes starting there as a key, both straight and with its two
    16-byte halves swapped (confirmed empirically: at least one build stores
    the two key halves as separate 16-byte loads whose combined 32-byte
    buffer needs the halves swapped relative to their storage order - the
    key-schedule setup call in between them evidently reorders them)."""
    candidates = []
    for va in refs:
        rva = va - image_base
        blob = _read(raw, sections, rva, 32)
        if blob is None:
            continue
        h1, h2 = blob[:16], blob[16:]
        candidates.append(blob)
        candidates.append(h2 + h1)
    return candidates


def discover_key(raw, sections, image_base, sample_entries, target_va=None,
                  text_vaddr=None, search_window=0x20000):
    if not sample_entries:
        return None, None
    anchor_rva = sample_entries[0]["data_rva"]

    # Strategy 1: flat constant near the ciphertext in .rdata/.data (the
    # common case for this family).
    for sec in sections:
        if sec["name"] not in (".rdata", ".data"):
            continue
        lo = max(sec["vaddr"], anchor_rva - search_window)
        hi = min(sec["vaddr"] + sec["vsize"], anchor_rva + search_window)
        for rva in range(lo, hi - 32, 16):
            key = _read(raw, sections, rva, 32)
            if key is None:
                continue
            if key.count(0) > 24:
                continue
            ok, cipher_name = try_key_at(raw, sections, key, sample_entries, max_tries=3)
            if ok > 0:
                return key, cipher_name

    # Strategy 2: the key isn't near the ciphertext at all - it's referenced
    # directly by RIP-relative LEA/MOVAPS/MOVUPS constant loads in the
    # decrypt function's own prologue (seen when strategy 1 finds nothing,
    # even on a genuinely verified real decrypt function: the key lived in
    # .rdata but ~0x2e0000 bytes away from the first ciphertext, well outside
    # the proximity search window - proximity to ciphertext was never a safe
    # assumption to begin with, this is the more reliable general approach).
    if isinstance(target_va, int):
        refs = _find_rip_constant_refs(raw, sections, target_va, image_base)
        for key in _key_candidates_from_refs(raw, sections, image_base, refs):
            if key.count(0) > 24:
                continue
            ok, cipher_name = try_key_at(raw, sections, key, sample_entries, max_tries=3)
            if ok > 0:
                return key, cipher_name

    return None, None


def verify_candidates(raw, sections, image_base, candidates, text_vaddr=None,
                       top_n=5, probe_n=6):
    verified = []
    for target, entries in candidates[:top_n]:
        key, cipher_name = discover_key(raw, sections, image_base, entries,
                                         target_va=target, text_vaddr=text_vaddr)
        if key is None:
            continue
        ok, _ = try_key_at(raw, sections, key, entries, max_tries=min(probe_n, len(entries)))
        if ok >= 2:
            verified.append((target, entries, key, cipher_name, ok))
    verified.sort(key=lambda v: -v[4])
    return verified


def find_word_xor_call_sites(raw, image_base, text_vaddr):
    """Find direct-call sites matching:
         LEA RCX,[rip+disp32]   ; encoded wide blob
         MOV EDX, imm32         ; plaintext length
         CALL rel32
    where the callee returns a decoded byte buffer.
    """
    by_target = {}
    va_base = image_base + text_vaddr
    for i in range(len(raw) - 5):
        if raw[i] != DIRECT_CALL_OPCODE:
            continue
        rel = struct.unpack_from("<i", raw, i + 1)[0]
        target = va_base + i + 5 + rel
        blob_va = None
        size = None
        window = raw[max(0, i - 32):i]
        for pos in range(len(window) - 7, -1, -1):
            if window[pos:pos + 3] == b"\x48\x8d\x0d":
                disp = struct.unpack_from("<i", window, pos + 3)[0]
                blob_va = va_base + (i - len(window) + pos) + 7 + disp
                break
        for pos in range(len(window) - 5, -1, -1):
            if window[pos] == 0xBA:
                size = struct.unpack_from("<I", window, pos + 1)[0]
                break
        if blob_va is None or size is None or not (0 < size < 4096):
            continue
        by_target.setdefault(target, []).append({
            "call_va": va_base + i,
            "data_rva": blob_va - image_base,
            "size": size,
        })
    return by_target


def decode_word_xor_entry(raw, sections, entry):
    blob = _read(raw, sections, entry["data_rva"], entry["size"] * 2)
    if blob is None:
        return None
    return bytes(blob[i] ^ blob[i + 1] for i in range(0, len(blob), 2))


def score_word_xor_plaintext(buf):
    try:
        text = buf.decode("utf-8")
    except UnicodeDecodeError:
        return -100
    printable = sum(32 <= ord(ch) < 127 for ch in text)
    score = printable * 2 - (len(text) - printable) * 4
    if text.startswith("%AppData%") or text.startswith("%LocalAppData%") or text.startswith("%UserProfile%"):
        score += 50
    if text.startswith("http://") or text.startswith("https://"):
        score += 50
    if TELEGRAM_TOKEN_RE.match(text):
        score += 100
    if re.match(r"^-?\d{6,15}$", text):
        score += 40
    if "\\" in text or "/" in text:
        score += 20
    if any(k in text.lower() for k in ("cookies", "login data", "wallet", "telegram desktop", "discord")):
        score += 25
    return score


def verify_word_xor_candidates(raw, sections, candidates, top_n=12):
    verified = []
    for target, entries in candidates[:top_n]:
        decoded = []
        scores = []
        for entry in entries[:32]:
            pt = decode_word_xor_entry(raw, sections, entry)
            if pt is None:
                continue
            decoded.append(pt)
            scores.append(score_word_xor_plaintext(pt))
        if not scores:
            continue
        best = max(scores)
        total = sum(sorted(scores, reverse=True)[: min(16, len(scores))])
        if best < 20:
            continue
        verified.append((target, entries, None, "word-xor16", total))
    verified.sort(key=lambda v: -v[4])
    return verified


TELEGRAM_TOKEN_RE = re.compile(r"^\d{8,}:AA[A-Za-z0-9_-]{30,}$")
RUST_TEMPLATE_KEYWORDS = (
    "chat_id",
    "caption",
    "parse_mode",
    "content-disposition",
    "screenshot.png",
    "telegram desktop",
    "discord",
    "wallet",
    "cookies",
    "login data",
    "user:",
    "host:",
    "ip:",
    "location:",
    "tz:",
    "time:",
    "deletefile",
    "createobject",
    "senddocument",
    "sendphoto",
    "sendmessage",
    "bot",
    "api.telegram.org",
)


def classify(text):
    if TELEGRAM_TOKEN_RE.match(text):
        return "TELEGRAM_BOT_TOKEN"
    if re.match(r"^-?\d{6,12}$", text):
        return "TELEGRAM_CHAT_ID"
    if "api.telegram.org" in text:
        return "TELEGRAM_API"
    if "sendDocument" in text or "sendPhoto" in text or "sendMessage" in text:
        return "TELEGRAM_DATA"
    low = text.lower()
    if any(k in low for k in ("wallet", "metamask", "electrum", "exodus", ".dat")) and "\\" in text:
        return "CRYPTO_WALLET"
    if "id_rsa" in low or ("ssh" in low and "\\" in text):
        return "SSH_KEY"
    if "openvpn" in low or ".ovpn" in low:
        return "VPN_CONFIG"
    if "anydesk" in low or "teamviewer" in low or ("remote" in low and "\\" in text):
        return "REMOTE_ACCESS"
    if "filezilla" in low or "ftp" in low:
        return "FTP_CONFIG"
    if "telegram" in low or "discord" in low or "signal" in low or "whatsapp" in low:
        return "MESSAGING"
    if "thunderbird" in low or "outlook" in low:
        return "EMAIL"
    if ".db" in low or "sqlite" in low:
        return "DATABASE"
    if "aws" in low or "azure" in low or "gcloud" in low or ".cloud" in low:
        return "CLOUD_CREDS"
    if "steam" in low or "epicgames" in low or "battle.net" in low:
        return "GAMING"
    if "keepass" in low or "bitwarden" in low or "1password" in low:
        return "PASSWORD_MANAGER"
    if ".git" in low or "netrc" in low or "npmrc" in low:
        return "DEV_CREDS"
    if "dropbox" in low or "google drive" in low or "onedrive" in low:
        return "CLOUD_STORAGE"
    # URL must precede FILE_PATH: "https://api.ipify.org" contains two
    # slashes and would otherwise be reported as a file path.
    if text.startswith(("http://", "https://")):
        return "URL"
    if "\\" in text or ("/" in text and text.count("/") > 1):
        return "FILE_PATH"
    if "*" in text and "." in text:
        return "FILE_PATTERN"
    return "OTHER"


def decode_rust_compact_template(blob, start):
    out = []
    arg_idx = 0
    saw_literal = False
    saw_placeholder = False
    i = start
    while i < len(blob):
        op = blob[i]
        if op == 0:
            text = "".join(out)
            if not text or not saw_literal:
                return None
            bad = sum(ord(ch) < 0x20 and ch not in "\r\n\t" for ch in text)
            if bad or len(text) < 8:
                return None
            return i + 1, text, saw_placeholder
        if op < 0x80:
            end = i + 1 + op
            if end > len(blob):
                return None
            try:
                chunk = blob[i + 1:end].decode("utf-8")
            except UnicodeDecodeError:
                return None
            if any(ord(ch) < 0x20 and ch not in "\r\n\t" for ch in chunk):
                return None
            out.append(chunk)
            saw_literal = True
            i = end
            continue
        if op == 0xC0:
            out.append(f"<ARG{arg_idx}>")
            arg_idx += 1
            saw_placeholder = True
            i += 1
            continue
        if op == 0x80:
            if i + 3 > len(blob):
                return None
            span = blob[i + 1] | (blob[i + 2] << 8)
            if i + 3 + span > len(blob):
                return None
            out.append(f"<SPECIAL{span}>")
            saw_placeholder = True
            i += 3 + span
            continue
        j = i + 1
        if op & 1:
            j += 4
        if op & 2:
            j += 2
        if op & 4:
            j += 2
        if j > len(blob):
            return None
        ref_idx = arg_idx
        if op & 8:
            if j + 2 > len(blob):
                return None
            ref_idx = blob[j] | (blob[j + 1] << 8)
            j += 2
            arg_idx = ref_idx + 1
        else:
            arg_idx += 1
        out.append(f"<ARG{ref_idx}>")
        saw_placeholder = True
        i = j
    return None


def looks_like_rust_template(text, saw_placeholder):
    low = text.lower()
    if any(k in low for k in RUST_TEMPLATE_KEYWORDS):
        return True
    if saw_placeholder and any(
        marker in text for marker in ("%AppData%", "%LocalAppData%", "%UserProfile%")
    ):
        return True
    return False


def scan_rust_compact_templates(raw, sections, image_base):
    hits = []
    for sec in sections:
        if sec["name"] not in (".rdata", ".data"):
            continue
        start_off = sec["rawptr"]
        buf = raw[start_off:start_off + sec["rawsize"]]
        i = 0
        while i < len(buf):
            decoded = decode_rust_compact_template(buf, i)
            if decoded is None:
                i += 1
                continue
            end, text, saw_placeholder = decoded
            if looks_like_rust_template(text, saw_placeholder):
                hits.append({
                    "va": image_base + sec["vaddr"] + i,
                    "section": sec["name"],
                    "text": text,
                })
                i = end
            else:
                i += 1
    unique = OrderedDict()
    for hit in sorted(hits, key=lambda h: h["va"]):
        unique.setdefault(hit["text"], hit)
    return list(unique.values())


URL_RE = re.compile(rb"https?://[\x21-\x7e]{4,300}")
IPV4_RE = re.compile(rb"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                      rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
TRAILING_EXT_RE = re.compile(rb"\.(?:bin|exe|dll|php|zip|txt|json|dat|jpg|png|gif|ps1)",
                             re.IGNORECASE)
HARD_URL_CAP = 120


def _trim_url_match(raw_match: bytes) -> bytes:
    """Cut a greedy URL match back to its real end.

    Rust packs adjacent string literals with no separator, so a regex over raw
    bytes runs past the end of a URL into whatever constant follows. Two cuts,
    in order: a long unbroken lowercase-hex run is one of this family's
    encrypted config blobs and never part of a URL; otherwise trim at the first
    trailing file extension (deliberately not \b-anchored, since the next byte
    is often another packed literal), else hard-cap. Heuristic, not exact.
    """
    tail, run = len(raw_match), 0
    for i in range(len(raw_match) - 1, -1, -1):
        if raw_match[i] in b"0123456789abcdef":
            run += 1
        else:
            if run >= 24:
                tail = i + 1
            run = 0
    raw_match = raw_match[:tail] if (tail and run < 24) else raw_match
    m = TRAILING_EXT_RE.search(raw_match)
    if m:
        return raw_match[:m.end()]
    return raw_match[:HARD_URL_CAP]


def scan_plaintext_secrets(raw, sections):
    """Fallback pass for builds that don't AEAD/word-xor-encrypt their own
    config: pull raw strings out of .rdata/.data and keep anything that looks
    like a C2 URL, Telegram bot token, or IPv4 address. Returns a dict of
    category -> sorted unique list of strings."""
    found = {"URL": set(), "TELEGRAM_BOT_TOKEN": set(), "IPV4": set()}
    for sec in sections:
        if sec["name"] not in (".rdata", ".data"):
            continue
        start = sec["rawptr"]
        buf = raw[start:start + sec["rawsize"]]

        for m in URL_RE.finditer(buf):
            trimmed = _trim_url_match(m.group(0))
            try:
                text = trimmed.decode("utf-8")
            except UnicodeDecodeError:
                continue
            found["URL"].add(text)

        for m in re.finditer(rb"\d{8,10}:AA[A-Za-z0-9_-]{30,}", buf):
            found["TELEGRAM_BOT_TOKEN"].add(m.group(0).decode("ascii"))

        for m in IPV4_RE.finditer(buf):
            ip = m.group(0).decode("ascii")
            # skip obvious version-number / build-metadata false positives.
            # NOTE: this section also contains ASN.1 DER data (the AES OID
            # etc. used by this family's Firefox-NSS decryptor, see the v9
            # docstring) whose small integer arcs can coincidentally match a
            # dotted-quad pattern (e.g. "1.3.6.1" is a real OID prefix, not
            # an IP) - low-numbered results here should be treated with
            # suspicion and cross-checked, not taken at face value.
            if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                found["IPV4"].add(ip)

    return {k: sorted(v) for k, v in found.items() if v}


def classify_rust_template(text):
    low = text.lower()
    if "content-disposition" in low or "chat_id" in low or "parse_mode" in low:
        return "HTTP_TEMPLATE"
    if "user:" in low and "host:" in low and "ip:" in low:
        return "SYSTEM_SUMMARY_TEMPLATE"
    if "deletefile" in low or "createobject" in low or ".vbs" in low:
        return "CLEANUP_SCRIPT"
    if text.startswith("%") or "telegram desktop" in low or "discord" in low or "wallet" in low:
        return "TARGET_PATTERNS"
    return "OTHER_TEMPLATE"


# ---------------------------------------------------------------------------
# Report assembly and output
# ---------------------------------------------------------------------------
# One schema for every build generation. The category list below is fixed and
# always emitted in full, including empty categories, so a diff between two
# samples is a diff of values and never of structure. Where a string came from
# is a field, not a section-name prefix:
#
#   enc   recovered from the encrypted/obfuscated config blob
#   lit   plaintext Rust &str literal, exact length read from the code
#   tpl   Rust compact formatter template
#   scan  raw .rdata/.data string scan (last-resort fallback)

CATEGORIES = (
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_API", "TELEGRAM_DATA",
    "URL", "IPV4",
    "CLOUD_CREDS", "CLOUD_STORAGE", "CRYPTO_WALLET", "DATABASE", "DEV_CREDS",
    "EMAIL", "FILE_PATH", "FILE_PATTERN", "FTP_CONFIG", "GAMING", "MESSAGING",
    "PASSWORD_MANAGER", "REMOTE_ACCESS", "SSH_KEY", "VPN_CONFIG", "OTHER",
    "HTTP_TEMPLATE", "SYSTEM_SUMMARY_TEMPLATE", "CLEANUP_SCRIPT",
    "TARGET_PATTERNS", "OTHER_TEMPLATE",
)


class Report:
    def __init__(self, path, sha256):
        self.path = path
        self.sha256 = sha256
        self.scheme = "none"
        self.decrypt_fn = None
        self.key = None
        self.blobs = []
        self.counts = {"strings_total": 0, "strings_unique": 0,
                       "literals_total": 0, "literals_kept": 0}
        self.items = OrderedDict((c, {}) for c in CATEGORIES)

    def add(self, value, source, category=None):
        """First source to yield a value wins, so a literal that merely
        duplicates an already-decrypted string does not appear twice.

        A raw-scan hit that starts with a value already recovered with an exact
        length is that value plus whatever Rust packed next to it in .rdata,
        so it is dropped rather than reported as a longer C2 URL."""
        if not value:
            return
        if source == "scan":
            for existing in self.items.values():
                if any(value != known and value.startswith(known)
                       for known in existing):
                    return
        cat = category or classify(value)
        if cat not in self.items:
            cat = "OTHER"
        for existing in self.items.values():
            if value in existing:
                return
        self.items[cat][value] = source

    def rows(self, cat):
        return sorted(self.items[cat].items())


def emit_text(rep, out=sys.stdout):
    w = out.write
    w(f"# {TOOL} {VERSION}\n")
    w(f"file: {rep.path}\n")
    w(f"sha256: {rep.sha256}\n")
    w(f"scheme: {rep.scheme}\n")
    w(f"decrypt_fn: {rep.decrypt_fn or '-'}\n")
    w(f"key: {rep.key or '-'}\n")
    w(f"blobs: {len(rep.blobs)}\n")
    for k in ("strings_total", "strings_unique", "literals_total", "literals_kept"):
        w(f"{k}: {rep.counts[k]}\n")
    for b in rep.blobs:
        w(f"blob: rva={b['blob_rva']:#x} len={b['hex_len']} "
          f"key={b['key']:#04x} how={b['how']}\n")
    for cat in CATEGORIES:
        rows = rep.rows(cat)
        w(f"\n=== {cat} ({len(rows)}) ===\n")
        for value, source in rows:
            w(f"  {source}  {_safe(value)}\n")


def emit_json(rep, out=sys.stdout):
    json.dump({
        "tool": TOOL,
        "version": VERSION,
        "file": rep.path,
        "sha256": rep.sha256,
        "scheme": rep.scheme,
        "decrypt_fn": rep.decrypt_fn,
        "key": rep.key,
        "blobs": [{"rva": b["blob_rva"], "len": b["hex_len"],
                   "key": b["key"], "how": b["how"]} for b in rep.blobs],
        "counts": rep.counts,
        "categories": {cat: [{"value": v, "source": s} for v, s in rep.rows(cat)]
                       for cat in CATEGORIES},
    }, out, indent=1, ensure_ascii=False)
    out.write("\n")


def add_literals(rep, raw, sections, image_base, text_sec):
    """Plaintext-literal pass. Always runs: AEAD builds carry part of the
    config in the clear, and late builds carry nearly all of it that way."""
    lits = find_rust_str_literals(raw, sections, image_base, text_sec)
    rep.counts["literals_total"] = len(lits)
    kept = 0
    for lit in lits:
        if not looks_like_config_literal(lit["text"]):
            continue
        before = sum(len(v) for v in rep.items.values())
        rep.add(lit["text"], "lit")
        kept += sum(len(v) for v in rep.items.values()) - before
    rep.counts["literals_kept"] = kept


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        prog="parsastealer_config.py",
        description="Recover UMPDC / ParsaStealer configuration from a PE sample.")
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument("--scan-only", action="store_true",
                    help="list candidate call sites without decrypting")
    ap.add_argument("--key", help="hex-encoded 32-byte key override")
    ap.add_argument("--func", help="decrypt function VA override (hex)")
    ap.add_argument("--cipher", choices=list(CIPHERS) + ["word-xor16"],
                    help="cipher override")
    ap.add_argument("--min-calls", type=int, default=2,
                    help="minimum call sites for a candidate decrypt function")
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        raw = f.read()
    sha256 = hashlib.sha256(raw).hexdigest()
    rep = Report(args.binary, sha256)
    log(f"[*] sha256 {sha256}")

    if not HAVE_CAPSTONE:
        log("[!] capstone missing - reduced-accuracy call-site scan")
    if not HAVE_CRYPTOGRAPHY:
        log("[!] cryptography missing - AEAD schemes disabled")

    sections, image_base = parse_pe(raw)
    text_sec = next((s for s in sections if s["name"] == ".text"), None)
    if text_sec is None:
        log("[!] no .text section")
        sys.exit(1)
    text_raw = raw[text_sec["rawptr"]:text_sec["rawptr"] + text_sec["rawsize"]]

    override = bool(args.key or args.func or args.cipher)

    # 1. hex+XOR / raw sub-XOR. Tried first: the thunks carry length and key as
    #    immediates, so a hit is self-verifying and cannot be faked by the Rust
    #    Debug-formatting false positives that plague the AEAD fingerprint.
    if not override:
        blobs = find_hexxor_thunks(raw, sections, image_base, text_sec)
        if blobs:
            blobs += brute_hexxor_blobs(raw, sections, blobs)
        else:
            blobs = find_raw_xor_thunks(raw, sections, image_base, text_sec)
        if blobs:
            if args.scan_only:
                for b in blobs:
                    log(f"  blob {b['blob_rva']:#x} len={b['hex_len']} "
                        f"key={b['key']:#04x} ({b['how']})")
                return
            raw_variant = next((b["how"] for b in blobs
                                if b["how"].startswith("raw:")), None)
            rep.scheme = (raw_variant.split(" via ")[0].replace("raw:", "raw-")
                          if raw_variant else "ascii-hex+xor")
            rep.blobs = blobs
            strings = []
            for b in blobs:
                strings.extend(split_hexxor_records(b["plain"]))
            rep.counts["strings_total"] = len(strings)
            rep.counts["strings_unique"] = len(set(strings))
            for s in strings:
                rep.add(s, "enc")
            add_literals(rep, raw, sections, image_base, text_sec)
            (emit_json if args.json else emit_text)(rep)
            return

    # 2. AEAD / word-xor16 call-site discovery.
    by_target = find_decrypt_call_sites(text_raw, sections, image_base,
                                        text_sec["vaddr"])
    wx_by_target = find_word_xor_call_sites(text_raw, image_base, text_sec["vaddr"])
    log(f"[*] {len(by_target)} AEAD / {len(wx_by_target)} word-xor candidate targets")

    candidates = pick_decrypt_function(by_target, min_calls=args.min_calls)
    wx_candidates = pick_decrypt_function(wx_by_target, min_calls=args.min_calls)
    if args.scan_only:
        for label, cands in (("AEAD", candidates), ("WORDXOR", wx_candidates)):
            for t, entries in cands[:10]:
                log(f"  {label} {t if isinstance(t, str) else hex(t)}: "
                    f"{len(entries)} calls")
        return

    # Everything below reads against the full file, not text_raw: the call
    # sites point at ciphertext/nonce/key data in .rdata/.data, which .text
    # bytes alone do not cover.
    verified = []
    if args.key and args.func:
        target = int(args.func, 16)
        verified = [(target, by_target.get(target, []), bytes.fromhex(args.key),
                     args.cipher or "aes-gcm", len(by_target.get(target, [])))]
    elif HAVE_CRYPTOGRAPHY and args.cipher != "word-xor16":
        verified = verify_candidates(raw, sections, image_base, candidates,
                                     text_vaddr=text_sec["vaddr"])
    if not verified:
        verified = verify_word_xor_candidates(raw, sections, wx_candidates)

    # 3. Nothing verified: compact templates, then a raw string scan.
    if not verified:
        for item in scan_rust_compact_templates(raw, sections, image_base):
            rep.add(item["text"], "tpl", classify_rust_template(item["text"]))
        add_literals(rep, raw, sections, image_base, text_sec)
        for cat, values in scan_plaintext_secrets(raw, sections).items():
            for v in values:
                rep.add(v, "scan", cat if cat in CATEGORIES else None)
        (emit_json if args.json else emit_text)(rep)
        if not any(rep.items.values()):
            log("[!] no config recovered: unrecognised calling convention, "
                "not this family, or try --scan-only")
            sys.exit(1)
        return

    target, entries, key, cipher_name, ok = verified[0]
    rep.scheme = cipher_name
    rep.decrypt_fn = target if isinstance(target, str) else hex(target)
    rep.key = key.hex() if key else None
    log(f"[+] verified {rep.decrypt_fn} cipher={cipher_name} "
        f"({len(entries)} call sites, score/probes={ok})")

    aead = CIPHERS[cipher_name](key) if cipher_name != "word-xor16" else None
    strings = []
    for entry in entries:
        if aead is None:
            pt = decode_word_xor_entry(raw, sections, entry)
            if pt is not None:
                strings.append(pt.decode("utf-8", "replace"))
            continue
        ct = _read(raw, sections, entry["data_rva"], entry["size"])
        nonce = _read(raw, sections, entry["nonce_rva"], 12)
        if ct is None or nonce is None:
            continue
        try:
            strings.append(aead.decrypt(nonce, ct, None).decode("utf-8", "replace"))
        except Exception:
            continue

    rep.counts["strings_total"] = len(strings)
    rep.counts["strings_unique"] = len(set(strings))
    for s in strings:
        rep.add(s, "enc")
    add_literals(rep, raw, sections, image_base, text_sec)
    (emit_json if args.json else emit_text)(rep)


if __name__ == "__main__":
    main()
