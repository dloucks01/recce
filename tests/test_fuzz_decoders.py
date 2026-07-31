"""Fuzz-invariant harness for recce's Layer-1 decoders (pure bytes/text -> struct).

The audit found that the bug-dense surface in recce is the pure protocol decoders
(BSON, BER, NTLM, SMB, nmap XML) that turn a *hostile server's* bytes into Python
objects. They are pure functions, so we can hammer them hard with no network.

For every decoder we assert its real contract under mutation of a valid message:

  1. Terminates.        A SIGALRM watchdog bounds each call; an infinite loop or a
                        non-advancing offset (the class of bug the audit found in
                        bson_parse) trips the alarm and fails the test instead of
                        hanging the suite forever.
  2. Only declared exceptions escape.  Each decoder lists the exceptions its own
                        caller catches; anything else (TypeError, RecursionError,
                        struct.error where unhandled, ...) is a real robustness bug,
                        because on a live engagement it would crash the enum phase.
  3. Output stays in bounds.  Offset-returning parsers must return an index inside
                        the input; None/dict/list-returning parsers must return the
                        declared shape.

Mutations applied to each seed: every truncation, single/double byte flips, length-
field corruption (negative / huge / zero), random splices, and a few targeted
structural attacks (deeply nested BSON, unterminated strings). Everything is driven
by a fixed-seed RNG so a failure reproduces exactly.
"""
import os
import random
import signal
import struct
import tempfile
import unittest

from recce import snmp
from recce import mongodb
from recce import ldap
from recce import ntlm
from recce import smb
from recce import web
from recce import parser
from recce import mssql
from recce import credenum
from recce import bloodhound
from tests import wire_vectors as W


# --- per-call termination watchdog ----------------------------------------------

class _Timeout(Exception):
    pass


class _bounded:
    """Context manager: raise _Timeout if the wrapped call runs past `seconds`.

    Uses SIGALRM, so it interrupts Python-level loops (the infinite-loop bug class)
    between bytecodes. Main-thread only, which is where unittest runs decoders."""

    def __init__(self, seconds=3.0):
        self.seconds = seconds

    def __enter__(self):
        self._old = signal.signal(signal.SIGALRM, self._fire)
        signal.setitimer(signal.ITIMER_REAL, self.seconds)
        return self

    def __exit__(self, *exc):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self._old)
        return False

    @staticmethod
    def _fire(signum, frame):
        raise _Timeout("decoder did not terminate within the watchdog window")


# --- decoder contract specs -----------------------------------------------------

class _Spec:
    """One decoder under test: how to call it, which exceptions it may raise, and
    what a well-formed return looks like."""

    def __init__(self, name, fn, seeds, allowed=(), validate=None):
        self.name = name
        self.fn = fn
        self.seeds = seeds
        self.allowed = allowed              # exception types the caller catches
        self.validate = validate or (lambda r, inp: True)


def _idx_in_bounds(result, inp):
    """(obj, index) parsers: the returned offset must land inside the input."""
    obj, idx = result
    return isinstance(idx, int) and 0 <= idx <= len(inp)


def _none_or_tuple2(result, inp):
    return result is None or (isinstance(result, tuple) and len(result) == 2)


def _none_or_dict(result, inp):
    return result is None or isinstance(result, dict)


def _none_or_int(result, inp):
    return result is None or isinstance(result, int)


def _is_dict(result, inp):
    return isinstance(result, dict)


def _byte_specs():
    return [
        # never-raises decoders (return None on garbage)
        _Spec("snmp.parse_response", snmp.parse_response,
              [W.snmp_get_response()], allowed=(), validate=_none_or_tuple2),
        _Spec("snmp._response_request_id", snmp._response_request_id,
              [W.snmp_get_response()], allowed=(), validate=_none_or_int),
        _Spec("ldap.result_code", ldap.result_code,
              [W.ldap_search_entry()], allowed=(), validate=_none_or_int),
        _Spec("ldap._op_tag", ldap._op_tag,
              [W.ldap_search_entry()], allowed=(), validate=_none_or_int),
        _Spec("ntlm.parse_type2", ntlm.parse_type2,
              [W.ntlm_type2()], allowed=(), validate=_none_or_dict),
        _Spec("smb.parse_smb2_negotiate", smb.parse_smb2_negotiate,
              [W.smb2_negotiate_response()], allowed=(), validate=_none_or_dict),
        _Spec("smb.parse_smb1_negotiate", smb.parse_smb1_negotiate,
              [W.smb1_negotiate_response()], allowed=(), validate=_is_dict),
        # decoders whose *caller* owns the never-raise guarantee: they may raise the
        # listed exceptions, but must still terminate and return in-bounds offsets.
        _Spec("mongodb.bson_parse", lambda b: mongodb.bson_parse(b, 0),
              [W.mongodb_hello_doc(), W.mongodb_listdbs_doc()],
              allowed=(struct.error, IndexError, ValueError),
              validate=_idx_in_bounds),
        _Spec("ldap.parse_search_entry", ldap.parse_search_entry,
              [W.ldap_search_entry()],
              allowed=(IndexError, ValueError),
              validate=lambda r, inp: isinstance(r, tuple) and len(r) == 2),
    ]


# --- mutation generators --------------------------------------------------------

def _mutations(seed, rng, rounds=60):
    """Yield hostile variants of one valid message."""
    n = len(seed)
    # every truncation, including empty
    for k in range(0, n + 1):
        yield seed[:k]
    # single and double byte flips at random positions
    for _ in range(rounds):
        b = bytearray(seed)
        b[rng.randrange(n)] ^= 1 << rng.randrange(8)
        yield bytes(b)
    for _ in range(rounds):
        b = bytearray(seed)
        b[rng.randrange(n)] = rng.randrange(256)
        b[rng.randrange(n)] = rng.randrange(256)
        yield bytes(b)
    # corrupt each 4-byte window as if it were a length field: negative / huge / zero
    for pos in range(0, max(1, n - 4), 3):
        for val in (b"\xff\xff\xff\xff", b"\xff\xff\xff\x7f", b"\x00\x00\x00\x00"):
            b = bytearray(seed)
            b[pos:pos + 4] = val
            yield bytes(b)
    # random splices and appends
    for _ in range(rounds):
        cut = rng.randrange(n + 1)
        extra = bytes(rng.randrange(256) for _ in range(rng.randrange(8)))
        yield seed[:cut] + extra + seed[cut:]
    # pure random blobs of assorted sizes
    for size in (0, 1, 2, 3, 4, 5, 7, 16, 64, 255):
        yield bytes(rng.randrange(256) for _ in range(size))


class ByteDecoderFuzzTest(unittest.TestCase):

    def _hammer(self, spec):
        rng = random.Random(0xF0 ^ hash(spec.name) & 0xFFFF)
        for seed in spec.seeds:
            for inp in _mutations(seed, rng):
                with self.subTest(decoder=spec.name, inp=inp.hex()):
                    try:
                        with _bounded():
                            result = spec.fn(inp)
                    except _Timeout as t:
                        self.fail(f"{spec.name} did not terminate on {inp.hex()!r}: {t}")
                    except spec.allowed:
                        continue                     # a declared, caller-handled error
                    except Exception as e:           # noqa: BLE001 - that's the point
                        self.fail(f"{spec.name} raised undeclared "
                                  f"{type(e).__name__} on {inp.hex()!r}: {e}")
                    self.assertTrue(
                        spec.validate(result, inp),
                        f"{spec.name} returned out-of-contract {result!r} "
                        f"on {inp.hex()!r}")

    def test_all_byte_decoders_survive_mutations(self):
        for spec in _byte_specs():
            self._hammer(spec)

    def test_bson_deep_nesting_terminates(self):
        """A hostile daemon can nest embedded documents (type 0x03) far past Python's
        recursion limit. bson_parse must not blow the stack in a way its caller
        (mongodb.command, which catches struct.error/IndexError/ValueError) can't
        absorb - a RecursionError would escape and crash the probe."""
        depth = 5000
        # innermost empty doc, then wrap it `depth` times as field "d" (type 0x03).
        doc = struct.pack("<i", 5) + b"\x00"
        for _ in range(depth):
            body = b"\x03" + b"d\x00" + doc
            doc = struct.pack("<i", 4 + len(body) + 1) + body + b"\x00"
        try:
            with _bounded():
                mongodb.bson_parse(doc, 0)
        except _Timeout:
            self.fail("bson_parse did not terminate on deeply nested document")
        except (struct.error, IndexError, ValueError):
            pass                                     # caller-handled: acceptable
        # RecursionError / any other exception propagates and fails the test.

    def test_bson_unterminated_cstring_terminates(self):
        """A field name with no NUL terminator must not run data.index() off a cliff
        in a way that loops or over-reads."""
        doc = struct.pack("<i", 64) + b"\x02" + b"noterminatorhere"
        try:
            with _bounded():
                out, idx = mongodb.bson_parse(doc, 0)
            self.assertLessEqual(idx, len(doc))
        except _Timeout:
            self.fail("bson_parse hung on unterminated cstring")
        except (struct.error, IndexError, ValueError):
            pass


# --- text / file decoders -------------------------------------------------------

class TextDecoderFuzzTest(unittest.TestCase):

    def test_web_fingerprint_survives_hostile_headers_and_body(self):
        """fingerprint() runs regexes over an attacker-controlled body and reads
        attacker-controlled header values; it must always return {tech, title}."""
        rng = random.Random(1234)
        alphabet = "<>/=\"'{}%$ script generator title meta name content \x00�"
        for _ in range(400):
            body = "".join(rng.choice(alphabet)
                           for _ in range(rng.randrange(0, 4096)))
            headers = {h: "".join(rng.choice(alphabet) for _ in range(rng.randrange(40)))
                       for h in ("server", "x-powered-by", "set-cookie", "x-generator")}
            with self.subTest(body_len=len(body)):
                with _bounded():
                    out = web.fingerprint(headers, body)
                self.assertIn("tech", out)
                self.assertIn("title", out)
                self.assertIsInstance(out["tech"], list)

    def test_parse_nmap_xml_never_raises_on_corrupt_files(self):
        """parse_nmap_xml() promises [] rather than a crash on any malformed file -
        nmap can leave a truncated XML when killed mid-write."""
        rng = random.Random(99)
        seed = W.NMAP_XML
        variants = [seed[:k] for k in range(0, len(seed), 7)]   # every truncation
        for _ in range(120):                                    # + byte corruption
            b = bytearray(seed.encode())
            for _ in range(rng.randrange(1, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            variants.append(b.decode("latin-1"))
        variants += ["", "<", "<nmaprun>", "<nmaprun><host></nmaprun>",
                     "<nmaprun><host><ports><port/></ports></host></nmaprun>",
                     "not xml at all \x00\x01\x02"]
        fd, path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        try:
            for text in variants:
                with open(path, "w", errors="replace") as fh:
                    fh.write(text)
                with self.subTest(sample=text[:40]):
                    with _bounded():
                        hosts = parser.parse_nmap_xml(path)
                    self.assertIsInstance(hosts, list)
        finally:
            os.unlink(path)


# --- tool-output text parsers ---------------------------------------------------
# recce shells out to nxc/netexec, impacket and sqlcmd, then parses their stdout.
# That text is effectively untrusted: a tool can print a truncated table, an error
# banner mid-output, ANSI colour, or unexpected unicode. Every parser must degrade
# to an empty/partial result of the right *type*, never raise - a crash here aborts
# the credentialed-enum phase. These specs mutate a real sample of each format.

class _TextSpec:
    def __init__(self, name, fn, seed, rettype):
        self.name = name
        self.fn = fn                        # str -> result (dbs args pre-bound)
        self.seed = seed
        self.rettype = rettype


def _text_specs():
    return [
        _TextSpec("mssql.parse_nxc_mssql", mssql.parse_nxc_mssql,
                  W.NXC_MSSQL_OUTPUT, dict),
        _TextSpec("mssql.parse_enum", mssql.parse_enum,
                  W.MSSQL_ENUM_OUTPUT, dict),
        _TextSpec("mssql.parse_dbowner",
                  lambda t: mssql.parse_dbowner(t, W.MSSQL_DBOWNER_DBS),
                  W.MSSQL_DBOWNER_OUTPUT, dict),
        _TextSpec("mssql.parse_exec", mssql.parse_exec,
                  W.MSSQL_EXEC_OUTPUT, str),
        _TextSpec("mssql.parse_datamine",
                  lambda t: mssql.parse_datamine(t, W.MSSQL_DATAMINE_DBS),
                  W.MSSQL_DATAMINE_OUTPUT, dict),
        _TextSpec("mssql.parse_permmine",
                  lambda t: mssql.parse_permmine(t, W.MSSQL_PERMMINE_DBS),
                  W.MSSQL_PERMMINE_OUTPUT, dict),
        _TextSpec("mssql.parse_write_proof", mssql.parse_write_proof,
                  W.MSSQL_WRITE_PROOF_OUTPUT, dict),
        _TextSpec("credenum.parse_nxc_smb", credenum.parse_nxc_smb,
                  W.NXC_SMB_OUTPUT, dict),
        _TextSpec("credenum.parse_getuserspns", credenum.parse_getuserspns,
                  W.GETUSERSPNS_OUTPUT, list),
        _TextSpec("credenum.parse_getnpusers", credenum.parse_getnpusers,
                  W.GETNPUSERS_OUTPUT, list),
        _TextSpec("credenum.parse_secretsdump", credenum.parse_secretsdump,
                  W.SECRETSDUMP_OUTPUT, list),
        _TextSpec("credenum.parse_ssh_enum", credenum.parse_ssh_enum,
                  W.SSH_ENUM_OUTPUT, dict),
        _TextSpec("bloodhound.parse_tgs", bloodhound.parse_tgs,
                  W.BH_TGS_OUTPUT, list),
        _TextSpec("bloodhound.parse_asrep", bloodhound.parse_asrep,
                  W.BH_ASREP_OUTPUT, list),
        _TextSpec("bloodhound.parse_secretsdump", bloodhound.parse_secretsdump,
                  W.BH_SECRETSDUMP_OUTPUT, list),
    ]


_TEXT_NOISE = ("", "|", "@@", "@@B:", ":::", "\x1b[31m", "\x00", "😀",
               "%s%n", "-" * 400, "\t\t\t", "None", "0xDEADBEEF",
               "$krb5tgs$", "(Pwn3d!)", "NULL")


def _text_mutations(seed, rng, rounds=50):
    """Yield hostile variants of one real tool-output sample."""
    lines = seed.split("\n")
    # every line-prefix truncation (tool killed / pipe closed mid-stream)
    for k in range(len(lines) + 1):
        yield "\n".join(lines[:k])
    # character-level truncations
    for k in range(0, len(seed), max(1, len(seed) // 40)):
        yield seed[:k]
    # drop random lines
    for _ in range(rounds):
        keep = [ln for ln in lines if rng.random() > 0.3]
        yield "\n".join(keep)
    # corrupt delimiters / sentinels / fields in place
    for _ in range(rounds):
        b = list(seed)
        for _ in range(rng.randrange(1, 8)):
            if not b:
                break
            i = rng.randrange(len(b))
            if rng.random() < 0.5:
                b[i] = rng.choice("|:@$\\ \t\n0")
            else:
                del b[i]
        yield "".join(b)
    # inject noise lines at random positions
    for _ in range(rounds):
        pos = rng.randrange(len(lines) + 1)
        noisy = lines[:pos] + [rng.choice(_TEXT_NOISE) * rng.randrange(1, 5)] + lines[pos:]
        yield "\n".join(noisy)
    # duplicate the whole block (tools re-emitting on retry) and reverse it
    yield seed + seed
    yield "\n".join(reversed(lines))
    # pure noise blobs
    for _ in range(rounds):
        yield "".join(rng.choice(_TEXT_NOISE + ("a", "1", "\n"))
                      for _ in range(rng.randrange(0, 200)))


class TextParserFuzzTest(unittest.TestCase):

    def _hammer(self, spec):
        rng = random.Random(0x7E ^ (hash(spec.name) & 0xFFFF))
        for inp in _text_mutations(spec.seed, rng):
            with self.subTest(parser=spec.name, inp=inp[:60]):
                try:
                    with _bounded():
                        result = spec.fn(inp)
                except _Timeout as t:
                    self.fail(f"{spec.name} did not terminate on {inp[:80]!r}: {t}")
                except Exception as e:            # noqa: BLE001 - parsers must not raise
                    self.fail(f"{spec.name} raised {type(e).__name__} "
                              f"on {inp[:80]!r}: {e}")
                self.assertIsInstance(
                    result, spec.rettype,
                    f"{spec.name} returned {type(result).__name__}, "
                    f"expected {spec.rettype.__name__}, on {inp[:80]!r}")

    def test_all_text_parsers_survive_mutations(self):
        for spec in _text_specs():
            self._hammer(spec)

    def test_dbs_arg_mismatch_is_tolerated(self):
        """The mssql db-scoped parsers take a `dbs` list index-aligned with the
        output's sentinels. A mismatch (empty list, or more dbs than sentinels, or
        the wrong names) is a realistic race between what we asked for and what the
        server echoed - it must yield a dict, not an IndexError."""
        cases = [
            (mssql.parse_dbowner, W.MSSQL_DBOWNER_OUTPUT),
            (mssql.parse_datamine, W.MSSQL_DATAMINE_OUTPUT),
            (mssql.parse_permmine, W.MSSQL_PERMMINE_OUTPUT),
        ]
        for fn, out in cases:
            for dbs in ([], ["only-one"], ["a", "b", "c", "d", "e", "f"],
                        ["MASTER", "PayRoll"]):
                with self.subTest(fn=fn.__name__, dbs=dbs):
                    with _bounded():
                        self.assertIsInstance(fn(out, dbs), dict)


if __name__ == "__main__":
    unittest.main()
