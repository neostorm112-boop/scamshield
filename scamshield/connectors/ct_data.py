"""DNS names from Static CT data tiles (https://c2sp.org/static-ct-api), for logs without the names-tile extension."""

from __future__ import annotations

import json
import zlib

_SAN_OID = bytes.fromhex("551d11")  # 2.5.29.17 subjectAltName
_CN_OID = bytes.fromhex("550403")  # 2.5.4.3 commonName
_STRING_TAGS = {0x0C: "utf-8", 0x13: "ascii", 0x16: "ascii", 0x14: "latin-1", 0x1E: "utf-16-be"}


class _Bad(Exception):
    pass


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, content start, content end) of the DER element at pos."""
    if pos + 2 > len(data):
        raise _Bad
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first & 0x80:
        count = first & 0x7F
        if not 1 <= count <= 4 or pos + count > len(data):
            raise _Bad
        first = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + first > len(data):
        raise _Bad
    return tag, pos, pos + first


def _children(data: bytes, start: int, end: int):
    while start < end:
        tag, cstart, cend = _tlv(data, start)
        yield tag, start, cstart, cend  # tag, element start, content start, content end
        start = cend


def _tbs_names(tbs: bytes) -> list[str]:
    """dNSName entries of the SAN extension; the subject CN only when the certificate has none."""
    _, start, end = _tlv(tbs, 0)
    fields = list(_children(tbs, start, end))
    if fields and fields[0][0] == 0xA0:  # explicit version
        fields = fields[1:]
    if len(fields) < 6:  # serial, signature, issuer, validity, subject, spki
        raise _Bad
    names, common = [], []
    for rdn in _children(tbs, fields[4][2], fields[4][3]):
        for attr in _children(tbs, rdn[2], rdn[3]):
            _, oid_start, oid_end = _tlv(tbs, attr[2])
            value_tag, value_start, value_end = _tlv(tbs, oid_end)
            if tbs[oid_start:oid_end] == _CN_OID and value_tag in _STRING_TAGS:
                common.append(tbs[value_start:value_end].decode(_STRING_TAGS[value_tag], "ignore").strip().lower())
    for field in fields:
        if field[0] != 0xA3:  # [3] extensions
            continue
        _, ext_list_start, ext_list_end = _tlv(tbs, field[2])
        for ext in _children(tbs, ext_list_start, ext_list_end):
            _, oid_start, oid_end = _tlv(tbs, ext[2])
            if tbs[oid_start:oid_end] != _SAN_OID:
                continue
            tag, value_start, value_end = _tlv(tbs, oid_end)
            if tag == 0x01:  # critical flag
                tag, value_start, value_end = _tlv(tbs, value_end)
            if tag != 0x04:
                raise _Bad
            _, names_start, names_end = _tlv(tbs, value_start)
            for g in _children(tbs, names_start, names_end):
                if (
                    g[0] == 0x82 and tbs[g[2] : g[3]].isascii()
                ):  # a non-ASCII dNSName is malformed: drop it, do not guess
                    names.append(tbs[g[2] : g[3]].decode("ascii").lower())
    return names or [c for c in common if "." in c and " " not in c]


def _cert_tbs(cert: bytes) -> bytes:
    _, start, _ = _tlv(cert, 0)
    _, _, end = _tlv(cert, start)
    return cert[start:end]


def _take(body: bytes, pos: int, size: int) -> tuple[int, int]:
    """Read a big-endian length field of `size` bytes: (value, next position)."""
    if pos + size > len(body):
        raise _Bad
    return int.from_bytes(body[pos : pos + size], "big"), pos + size


def parse_tile(body: bytes, max_bytes: int) -> list[dict]:
    """Names-tile style rows {"Timestamp": ms, "DNS": [...]}, one per entry of a data tile (an unreadable certificate gives an empty DNS list,
    so row i is always entry i). Broken framing or a body over max_bytes ends the tile: fewer rows than entries."""
    if body[:2] == b"\x1f\x8b":  # raw gzip, when the server did not set Content-Encoding
        inflater = zlib.decompressobj(31)
        try:
            body = inflater.decompress(body, max_bytes + 1)
        except zlib.error:
            return []
    if len(body) > max_bytes:
        return []
    rows, pos = [], 0
    try:
        while pos < len(body):
            timestamp, pos = _take(body, pos, 8)
            kind, pos = _take(body, pos, 2)
            if kind == 1:
                pos += 32  # issuer_key_hash
            elif kind != 0:
                break
            size, pos = _take(body, pos, 3)
            signed = body[pos : pos + size]
            pos += size
            size, pos = _take(body, pos, 2)  # extensions
            pos += size
            if kind == 1:
                size, pos = _take(body, pos, 3)  # pre_certificate
                pos += size
            size, pos = _take(body, pos, 2)  # certificate_chain fingerprints
            pos += size
            try:
                rows.append({"Timestamp": timestamp, "DNS": _tbs_names(signed if kind == 1 else _cert_tbs(signed))})
            except _Bad:
                rows.append({"Timestamp": timestamp, "DNS": []})
    except _Bad:
        pass
    return rows


def to_lines(body: bytes, max_bytes: int, width: int) -> str | None:
    """JSON lines of the tile, or None when it holds fewer than `width` entries (cut short, unreadable)."""
    rows = parse_tile(body, max_bytes)
    return "\n".join(json.dumps(row) for row in rows) if len(rows) == width else None
