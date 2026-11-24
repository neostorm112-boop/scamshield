import asyncio
import gzip
from pathlib import Path

import httpx

from scamshield.connectors import ct_data, ct_tiled
from scamshield.contracts import Ctx, Settings, SourceCfg

RAW = gzip.decompress(
    (Path(__file__).parent / "fixtures" / "ct_data_tile.gz").read_bytes()
)  # 6 real Google ParcelYard 2027h1 entries: 3 x509, then 3 precerts

# `openssl x509 -noout -ext subjectAltName` on the same entries (x509 certificate / pre_certificate)
OPENSSL = [
    ["*.bosphorusdataintellect.digital", "bosphorusdataintellect.digital"],
    ["*.marcellusscamehorn4cbyj.pages.dev", "marcellusscamehorn4cbyj.pages.dev"],
    ["atlisoldesoutlet.com"],
    ["lead-up.site", "*.lead-up.site"],
    ["alpinecrown.cc", "*.alpinecrown.cc"],
    ["uaconsulting.biz"],
]


MAX = 8_000_000


def _tlv(tag, body):
    size = len(body)
    head = bytes([size]) if size < 128 else bytes([0x82]) + size.to_bytes(2, "big")
    return bytes([tag]) + head + body


def _precert_entry(*dns_names):
    san = _tlv(0x30, b"".join(_tlv(0x82, name) for name in dns_names))
    extension = _tlv(0x30, _tlv(0x06, bytes.fromhex("551d11")) + _tlv(0x04, san))
    tbs = _tlv(
        0x30, _tlv(0x02, b"\x01") + b"".join(_tlv(0x30, b"") for _ in range(5)) + _tlv(0xA3, _tlv(0x30, extension))
    )
    return (
        bytes(8)
        + (1).to_bytes(2, "big")
        + bytes(32)
        + len(tbs).to_bytes(3, "big")
        + tbs
        + bytes(2)
        + bytes(3)
        + bytes(2)
    )


def test_names_equal_openssl_for_x509_and_precert_entries():
    rows = ct_data.parse_tile(RAW, MAX)

    assert [row["DNS"] for row in rows] == OPENSSL
    assert rows[0]["Timestamp"] == 1795292875240


def test_raw_gzip_body_is_read_too():
    assert [row["DNS"] for row in ct_data.parse_tile(gzip.compress(RAW), MAX)] == OPENSSL


def test_broken_entry_keeps_its_place_as_an_empty_row_and_never_raises():
    garbage = (
        bytes(8) + (0).to_bytes(2, "big") + (4).to_bytes(3, "big") + b"\x30\x02ab" + bytes(4)
    )  # framing is fine, the certificate is not DER
    rows = ct_data.parse_tile(garbage + RAW + garbage, MAX)

    assert [row["DNS"] for row in rows] == [[], *OPENSSL, []]
    assert len(ct_data.parse_tile(RAW[:500], MAX)) < 6
    assert ct_data.parse_tile(b"", MAX) == []
    assert ct_data.parse_tile(b"\x1f\x8bnot gzip", MAX) == []


def test_non_ascii_dns_name_is_dropped():
    rows = ct_data.parse_tile(_precert_entry(b"good.example", "é.example".encode()), MAX)

    assert rows[0]["DNS"] == ["good.example"]


def test_body_over_the_cap_is_refused_before_it_is_expanded():
    assert ct_data.parse_tile(gzip.compress(RAW), len(RAW) - 1) == []
    assert ct_data.parse_tile(RAW, len(RAW) - 1) == []
    assert ct_data.to_lines(gzip.compress(bytes(50_000_000)), MAX, 6) is None


def _ctx(handler, **extra):
    settings = Settings(
        brands=[],
        sources={
            "ct_tiled": SourceCfg(
                "connector",
                extra={
                    "data_tile_hosts": ["storage.googleapis.com"],
                    "data_tile_max_bytes": MAX,
                    "max_lag_minutes": 10**9,
                    **extra,
                },
            )
        },
        scoring={},
        shared_infra={},
        data_dir="",
        port=0,
        db_path="",
        evidence_dir="",
        secrets={},
    )
    return Ctx(
        settings=settings,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        resolver=None,
        budget=_Budget(),
        pool="auto",
        now=lambda: "2026-11-22T00:00:00Z",
    )


class _Budget:
    async def take(self, source, pool="auto"):
        return True


LOG = "https://storage.googleapis.com/log"


def _handler(body, urls):
    def handle(request):
        urls.append(str(request.url))
        if request.url.path.endswith("/checkpoint"):
            return httpx.Response(200, text="log\n6\nhash\n")
        return httpx.Response(200, content=body)

    return handle


def test_data_host_reads_data_tiles_as_names_rows():
    urls = []
    ctx = _ctx(_handler(RAW, urls))

    text = asyncio.run(ct_tiled._read_tile(ctx, LOG, 0, 6))

    assert urls == [LOG + "/tile/data/000.p/6"]
    assert "pages.dev" in text


def test_cursor_in_the_middle_of_a_partial_data_tile():
    ctx = _ctx(_handler(RAW, []))
    step = asyncio.run(ct_tiled._step("3", 256, ctx, LOG))

    assert step.batch.status == "ok"
    assert step.batch.next_cursor == "6"
    assert step.last_ts is not None


def test_truncated_data_tile_is_an_error_and_the_cursor_stays():
    ctx = _ctx(_handler(RAW[:3000], []))
    step = asyncio.run(ct_tiled._step("3", 256, ctx, LOG))

    assert (step.batch.status, step.batch.next_cursor) == ("error", "3")


def test_tile_that_never_parses_is_retried_with_growing_pauses_then_skipped_visibly(monkeypatch):
    stored = []

    async def store(candidates, connector, cursor, recheck_s):
        stored.append(cursor)

    monkeypatch.setattr(ct_tiled.intake, "store_candidates", store)

    def handle(request):
        if request.url.path.endswith("/checkpoint"):
            return httpx.Response(200, text="log\n600\nhash\n")
        return httpx.Response(200, content=RAW[:3000])  # always cut short, for every tile

    ctx = _ctx(
        handle, recheck_hours=6, max_tiles_per_cycle=1, data_tile_concurrency=1, backoff_max_s=60, bad_tile_retries=5
    )
    cursor, results = "0", []
    for _ in range(5):
        result = asyncio.run(ct_tiled.run_once(LOG, cursor, ctx))
        cursor = result["cursor"]
        results.append(result)

    assert [r.get("retry_after_s") for r in results] == [2, 4, 8, 16, None]
    assert [r["status"] for r in results] == ["error"] * 4 + ["ok"]
    assert results[-1]["skipped"]["from"] == 0 and results[-1]["skipped"]["to"] == 256
    assert cursor == "256" and stored == ["256"]
