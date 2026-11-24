import re
import sqlite3
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "live_drill.sh"


def _dup_count(rows):
    sql = re.search(r'dups\(\) \{\s*q "(.+?)"\n', SCRIPT.read_text()).group(1)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE facts (domain_id, type, source, job_id, value_json)")
    db.executemany("INSERT INTO facts VALUES (?,?,?,?,?)", rows)
    return db.execute(sql).fetchone()[0]


def test_two_ips_of_one_domain_are_not_duplicates():
    rows = [(1, "ip_asn", "dns", 7, '{"ip":"1.1.1.1"}'), (1, "ip_asn", "dns", 7, '{"ip":"2.2.2.2"}')]
    assert _dup_count(rows) == 0


def test_same_value_twice_is_a_duplicate():
    rows = [(1, "ip_asn", "dns", 7, '{"ip":"1.1.1.1"}')] * 2
    assert _dup_count(rows) == 1
