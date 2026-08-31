import pytest

from netsentry.database import Database


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "test_netsentry.db"))
    yield database
    database.close()


def test_insert_and_read_connection(db):
    db.insert_connection({
        "local_addr": "127.0.0.1", "local_port": 8080,
        "remote_addr": "8.8.8.8", "remote_port": 443,
        "protocol": "TCP", "status": "ESTABLISHED",
        "pid": 100, "process_name": "chrome.exe",
    })
    rows = db.recent_connections()
    assert len(rows) == 1
    assert rows[0]["remote_addr"] == "8.8.8.8"


def test_bulk_insert_connections(db):
    rows = [
        {"local_addr": "127.0.0.1", "local_port": p, "remote_addr": "1.2.3.4",
         "remote_port": 443, "protocol": "TCP", "status": "ESTABLISHED",
         "pid": 1, "process_name": "test"}
        for p in range(5)
    ]
    db.bulk_insert_connections(rows)
    assert len(db.recent_connections()) == 5


def test_insert_and_read_alert(db):
    db.insert_alert({
        "alert_type": "port_scan", "severity": "high",
        "source_ip": "203.0.113.5", "description": "test scan",
        "details": {"ports": [22, 80, 443]},
    })
    alerts = db.recent_alerts()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "port_scan"
    assert alerts[0]["severity"] == "high"


def test_alert_counts_by_severity(db):
    for sev in ("high", "high", "low", "critical"):
        db.insert_alert({"alert_type": "x", "severity": sev, "source_ip": "1.1.1.1"})
    counts = db.alert_counts_by_severity()
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 1


def test_ip_cache_upsert_and_get(db):
    db.upsert_ip_cache("8.8.8.8", {
        "country": "United States", "country_code": "US", "isp": "Google",
        "asn": "AS15169", "reputation_score": 5, "reputation_label": "clean",
    })
    cached = db.get_ip_cache("8.8.8.8")
    assert cached is not None
    assert cached["country"] == "United States"

    # upsert should update, not duplicate
    db.upsert_ip_cache("8.8.8.8", {
        "country": "United States", "country_code": "US", "isp": "Google LLC",
        "asn": "AS15169", "reputation_score": 5, "reputation_label": "clean",
    })
    cached2 = db.get_ip_cache("8.8.8.8")
    assert cached2["isp"] == "Google LLC"


def test_prune_old_rows_keeps_most_recent(db):
    for i in range(20):
        db.insert_alert({"alert_type": "x", "severity": "low", "source_ip": f"1.1.1.{i}"})
    db.prune_old_rows("alerts", keep_last=5)
    assert len(db.recent_alerts(limit=100)) == 5
