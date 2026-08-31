import pytest

from netsentry.database import Database
from netsentry.threat_detection import ThreatDetectionEngine


@pytest.fixture
def engine(tmp_path):
    db = Database(db_path=str(tmp_path / "threat_test.db"))
    alerts = []
    eng = ThreatDetectionEngine(db, on_alert=lambda a: alerts.append(a))
    eng.alerts = alerts  # convenience handle for assertions
    yield eng
    db.close()


def test_port_scan_detection(engine):
    threshold = engine.cfg["port_scan"]["distinct_ports_threshold"]
    snapshot = [
        {"remote_addr": "203.0.113.5", "local_port": p}
        for p in range(2000, 2000 + threshold)
    ]
    engine.process_connection_snapshot(snapshot)
    types = [a["alert_type"] for a in engine.alerts]
    assert "port_scan" in types


def test_port_scan_not_triggered_below_threshold(engine):
    threshold = engine.cfg["port_scan"]["distinct_ports_threshold"]
    snapshot = [
        {"remote_addr": "203.0.113.9", "local_port": p}
        for p in range(2000, 2000 + threshold - 3)
    ]
    engine.process_connection_snapshot(snapshot)
    assert "port_scan" not in [a["alert_type"] for a in engine.alerts]


def test_brute_force_detection_on_sensitive_port(engine):
    threshold = engine.cfg["brute_force"]["attempt_threshold"]
    for _ in range(threshold):
        engine.process_connection_snapshot([{"remote_addr": "198.51.100.9", "local_port": 22}])
    types = [a["alert_type"] for a in engine.alerts]
    assert "brute_force" in types


def test_brute_force_ignores_non_sensitive_ports(engine):
    threshold = engine.cfg["brute_force"]["attempt_threshold"]
    for _ in range(threshold + 5):
        engine.process_connection_snapshot([{"remote_addr": "198.51.100.9", "local_port": 8080}])
    assert "brute_force" not in [a["alert_type"] for a in engine.alerts]


def test_excessive_connections_detection(engine):
    threshold = engine.cfg["excessive_connections"]["connection_threshold"]
    for _ in range(threshold):
        engine.process_connection_snapshot([{"remote_addr": "198.51.100.50", "local_port": 9999}])
    types = [a["alert_type"] for a in engine.alerts]
    assert "excessive_connections" in types


def test_private_ips_are_ignored(engine):
    threshold = engine.cfg["port_scan"]["distinct_ports_threshold"]
    snapshot = [{"remote_addr": "192.168.1.50", "local_port": p} for p in range(2000, 2000 + threshold + 5)]
    engine.process_connection_snapshot(snapshot)
    assert engine.alerts == []


def test_dns_query_flood_detection(engine):
    threshold = engine.cfg["dns_anomaly"]["query_rate_threshold"]
    for i in range(threshold + 1):
        engine.process_dns_query("10.0.0.5", f"host{i}.example.com")
    types = [a["alert_type"] for a in engine.alerts]
    assert "dns_query_flood" in types


def test_suspicious_tld_detection(engine):
    engine.process_dns_query("10.0.0.5", "somesite.xyz")
    types = [a["alert_type"] for a in engine.alerts]
    assert "suspicious_dns_tld" in types


def test_high_entropy_domain_detection(engine):
    engine.process_dns_query("10.0.0.5", "xkq93jf8vz2mplr7.example.com")
    types = [a["alert_type"] for a in engine.alerts]
    assert "suspicious_dns_domain" in types


def test_alert_cooldown_prevents_duplicate_spam(engine):
    threshold = engine.cfg["brute_force"]["attempt_threshold"]
    for _ in range(threshold * 3):
        engine.process_connection_snapshot([{"remote_addr": "198.51.100.9", "local_port": 22}])
    brute_force_alerts = [a for a in engine.alerts if a["alert_type"] == "brute_force"]
    # cooldown should collapse repeated triggers into a single alert
    assert len(brute_force_alerts) == 1
