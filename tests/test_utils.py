from netsentry.utils import shannon_entropy, is_private_ip, human_bytes


def test_shannon_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_repeated_char_is_zero():
    assert shannon_entropy("aaaaaa") == 0.0


def test_shannon_entropy_random_string_is_high():
    assert shannon_entropy("xk29fjq8zmq1qptr") > 3.0


def test_is_private_ip_ranges():
    assert is_private_ip("10.0.0.5")
    assert is_private_ip("172.16.4.4")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("169.254.1.1")


def test_is_private_ip_public_addresses():
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("1.1.1.1")


def test_is_private_ip_malformed_defaults_to_true():
    assert is_private_ip("not-an-ip")
    assert is_private_ip("::1")


def test_human_bytes_formatting():
    assert human_bytes(500).strip().startswith("500.0")
    assert "KB" in human_bytes(2048)
    assert "MB" in human_bytes(5 * 1024 * 1024)
