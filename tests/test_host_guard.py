from security.host_guard import (
    parse_host,
    host_allowed,
    is_ip_literal,
    validate_forwarded,
    dns_rebind_ok
)


def test_exact():
    assert host_allowed('app.example', {'app.example'}) is True

def test_suffix():
    assert host_allowed('app.example.evil.com', {'app.example'}) is False

def test_port():
    assert parse_host('app.example:443') == 'app.example'

def test_userinfo():
    assert parse_host('app.example@evil.com') == ''

def test_ip():
    assert is_ip_literal('127.0.0.1') is True

def test_ip_reject():
    assert host_allowed('127.0.0.1', {'app.example'}) is False

def test_forwarded():
    assert validate_forwarded('app.example', {'app.example'}) is True

def test_forwarded_bad():
    assert validate_forwarded('evil.example, app.example', {'app.example'}) is False

def test_missing():
    assert host_allowed('', {'app.example'}) is False

def test_localhost():
    assert host_allowed('localhost', {'localhost'}) is False

def test_upper():
    assert host_allowed('APP.EXAMPLE', {'app.example'}) is True

def test_dot():
    assert parse_host('app.example.') == 'app.example'

def test_wildcard():
    assert host_allowed('x.example', {'*.example'}) is False

def test_empty():
    assert parse_host('') == ''

def test_rebind():
    assert dns_rebind_ok('app.example', '10.0.0.1') is False
