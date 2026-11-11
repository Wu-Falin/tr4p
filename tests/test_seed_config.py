import json
import os
import sys

import pytest

from tr4p.config import Config, ConfigError
from tr4p.fsutil import default_home, is_private, write_private
from tr4p.seed import Seed


def test_seed_derivation_is_deterministic_and_separated():
    seed = Seed(b"a" * 32)
    assert seed.digest("x", "ab", "c") == Seed(b"a" * 32).digest("x", "ab", "c")
    assert seed.digest("x", "ab", "c") != seed.digest("x", "a", "bc")
    assert seed.digest("x") != seed.digest("y")
    assert seed.digest("x") != Seed(b"b" * 32).digest("x")
    assert seed.rng("r").random() == seed.rng("r").random()


def test_seed_sign_and_verify():
    seed = Seed.generate()
    tag = seed.sign("cookie", b"value")
    assert seed.verify("cookie", b"value", tag)
    assert not seed.verify("cookie", b"other", tag)
    assert not seed.verify("other-label", b"value", tag)


def test_seed_rejects_short_secret():
    with pytest.raises(ValueError):
        Seed(b"short")


def test_seed_round_trip_is_private(tmp_path):
    path = tmp_path / "home" / "secret.key"
    seed = Seed.generate()
    seed.save(path)
    assert Seed.load(path).digest("x") == seed.digest("x")
    assert is_private(path)
    if sys.platform != "win32":
        assert (path.stat().st_mode & 0o777) == 0o600
        assert (path.parent.stat().st_mode & 0o777) == 0o700


def test_write_private_replaces_atomically(tmp_path):
    path = tmp_path / "file"
    write_private(path, b"one")
    write_private(path, b"two")
    assert path.read_bytes() == b"two"
    assert [item.name for item in tmp_path.iterdir()] == ["file"]


def test_default_home_honours_override(monkeypatch, tmp_path):
    monkeypatch.setenv("TR4P_HOME", str(tmp_path / "custom"))
    assert default_home() == tmp_path / "custom"


def test_config_defaults_are_valid_and_round_trip(tmp_path):
    config = Config()
    config.validate()
    path = tmp_path / "config.json"
    config.save(path)
    assert Config.load(path).to_dict() == config.to_dict()
    assert is_private(path)


def test_config_dashboard_is_loopback_by_default():
    assert Config().dashboard.host == "127.0.0.1"


@pytest.mark.parametrize("patch, message", [
    ({"public": {"mode": "magic"}}, "public.mode"),
    ({"public": {"upstream": "ftp://x"}}, "public.upstream"),
    ({"public": {"port": 0}}, "public.port"),
    ({"public": {"port": 8787}}, "must differ"),
    ({"detection": {"medium_threshold": 90.0, "trap_threshold": 50.0}}, "thresholds"),
    ({"detection": {"weights": {"made_up": 5}}}, "unknown signal weights"),
    ({"whitelist": ["not-an-ip"]}, "whitelist"),
    ({"session": {"cookie_mode": "never"}}, "cookie_mode"),
    ({"surprise": 1}, "unknown setting"),
    ({"public": {"port": "80"}}, "whole number"),
    ({"inject": {"enabled": "yes"}}, "true or false"),
])
def test_config_rejects_bad_values(patch, message):
    with pytest.raises(ConfigError, match=message):
        Config.from_dict(patch)


def test_config_partial_weights_keep_defaults():
    config = Config.from_dict({"detection": {"weights": {"rate": 5}}})
    assert config.detection.weights["rate"] == 5.0
    assert config.detection.weights["canary_path"] == 45.0


def test_config_load_reports_missing_and_malformed(tmp_path):
    with pytest.raises(ConfigError, match="tr4p init"):
        Config.load(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        Config.load(bad)
    bad.write_text(json.dumps([1, 2]), encoding="utf-8")
    with pytest.raises(ConfigError, match="JSON object"):
        Config.load(bad)
