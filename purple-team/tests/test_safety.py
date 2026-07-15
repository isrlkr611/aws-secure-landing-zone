import pytest

from safety import LabHost, load_lab_config, require_lab_target


def test_localhost_is_always_allowed_regardless_of_confirmed_flag():
    host = LabHost(name="localhost", address="127.0.0.1", confirmed_own_lab=False)
    require_lab_target(host)  # must not raise


def test_unconfirmed_remote_host_is_refused():
    host = LabHost(name="some-box", address="10.0.0.5", confirmed_own_lab=False)
    with pytest.raises(PermissionError):
        require_lab_target(host)


def test_confirmed_remote_host_is_allowed():
    host = LabHost(name="my-lab-node", address="10.0.0.5", confirmed_own_lab=True)
    require_lab_target(host)  # must not raise


def test_default_lab_config_only_lists_localhost_and_it_is_confirmed():
    hosts = load_lab_config()
    assert "localhost" in hosts
    assert hosts["localhost"].confirmed_own_lab is True
    # The shipped default must not silently pre-authorize anything beyond
    # loopback - if this assertion ever fails, someone added a confirmed
    # non-localhost entry to the committed lab-config.yaml, which defeats
    # the point of the gate being opt-in.
    non_localhost_confirmed = [
        h for h in hosts.values() if h.address not in ("127.0.0.1", "::1", "localhost") and h.confirmed_own_lab
    ]
    assert non_localhost_confirmed == []


def test_load_lab_config_missing_confirmed_flag_defaults_to_false(tmp_path):
    config_file = tmp_path / "lab-config.yaml"
    config_file.write_text(
        "hosts:\n  - name: bare-entry\n    address: 10.1.1.1\n"  # no confirmed_own_lab key at all
    )
    hosts = load_lab_config(config_file)
    assert hosts["bare-entry"].confirmed_own_lab is False
    with pytest.raises(PermissionError):
        require_lab_target(hosts["bare-entry"])
