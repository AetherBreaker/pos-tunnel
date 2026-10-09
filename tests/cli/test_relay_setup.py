# Standard library imports
import json
import os
import socket
import subprocess
import time
import tomllib
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Third party imports
import pytest

if TYPE_CHECKING:
  # Standard library imports
  from collections.abc import Callable

pytestmark = pytest.mark.skipif(os.environ.get("POS_TUNNEL_DOCKER") != "1", reason="Docker tests: set POS_TUNNEL_DOCKER=1")
ROOT = Path(__file__).resolve().parents[2]
RELAY = ROOT / "relay"
EXE = ".exe" if os.name == "nt" else ""


def sh(
  *args: str,
  check: bool = True,
  timeout: int = 900,
  cwd: Path | None = None,
  env: dict[str, str] | None = None,
  stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
  return subprocess.run(list(args), capture_output=True, text=True, check=check, timeout=timeout, cwd=cwd, env=env, input=stdin)


def wait_for(what: str, condition: Callable[[], bool], timeout: float) -> None:
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if condition():
      return
    time.sleep(2)
  pytest.fail(f"timed out after {timeout:g} s waiting for {what}")


def free_port() -> int:
  with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    return s.getsockname()[1]


def config_of(home: Path) -> dict[str, Any]:
  return tomllib.loads((home / "posctl" / "config.toml").read_text(encoding="utf-8"))


class Setup:
  """`posctl-admin` building a relay's configuration, and the real relay container running with it."""

  def __init__(self, tmp: Path) -> None:
    self.tag = uuid.uuid4().hex[:8]
    self.port = free_port()
    self.admin_home, self.bob_home = tmp / "admin", tmp / "bob"
    self.network, self.relay, self.logserver = f"setup-net-{self.tag}", f"setup-relay-{self.tag}", f"setup-logs-{self.tag}"
    self.volume = f"setup-data-{self.tag}"
    self.bundle = ""
    admin_key = tmp / "admin_key"
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(admin_key))
    admin_pub = " ".join(admin_key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2])
    # posctl-admin runs only with the admin key built into it, so build one with this test's.
    sh("cargo", "build", "--bins", cwd=ROOT, env={**os.environ, "POSCTL_ADMIN_KEY": admin_pub})
    target = json.loads(sh("cargo", "metadata", "--format-version", "1", "--no-deps", cwd=ROOT).stdout)["target_directory"]
    self.bin = Path(target) / "debug"
    # What `posctl-admin init` writes after signing in to NinjaOne, which this test has no tenant for.
    config = self.admin_home / "posctl" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
      f"operator_key = {json.dumps(str(admin_key))}\n\n[ninjaone]\n"
      'base_url = "https://example.invalid"\nclient_id = "c"\npos_policy_id = 1\ninstall_script_id = 2\ninvoke_script_id = 3\n',
      encoding="utf-8",
    )
    (self.admin_home / "posctl-admin").mkdir()
    (self.admin_home / "posctl-admin" / "operators.toml").write_text(f'[operators]\nadmin = "{admin_pub}"\n', encoding="utf-8")

  def run(self, binary: str, *args: str, home: Path, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "POSCTL_CONFIG_HOME": str(home)}
    return sh(str(self.bin / f"{binary}{EXE}"), *args, env=env, stdin=stdin, check=check, timeout=60)

  def up(self, relay_line: str, operators_line: str) -> None:
    sh("docker", "build", "-q", "-f", "tests/integration/Dockerfile", "-t", "pos-tunnel-relay:test", ".", cwd=RELAY)
    sh("docker", "build", "-q", "-f", "tests/integration/logserver.Dockerfile", "-t", "pos-tunnel-relay-logs:test", ".", cwd=RELAY)
    sh("docker", "network", "create", self.network)
    sh("docker", "volume", "create", self.volume)
    # -i keeps the log server's stdin open: it shuts down when stdin closes.
    sh(
      "docker",
      "run",
      "-d",
      "-i",
      "--name",
      self.logserver,
      "--network",
      self.network,
      "--network-alias",
      "logserver",
      "pos-tunnel-relay-logs:test",
    )
    # The relay exits if the log server isn't listening yet (aeth_ext's startup probe).
    wait_for("the log server", lambda: '"log_port"' in sh("docker", "logs", self.logserver).stdout, timeout=60)
    sh(
      "docker", "run", "-d", "--name", self.relay, "--network", self.network, "-p", f"127.0.0.1:{self.port}:2222",
      "-v", f"{self.volume}:/app/persisted_data",
      "-e", relay_line, "-e", operators_line,
      "-e", "ALERTS_EMAIL_PWD=unused", "-e", "LOG_CONN_HOST=logserver", "-e", "LOG_CONN_PORT=9020",
      "pos-tunnel-relay:test",
    )  # fmt: skip

  def down(self) -> None:
    for name in (self.relay, self.logserver):
      sh("docker", "rm", "-f", name, check=False)
    sh("docker", "network", "rm", self.network, check=False)
    sh("docker", "volume", "rm", self.volume, check=False)

  def ctl_status(self, home: Path) -> subprocess.CompletedProcess[str]:
    """`tunnelctl status` as the operator whose posctl config is in `home`, the relay key pinned from that config."""
    config = config_of(home)
    known_hosts = home / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{self.port} {config['relay']['public_key']}\n", encoding="utf-8")
    return sh(
      "ssh", "-F", "none", "-p", str(self.port), "-i", config["operator_key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
      "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}", "ctl@127.0.0.1", "tunnelctl", "status",
      check=False, timeout=30,
    )  # fmt: skip


@pytest.fixture(scope="module")
def setup(tmp_path_factory: pytest.TempPathFactory):
  s = Setup(tmp_path_factory.mktemp("setup"))
  try:
    relay_line = s.run("posctl-admin", "relay", "keygen", f"127.0.0.1:{s.port}", home=s.admin_home).stdout.strip()
    s.bundle, operators_line = s.run("posctl-admin", "operator", "add", "bob", home=s.admin_home).stdout.splitlines()
    s.up(relay_line, operators_line)
    wait_for("the relay", lambda: s.ctl_status(s.admin_home).returncode == 0, timeout=120)
    yield s
  finally:
    if os.environ.get("POS_TUNNEL_KEEP") != "1":
      s.down()


def test_the_admin_reaches_tunnelctl_with_the_relay_key_pinned(setup: Setup):
  result = setup.ctl_status(setup.admin_home)

  assert result.returncode == 0, result.stderr
  assert json.loads(result.stdout) == []


def test_an_added_operator_imports_the_bundle_and_reaches_tunnelctl(setup: Setup):
  setup.run("posctl", "operator", "import", home=setup.bob_home, stdin=setup.bundle + "\n")

  result = setup.ctl_status(setup.bob_home)

  assert result.returncode == 0, result.stderr
  assert json.loads(result.stdout) == []


def test_posctl_admin_refuses_anyone_but_the_admin(setup: Setup):
  result = setup.run("posctl-admin", "operator", "list", home=setup.bob_home, check=False)

  assert result.returncode != 0
  assert "not the admin's operator key" in result.stderr


def test_relay_set_repoints_an_operator(setup: Setup):
  relay_key = config_of(setup.admin_home)["relay"]["public_key"]

  setup.run("posctl", "relay", "set", "relay.example.com", *relay_key.split(), home=setup.bob_home)

  assert config_of(setup.bob_home)["relay"] == {"host": "relay.example.com", "port": 2222, "public_key": relay_key}
