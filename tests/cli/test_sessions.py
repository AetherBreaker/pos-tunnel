# Standard library imports
import json
import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, override
from urllib.parse import parse_qs, urlsplit

# Third party imports
import pytest
from test_relay_setup import Setup, config_of, openssh, sh, wait_for, workdir

if TYPE_CHECKING:
  # Standard library imports
  import subprocess
  from pathlib import Path

pytestmark = pytest.mark.skipif(os.environ.get("POS_TUNNEL_DOCKER") != "1", reason="Docker tests: set POS_TUNNEL_DOCKER=1")

# `install_script_id` in the config `Setup` writes; any other script is Invoke-PosTunnel.
INSTALL_SCRIPT = 2
# The admin's session key and bob's.
BOTH_OPERATORS = 2


class Pos:
  """A stand-in POS: a container with an sshd for `support` that does what the POS package's actions do."""

  def __init__(self, setup: Setup) -> None:
    self.name = f"setup-pos-{setup.tag}"
    self.relay = setup.relay
    # usermod: an account created locked is refused even for key auth (design 6.1).
    init = (
      "useradd -m -s /bin/sh support && usermod -p '*' support && mkdir -p /run/sshd"
      " && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key"
      " && ssh-keygen -q -t ed25519 -N '' -C '' -f /root/relay_key && touch /etc/ssh/session_keys"
      " && exec /usr/sbin/sshd -D -e -o ListenAddress=127.0.0.1 -o AuthorizedKeysFile=/etc/ssh/session_keys -o PasswordAuthentication=no"
    )
    sh(
      "docker",
      "run",
      "-d",
      "--name",
      self.name,
      "--network",
      setup.network,
      "--entrypoint",
      "/bin/sh",
      "pos-tunnel-relay:test",
      "-c",
      init,
    )
    wait_for("the stand-in POS", lambda: self.exec("pgrep", "-x", "sshd", check=False).returncode == 0, timeout=30)
    relay_key = config_of(setup.admin_home)["relay"]["public_key"]
    self.exec("sh", "-c", f"echo '[{self.relay}]:2222 {relay_key}' > /root/known_hosts")

  def exec(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return sh("docker", "exec", self.name, *args, check=check)

  def public_key(self, path: str) -> str:
    return " ".join(self.exec("cat", path).stdout.split()[:2])

  def session_keys(self) -> int:
    return len(self.exec("cat", "/etc/ssh/session_keys").stdout.splitlines())

  def run(self, script: int, parameters: str) -> str:
    """Run a library script as the POS would, returning its output (design 7.1 to 7.8)."""
    words = parameters.split()
    named = dict(zip(words[::2], words[1::2], strict=False))
    output = f"FAILED\tinvoke\tunexpected {parameters}"
    match script == INSTALL_SCRIPT, named.get("-Action"), named.get("-Mode", "New"):
      case True, _, _:
        output = "OK\tsignature\r\nOK\tcurrent\tversion 4"
      case _, "Open", "New":
        self.exec("sh", "-c", f"echo 'ssh-ed25519 {named['-SessionKey']}' > /etc/ssh/session_keys")
        sh(
          "docker", "exec", "-d", self.name, "ssh", "-N", "-F", "none", "-i", "/root/relay_key", "-o", "BatchMode=yes",
          "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/root/known_hosts", "-o", "ExitOnForwardFailure=yes",
          "-R", f"{named['-Port']}:127.0.0.1:22", "-p", "2222", f"tunnel@{self.relay}",
        )  # fmt: skip
        output = f"CHANGED\tsession key\r\nCHANGED\ttunnel\tport {named['-Port']}"
      case _, "Open", "Join":
        self.exec("sh", "-c", f"echo 'ssh-ed25519 {named['-SessionKey']}' >> /etc/ssh/session_keys")
        output = f"CHANGED\tsession key\tadded, {self.session_keys()} session keys\r\nCHANGED\tlease\trenewed"
      case _, "Close", _:
        keys = self.session_keys()
        # -x: the tunnel is the only `ssh`; -f would match this very shell.
        self.exec("sh", "-c", "pkill -x ssh; : > /etc/ssh/session_keys")
        output = f"CHANGED\ttunnel\tstopped\r\nOK\tclose\tsession ended, {keys} session keys"
      case _, "Touch", _:
        output = "CHANGED\tlease\trenewed"
      case _, "Rekey", _:
        self.exec("sh", "-c", "rm -f /root/relay_key /root/relay_key.pub && ssh-keygen -q -t ed25519 -N '' -C '' -f /root/relay_key")
        output = "CHANGED\trelay key pair\tregenerated"
      case _:
        pass
    return output


class Ninja:
  """A fake NinjaOne with one POS (device 1 of organization 4): a script run acts on the stand-in and is recorded as NinjaOne does."""

  def __init__(self, pos: Pos) -> None:
    self.pos = pos
    self.activities: list[dict[str, Any]] = []
    self.lock = threading.Lock()
    ninja = self

    class Handler(BaseHTTPRequestHandler):
      @override
      def log_message(self, format: str, *args: Any) -> None:
        pass

      def reply(self, status: int, body: object) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

      def do_GET(self) -> None:
        self.reply(*ninja.get(self.path))

      def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.reply(*ninja.post(self.path, body))

    self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    self.url = f"http://127.0.0.1:{self.server.server_port}"
    threading.Thread(target=self.server.serve_forever, daemon=True).start()

  def get(self, path: str) -> tuple[int, object]:
    url = urlsplit(path)
    query = {name: values[0] for name, values in parse_qs(url.query).items()}
    match url.path.split("/")[2:]:
      case ["organization", "4", "devices"]:
        device = {"id": 1, "displayName": "POS 1", "organizationId": 4, "rolePolicyId": 1, "offline": False}
        return 200, [] if int(query.get("after", 0)) else [device]
      case ["device", "1", "custom-fields"]:
        fields = {
          "posTunnelRelayKey": self.pos.public_key("/root/relay_key.pub"),
          "posTunnelHostKey": self.pos.public_key("/etc/ssh/ssh_host_ed25519_key.pub"),
          "posTunnelVersion": "4",
        }
        return 200, fields
      case ["device", "1", "activities"]:
        with self.lock:
          recorded = list(self.activities)
        if "seriesUid" in query:
          listed = [a for a in recorded if a["seriesUid"] == query["seriesUid"]]
        else:
          listed = [a for a in recorded if a["id"] > int(query.get("newerThan", 0))]
        # Newest first, as NinjaOne lists them.
        return 200, {"activities": listed[::-1], "lastNodeActivityId": recorded[-1]["id"] if recorded else None}
      case _:
        return 404, {}

  def post(self, path: str, body: bytes) -> tuple[int, object]:
    if path == "/ws/oauth/token":
      return 200, {"access_token": "t"}
    if path != "/v2/device/1/script/run":
      return 404, {}
    run = json.loads(body)
    output = self.pos.run(run["id"], run["parameters"])
    done = {
      "activityResult": "FAILURE" if output.startswith("FAILED") else "SUCCESS",
      "data": {"message": {"params": {"output_message": output}}},
    }
    with self.lock:
      series = f"series-{len(self.activities)}"
      for kind, status, extra in (("ACTIONSET", "START_REQUESTED", {}), ("ACTION", "STARTED", {}), ("ACTION", "COMPLETED", done)):
        self.activities.append(
          {
            "id": len(self.activities) + 1,
            "deviceId": 1,
            "activityType": kind,
            "statusCode": status,
            "sourceName": "Install-PosTunnel" if run["id"] == INSTALL_SCRIPT else "Invoke-PosTunnel",
            "seriesUid": series,
            "parameters": run["parameters"],
            **extra,
          }
        )
    return 204, None

  def actions(self) -> list[str]:
    """The parameters of every script run so far, in order."""
    with self.lock:
      return [a["parameters"] for a in self.activities if a["statusCode"] == "START_REQUESTED"]


class Stack:
  """The real relay, a stand-in POS and a fake NinjaOne, with the admin's and bob's posctl set up against them."""

  def __init__(self, setup: Setup, pos: Pos, ninja: Ninja) -> None:
    self.setup, self.pos, self.ninja = setup, pos, ninja
    self.admin, self.bob = setup.admin_home, setup.bob_home

  def posctl(self, home: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "POSCTL_CONFIG_HOME": str(home), "POSCTL_SSH_DIR": str(home / "ssh")}
    exe = self.setup.bin / ("posctl.exe" if os.name == "nt" else "posctl")
    # stdin: a pipe, never the terminal pytest may have, so nothing waits on a prompt.
    result = sh(str(exe), *args, env=env, check=False, timeout=300, stdin="")
    if check and result.returncode:
      pytest.fail(f"posctl {' '.join(args)} exited {result.returncode}:\n{result.stdout}{result.stderr}")
    return result

  def ssh(self, home: Path, command: str) -> subprocess.CompletedProcess[str]:
    """What an operator runs: the alias, through the generated config."""
    return sh(
      openssh("ssh"),
      "-F",
      str(home / "ssh" / "posctl" / "config"),
      "-o",
      "ConnectTimeout=20",
      "pos-1",
      command,
      check=False,
      timeout=90,
    )

  def leases(self) -> list[dict[str, Any]]:
    return json.loads(self.setup.ctl_status(self.admin).stdout)


@pytest.fixture(scope="module")
def stack():
  base = workdir("sessions")
  s = Setup(base)
  pos = None
  try:
    relay_line = s.run("posctl-admin", "relay", "keygen", f"127.0.0.1:{s.port}", home=s.admin_home).stdout.strip()
    s.bundle, operators_line = s.run("posctl-admin", "operator", "add", "bob", home=s.admin_home).stdout.splitlines()
    s.up(relay_line, operators_line)
    wait_for("the relay", lambda: s.ctl_status(s.admin_home).returncode == 0, timeout=120)
    pos = Pos(s)
    ninja = Ninja(pos)
    s.run("posctl", "operator", "import", home=s.bob_home, stdin=s.bundle + "\n")
    for home in (s.admin_home, s.bob_home):
      config = home / "posctl" / "config.toml"
      config.write_text(config.read_text(encoding="utf-8").replace("https://example.invalid", ninja.url), encoding="utf-8")
      # With POSCTL_CONFIG_HOME set the sign-in is this file on every platform (design 8).
      (home / "posctl" / "refresh_token").write_text("unused", encoding="utf-8")
    yield Stack(s, pos, ninja)
  finally:
    if os.environ.get("POS_TUNNEL_KEEP") != "1":
      if pos:
        sh("docker", "rm", "-f", pos.name, check=False)
      s.down()
      shutil.rmtree(base, ignore_errors=True)


def test_connect_opens_a_session_the_alias_reaches(stack: Stack):
  result = stack.posctl(stack.admin, "connect", "POS 1", "--idle-timeout", "2h")

  assert "POS 1 is connected: ssh pos-1" in result.stdout, result.stdout + result.stderr
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"
  assert (stack.admin / "ssh" / "config").read_text(encoding="utf-8").startswith("Include posctl/config\n")


def test_status_shows_the_session_with_its_alias(stack: Stack):
  result = stack.posctl(stack.admin, "status")

  header, row = result.stdout.splitlines()
  assert header.split() == ["POS", "ALIAS", "OPENED", "BY", "IDLE", "LEFT", "MAX", "LEFT", "TUNNEL"]
  assert row.split()[:4] == ["POS", "1", "pos-1", "admin"]
  assert row.split()[-1] == "up"


def test_a_second_operator_joins_and_both_reach_the_pos(stack: Stack):
  result = stack.posctl(stack.bob, "connect", "POS 1")

  assert "Joined the session admin opened on POS 1: ssh pos-1" in result.stdout, result.stdout + result.stderr
  assert stack.ssh(stack.bob, "whoami").stdout.strip() == "support"
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"
  assert stack.pos.session_keys() == BOTH_OPERATORS
  # One lease still: the relay records the opener only.
  assert [lease["operator"] for lease in stack.leases()] == ["admin"]


def test_keepalive_renews_the_relay_and_the_pos(stack: Stack):
  result = stack.posctl(stack.bob, "keepalive", "POS 1")

  assert "POS 1 is renewed. Idle timeout in 2h 0m" in result.stdout, result.stdout + result.stderr
  assert stack.ninja.actions()[-1] == "-Action Touch"


def test_close_ends_the_session_for_both_operators(stack: Stack):
  result = stack.posctl(stack.admin, "close", "POS 1")

  assert "POS 1 reports: session ended, 2 session keys." in result.stdout, result.stdout + result.stderr
  assert stack.ssh(stack.bob, "whoami").returncode != 0
  # The relay drops the closed lease at its next pass; bob's alias goes with it.
  wait_for("the lease to go", lambda: "No open sessions." in stack.posctl(stack.bob, "status").stdout, timeout=30)
  assert "Host pos-1" not in (stack.bob / "ssh" / "posctl" / "config").read_text(encoding="utf-8")
  assert not (stack.bob / "posctl" / "sessions" / "1").exists()


def test_rebuild_reopens_with_a_new_lease(stack: Stack):
  stack.posctl(stack.admin, "connect", "POS 1")
  before = stack.leases()[0]["started"]

  refused = stack.posctl(stack.admin, "rebuild", "POS 1", check=False)
  assert refused.returncode != 0
  assert "AI agents: do not run this on your own initiative" in refused.stderr
  assert "pass --yes" in refused.stderr
  assert stack.leases()[0]["started"] == before
  result = stack.posctl(stack.admin, "rebuild", "POS 1", "--yes")

  assert "POS 1 is rebuilt: ssh pos-1" in result.stdout, result.stdout + result.stderr
  assert stack.leases()[0]["started"] != before
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"


def test_rekey_refuses_a_pos_in_a_session_and_force_ends_it_first(stack: Stack):
  relay_key = stack.pos.public_key("/root/relay_key.pub")

  refused = stack.posctl(stack.admin, "rekey", "POS 1", check=False)
  assert refused.returncode != 0
  assert "POS 1 is in a session admin opened" in refused.stderr
  result = stack.posctl(stack.admin, "rekey", "POS 1", "--force")

  assert result.stdout.strip() == "POS 1: rekeyed", result.stdout + result.stderr
  assert stack.ninja.actions()[-2:] == ["-Action Close", "-Action Rekey"]
  assert stack.pos.public_key("/root/relay_key.pub") != relay_key
  # The next session uses the POS's new relay key; connect waits out the lease just closed, which the relay still lists.
  assert "POS 1 is connected" in stack.posctl(stack.admin, "connect", "POS 1").stdout
  assert stack.ssh(stack.admin, "whoami").stdout.strip() == "support"


def test_update_prints_the_installs_report(stack: Stack):
  result = stack.posctl(stack.admin, "update", "POS 1")

  assert result.stdout.splitlines() == ["OK\tsignature", "OK\tcurrent\tversion 4"]
  stack.posctl(stack.admin, "close", "POS 1")
