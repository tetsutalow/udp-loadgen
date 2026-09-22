import json
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("make-ice-command.py")
ARGS = [
    "--src-ip", "192.0.2.10", "--src-port", "50000",
    "--dst-ip", "192.0.2.20", "--dst-port", "40000",
    "--role", "controlled",
]


def run_tool(local, remote):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *ARGS],
        input=json.dumps(local) + "\n" + json.dumps(remote) + "\n",
        text=True, capture_output=True, check=False,
    )


class MakeIceCommandTests(unittest.TestCase):
    def test_extracts_nested_sdp_and_quotes_password(self):
        local = {"event": "setLocalDescription", "value": {
            "type": "offer", "sdp": "v=0\r\na=ice-ufrag:LOCAL\r\na=ice-pwd:unused\r\n"
        }}
        remote = {"event": "setRemoteDescription", "value": {
            "type": "answer", "sdp": "v=0\r\na=ice-ufrag:REMOTE\r\na=ice-pwd:secret+value/2\r\n"
        }}
        result = run_tool(local, remote)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--sender-ufrag LOCAL", result.stdout)
        self.assertIn("--target-ufrag REMOTE", result.stdout)
        self.assertIn("--target-password secret+value/2", result.stdout)
        self.assertNotIn("unused", result.stdout)

    def test_repeated_credentials_in_bundled_sdp(self):
        sdp = "a=ice-ufrag:A\na=ice-pwd:B\nm=video\na=ice-ufrag:A\na=ice-pwd:B\n"
        result = run_tool({"sdp": sdp}, {"sdp": sdp})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_long_json_and_prefixed_event_value(self):
        local = {"value": "type: offer, sdp: v=0\r\na=ice-ufrag:LOCAL\r\na=ice-pwd:unused\r\n"}
        remote = {"padding": "x" * 10000,
                  "value": "type: answer, sdp: v=0\r\na=ice-ufrag:REMOTE\r\na=ice-pwd:SECRET\r\n"}
        result = run_tool(local, remote)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--target-password SECRET", result.stdout)

    def test_rejects_multiple_ice_generations(self):
        sdp = "a=ice-ufrag:A\na=ice-pwd:B\nm=video\na=ice-ufrag:C\na=ice-pwd:D\n"
        result = run_tool({"sdp": sdp}, {"sdp": sdp})
        self.assertEqual(result.returncode, 2)
        self.assertIn("複数", result.stderr)
        self.assertNotIn("--target-password", result.stdout)

    def test_rejects_missing_password(self):
        result = run_tool({"sdp": "a=ice-ufrag:A\n"}, {"sdp": "a=ice-ufrag:B\na=ice-pwd:C\n"})
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
