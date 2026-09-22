import hashlib
import hmac
import os
import socket
import struct
import subprocess
import unittest
import zlib
from pathlib import Path


PROGRAM = Path(os.environ.get("UDP_LOADGEN_BIN", Path(__file__).with_name("udp-loadgen")))
PASSWORD = b"targetPassword0123456789"


def attributes(packet):
    offset = 20
    result = []
    while offset < len(packet):
        kind, length = struct.unpack_from("!HH", packet, offset)
        value = packet[offset + 4:offset + 4 + length]
        result.append((kind, value, offset))
        offset += 4 + ((length + 3) & ~3)
    if offset != len(packet):
        raise AssertionError("attribute length does not match STUN header")
    return result


def binding_response(request, error_code=0):
    message_type = 0x0101 if error_code == 0 else 0x0111
    if error_code == 0:
        preceding = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, 0x2112, 0x2112A442)
    else:
        preceding = struct.pack("!HHBBBB", 0x0009, 4, 0, 0,
                                error_code // 100, error_code % 100)
    integrity = struct.pack("!HH", 0x0008, 20)
    fingerprint = struct.pack("!HH", 0x8028, 4)
    full_length = len(preceding) + 24 + 8
    header = struct.pack("!HHI", message_type, full_length, 0x2112A442) + request[8:20]
    adjusted = struct.pack("!HHI", message_type, len(preceding) + 24,
                           0x2112A442) + request[8:20]
    digest = hmac.new(PASSWORD, adjusted + preceding, hashlib.sha1).digest()
    without_fp = header + preceding + integrity + digest
    crc = (zlib.crc32(without_fp) ^ 0x5354554e) & 0xffffffff
    return without_fp + fingerprint + struct.pack("!I", crc)


class IceBindingTests(unittest.TestCase):
    def test_packets_have_valid_ice_attributes_hmac_and_fingerprint(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(3)
            dest_port = receiver.getsockname()[1]
            command = [
                str(PROGRAM), "--mode", "ice-binding",
                "--src-ip", "127.0.0.1", "--src-port", "0",
                "--dst-ip", "127.0.0.1", "--dst-port", str(dest_port),
                "--sender-ufrag", "EDGE1234", "--target-ufrag", "SFU5678",
                "--target-password-env", "TEST_ICE_PASSWORD",
                "--role", "controlled", "--priority", "0x6e0001ff",
                "--pps", "1000", "--duration", "0", "--count", "2", "--quiet",
            ]
            env = dict(os.environ, TEST_ICE_PASSWORD=PASSWORD.decode("ascii"))
            run = subprocess.run(command, env=env, capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            packets = [receiver.recvfrom(2048)[0] for _ in range(2)]

        ids = set()
        for packet in packets:
            self.assertEqual(packet[:2], b"\x00\x01")
            self.assertEqual(struct.unpack_from("!H", packet, 2)[0], len(packet) - 20)
            self.assertEqual(packet[4:8], b"\x21\x12\xa4\x42")
            ids.add(packet[8:20])
            attrs = attributes(packet)
            self.assertEqual([a[0] for a in attrs],
                             [0x0006, 0x0024, 0x8029, 0x0008, 0x8028])
            self.assertEqual(attrs[0][1], b"SFU5678:EDGE1234")
            self.assertEqual(struct.unpack("!I", attrs[1][1])[0], 0x6e0001ff)
            self.assertEqual(len(attrs[2][1]), 8)
            self.assertEqual(len(attrs[3][1]), 20)
            mi_offset = attrs[3][2]
            hmac_input = bytearray(packet[:mi_offset])
            struct.pack_into("!H", hmac_input, 2, mi_offset + 24 - 20)
            expected = hmac.new(PASSWORD, hmac_input, hashlib.sha1).digest()
            self.assertEqual(attrs[3][1], expected)
            fp_offset = attrs[4][2]
            fingerprint = (zlib.crc32(packet[:fp_offset]) ^ 0x5354554e) & 0xffffffff
            self.assertEqual(struct.unpack("!I", attrs[4][1])[0], fingerprint)
        self.assertEqual(len(ids), 2, "each request must use a fresh transaction ID")

    def test_authenticated_success_response_is_counted(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(3)
            command = [
                str(PROGRAM), "--mode", "ice-binding",
                "--src-ip", "127.0.0.1", "--src-port", "0",
                "--dst-ip", "127.0.0.1", "--dst-port", str(receiver.getsockname()[1]),
                "--sender-ufrag", "EDGE1234", "--target-ufrag", "SFU5678",
                "--target-password", PASSWORD.decode("ascii"),
                "--role", "controlled", "--count", "1", "--duration", "0",
                "--response-wait", "1", "--quiet",
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            try:
                request, address = receiver.recvfrom(2048)
                receiver.sendto(binding_response(request), address)
                stdout, stderr = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.assertEqual(process.returncode, 0, stderr)
        self.assertIn("responses: success=1 error=0", stdout)
        self.assertIn("unanswered=0", stdout)

    def test_role_conflict_response_is_counted(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(3)
            command = [
                str(PROGRAM), "--mode", "ice-binding",
                "--src-ip", "127.0.0.1", "--src-port", "0",
                "--dst-ip", "127.0.0.1", "--dst-port", str(receiver.getsockname()[1]),
                "--sender-ufrag", "EDGE1234", "--target-ufrag", "SFU5678",
                "--target-password", PASSWORD.decode("ascii"),
                "--role", "controlling", "--count", "1", "--duration", "0",
                "--response-wait", "1", "--quiet",
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            try:
                request, address = receiver.recvfrom(2048)
                receiver.sendto(binding_response(request, error_code=487), address)
                stdout, stderr = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.assertEqual(process.returncode, 0, stderr)
        self.assertIn("responses: success=0 error=1 (401=0 487=1", stdout)

    def test_original_udp_mode_still_sends_payload(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(3)
            run = subprocess.run([
                str(PROGRAM), "--src-ip", "127.0.0.1", "--src-port", "0",
                "--dst-ip", "127.0.0.1", "--dst-port", str(receiver.getsockname()[1]),
                "--size", "8", "--fill", "0x5a", "--count", "1",
                "--duration", "0", "--quiet",
            ], capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(receiver.recvfrom(1024)[0], b"Z" * 8)

    def test_rejects_udp_payload_options_in_ice_mode(self):
        run = subprocess.run([
            str(PROGRAM), "--mode", "ice-binding",
            "--src-ip", "127.0.0.1", "--src-port", "0",
            "--dst-ip", "127.0.0.1", "--dst-port", "9",
            "--sender-ufrag", "EDGE1234", "--target-ufrag", "SFU5678",
            "--target-password", PASSWORD.decode("ascii"),
            "--role", "controlled", "--size", "1200",
        ], capture_output=True, text=True, timeout=5, check=False)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("--size", run.stderr)

    def test_hmac_with_password_longer_than_sha1_block(self):
        long_password = b"p" * 80
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(3)
            run = subprocess.run([
                str(PROGRAM), "--mode", "ice-binding",
                "--src-ip", "127.0.0.1", "--src-port", "0",
                "--dst-ip", "127.0.0.1", "--dst-port", str(receiver.getsockname()[1]),
                "--sender-ufrag", "EDGE1234", "--target-ufrag", "SFU5678",
                "--target-password", long_password.decode("ascii"),
                "--role", "controlled", "--count", "1", "--duration", "0",
                "--no-response-stats", "--quiet",
            ], capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            packet = receiver.recvfrom(2048)[0]
        integrity = next(a for a in attributes(packet) if a[0] == 0x0008)
        mi_offset = integrity[2]
        hmac_input = bytearray(packet[:mi_offset])
        struct.pack_into("!H", hmac_input, 2, mi_offset + 24 - 20)
        self.assertEqual(integrity[1], hmac.new(long_password, hmac_input,
                                                 hashlib.sha1).digest())


if __name__ == "__main__":
    unittest.main()
