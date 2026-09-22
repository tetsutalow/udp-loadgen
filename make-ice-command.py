#!/usr/bin/env python3
"""Build an ICE Binding Request command from two WebRTC SDP JSON copies."""

import argparse
import codecs
from contextlib import contextmanager
import ipaddress
import json
import os
import re
import shlex
import sys
import termios


UFRAG = re.compile(r"^a=ice-ufrag:([^\r\n]+)\s*$", re.MULTILINE)
PASSWORD = re.compile(r"^a=ice-pwd:([^\r\n]+)\s*$", re.MULTILINE)


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def port(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return number


def positive_int(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


@contextmanager
def private_input(fd):
    """Disable terminal echo and canonical line limits while pasting secrets."""
    if not os.isatty(fd):
        yield
        return
    original = termios.tcgetattr(fd)
    changed = termios.tcgetattr(fd)
    changed[3] &= ~(termios.ECHO | termios.ICANON)
    changed[6][termios.VMIN] = 1
    changed[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, changed)
    try:
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, original)


class JsonReader:
    def __init__(self, fd):
        self.fd = fd
        self.buffer = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")()

    def read(self, label):
        print(f"{label} の JSON を貼り付けてください（入力は非表示）:", file=sys.stderr)
        while True:
            # Some terminals wrap pasted text in bracketed-paste markers.
            self.buffer = self.buffer.lstrip()
            if self.buffer.startswith("\x1b[200~"):
                self.buffer = self.buffer[len("\x1b[200~"):]
                continue
            if self.buffer.startswith("\x1b[201~"):
                self.buffer = self.buffer[len("\x1b[201~"):]
                continue
            try:
                value, end = json.JSONDecoder().raw_decode(self.buffer)
            except json.JSONDecodeError:
                pass
            else:
                self.buffer = self.buffer[end:]
                if not isinstance(value, (dict, list, str)):
                    raise ValueError(f"{label}: JSON オブジェクトまたは文字列が必要です")
                return value
            chunk = os.read(self.fd, 4096)
            if not chunk:
                raise ValueError(f"{label}: JSON が完成する前に標準入力が終わりました")
            self.buffer += self.decoder.decode(chunk)
            if len(self.buffer) > 32 * 1024 * 1024:
                raise ValueError(f"{label}: JSON が 32 MiB を超えました")


def strings_in(value):
    """Yield leaf strings, including JSON serialized inside an event value."""
    if isinstance(value, str):
        yield value
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                nested = json.loads(stripped)
            except json.JSONDecodeError:
                return
            yield from strings_in(nested)
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings_in(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings_in(child)


def credentials(value, label):
    pairs = set()
    for string in strings_in(value):
        # A JSON event may contain "type: offer, sdp: ..." before the SDP.
        ufrags = UFRAG.findall(string)
        passwords = PASSWORD.findall(string)
        if not ufrags and not passwords:
            continue
        if not ufrags or not passwords:
            raise ValueError(f"{label}: ice-ufrag と ice-pwd の両方が必要です")
        if len(ufrags) != len(passwords):
            raise ValueError(f"{label}: ice-ufrag と ice-pwd の数が一致しません")
        pairs.update(zip(ufrags, passwords))
    if not pairs:
        raise ValueError(f"{label}: SDP の a=ice-ufrag / a=ice-pwd が見つかりません")
    if len(pairs) != 1:
        raise ValueError(
            f"{label}: 異なる ICE 認証情報が複数あります。"
            "同じ接続・世代の SDP を 1 件ずつコピーしてください"
        )
    return pairs.pop()


def main():
    parser = argparse.ArgumentParser(
        description="setLocalDescription と setRemoteDescription の JSON から ICE コマンドを作ります"
    )
    parser.add_argument("--src-ip", required=True, type=ipv4)
    parser.add_argument("--src-port", required=True, type=port)
    parser.add_argument("--dst-ip", required=True, type=ipv4)
    parser.add_argument("--dst-port", required=True, type=port)
    parser.add_argument("--role", required=True, choices=("controlling", "controlled"))
    parser.add_argument("--pps", type=positive_int, default=1)
    parser.add_argument("--duration", type=positive_int, default=10)
    parser.add_argument("--spoof-source", action="store_true")
    parser.add_argument("--interface", help="--spoof-source 使用時の送信インターフェース")
    args = parser.parse_args()
    if args.spoof_source and not args.interface:
        parser.error("--spoof-source には --interface が必要です")
    if args.interface and not args.spoof_source:
        parser.error("--interface は --spoof-source と併用してください")

    try:
        reader = JsonReader(sys.stdin.fileno())
        with private_input(sys.stdin.fileno()):
            local_ufrag, _ = credentials(reader.read("setLocalDescription"), "local")
            remote_ufrag, remote_password = credentials(
                reader.read("setRemoteDescription"), "remote"
            )
    except ValueError as exc:
        parser.exit(2, f"エラー: {exc}\n")

    command = ["./udp-loadgen", "--mode", "ice-binding"]
    if args.spoof_source:
        command += ["--spoof-source", "--interface", args.interface]
    command += [
        "--src-ip", args.src_ip, "--src-port", str(args.src_port),
        "--dst-ip", args.dst_ip, "--dst-port", str(args.dst_port),
        "--sender-ufrag", local_ufrag,
        "--target-ufrag", remote_ufrag,
        "--target-password", remote_password,
        "--role", args.role,
        "--pps", str(args.pps), "--duration", str(args.duration),
    ]
    print("# この出力には対象の ICE password が含まれます。共有・保存に注意してください。")
    print(shlex.join(command))


if __name__ == "__main__":
    main()
