"""One loopback connection per test; all credentials are generated/test-only.

Requires Python with paramiko. The server deliberately preserves the accepted
first factor only in this connection and sends SSH partial-success responses.
"""
import io
import json
import logging
import socket
import sys
import threading
import time
import stat
import base64
import hashlib
import hmac
import struct
import os
import tempfile

import paramiko
from cryptography.hazmat.primitives import serialization

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
mode = sys.argv[1]
host_key = paramiko.RSAKey.generate(2048)
client_key = paramiko.RSAKey.generate(2048)
key_text = io.StringIO()
if mode == "key_encrypted":
    key_text.write(client_key.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.BestAvailableEncryption(b"key-passphrase")).decode())
else:
    client_key.write_private_key(key_text)


class Server(paramiko.ServerInterface):
    first = False
    round = 0

    def check_channel_request(self, kind, chanid):
        if mode == "shared_no_sftp" and chanid > 0:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, *args):
        return True

    def check_channel_shell_request(self, channel):
        def echo():
            try:
                while True:
                    data = channel.recv(4096)
                    if not data: break
                    channel.sendall(data)
            except (EOFError, OSError):
                pass
        threading.Thread(target=echo, daemon=True).start()
        return True

    def check_channel_subsystem_request(self, channel, name):
        if mode == "shared_no_sftp":
            return False
        return super().check_channel_subsystem_request(channel, name)

    def check_channel_exec_request(self, channel, command):
        text = command.decode()
        if text == "fixture-sftp" or "for p in /usr/lib/openssh/sftp-server" in text:
            if mode == "shared_sudo_password":
                def start_after_password():
                    received = b""
                    while not received.endswith(b"\n"):
                        received += channel.recv(1)
                    if received != b"account-password\n":
                        channel.close()
                        return
                    paramiko.SFTPServer(channel, "sftp", self, MemoryFiles).start()
                threading.Thread(target=start_after_password, daemon=True).start()
            else:
                paramiko.SFTPServer(channel, "sftp", self, MemoryFiles).start()
            return True

        def reply():
            time.sleep(0.01)
            try:
                status = 0
                if text == "sudo -n true" and mode == "shared_sudo_password":
                    status = 1
                elif text.startswith("sudo -S -k"):
                    received = b""
                    while not received.endswith(b"\n"):
                        received += channel.recv(1)
                    status = 0 if received == b"account-password\n" else 1
                else:
                    channel.sendall(b"shared-exec-ok\n")
                channel.send_exit_status(status)
                channel.close()
            except (EOFError, OSError, paramiko.SSHException):
                pass
        threading.Thread(target=reply, daemon=True).start()
        return True

    def get_allowed_auths(self, username):
        return "keyboard-interactive" if self.first else "password,publickey,keyboard-interactive"

    def check_auth_password(self, username, password):
        if username != "fixture" or password != "account-password" or mode == "fallback":
            return paramiko.AUTH_FAILED
        self.first = True
        return paramiko.AUTH_SUCCESSFUL if mode == "password_only" else paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        if username != "fixture" or key != client_key or mode == "reject_key":
            if mode == "agent_mfa":
                self.first = False  # Offering more keys loses the accepted factor.
            return paramiko.AUTH_FAILED
        self.first = True
        return paramiko.AUTH_SUCCESSFUL if mode == "key_only" else paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_interactive(self, username, submethods):
        if mode in ("interactive", "fallback"):
            return paramiko.InteractiveQuery("", "", ("Password:", False))
        if not self.first:
            return paramiko.AUTH_FAILED
        if mode == "disconnect_start":
            raise EOFError("fixture closes before answering auth request")
        if mode == "disconnect_prompt":
            def close():
                time.sleep(0.25)
                transport.close()
            threading.Thread(target=close, daemon=True).start()
        return self.challenge()

    def challenge(self):
        if mode == "auto_delete_pending":
            return paramiko.InteractiveQuery("", "", ("Verification code:", False), ("Choice:", True))
        if mode == "auto_context_password":
            return paramiko.InteractiveQuery("OTP verification", "", ("Password:", False))
        if mode == "auto_menu":
            return paramiko.InteractiveQuery("", "", ("Choose OTP or password option:", False))
        if mode == "auto_mixed":
            return paramiko.InteractiveQuery("OTP verification", "", ("Password:", False), ("Verification code:", False))
        if mode.startswith("auto_"):
            return paramiko.InteractiveQuery("", "", ("Verification code:", False))
        if mode == "empty" and self.round == 0:
            return paramiko.InteractiveQuery("", "")
        if mode == "password_banner":
            return paramiko.InteractiveQuery("Password authentication", "", ("Response:", False))
        if mode == "new_password":
            return paramiko.InteractiveQuery("", "", ("New password:", False))
        if mode in ("echo", "context"):
            return paramiko.InteractiveQuery("MFA" if mode == "context" else "", "", ("Password:", mode == "echo"))
        if mode == "multi" and self.round == 0:
            return paramiko.InteractiveQuery("MFA", "Approve this login", ("Verification code:", False), ("Choice:", True))
        return paramiko.InteractiveQuery("", "", ("Response:", False))

    def check_auth_interactive_response(self, responses):
        if mode == "auto_delete_pending":
            return paramiko.AUTH_SUCCESSFUL if responses == ["654321", "approve"] else paramiko.AUTH_FAILED
        def valid_totp(value):
            for counter in range(int(time.time())//30-1, int(time.time())//30+2):
                digest=hmac.new(base64.b32decode("JBSWY3DPEHPK3PXP"),struct.pack(">Q",counter),hashlib.sha1).digest()
                offset=digest[-1]&15
                if value == str((int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%1000000).zfill(6):
                    return True
            return False
        if mode in ("auto_totp","auto_repeat","auto_mixed"):
            if mode == "auto_repeat" and self.round == 1:
                return paramiko.AUTH_SUCCESSFUL if responses == ["654321"] else paramiko.AUTH_FAILED
            good=(len(responses)==2 and responses[0]=="654321" and valid_totp(responses[1])) if mode=="auto_mixed" else (len(responses)==1 and valid_totp(responses[0]))
            if not good: return paramiko.AUTH_FAILED
            self.round+=1
            return self.challenge() if mode=="auto_repeat" else paramiko.AUTH_SUCCESSFUL
        if mode in ("interactive", "fallback"):
            return paramiko.AUTH_SUCCESSFUL if responses == ["account-password"] else paramiko.AUTH_FAILED
        expected = [] if mode == "empty" and self.round == 0 else ["654321"]
        if mode == "multi" and self.round == 0:
            expected = ["654321", "approve"]
        if responses != expected:
            return paramiko.AUTH_FAILED
        self.round += 1
        rounds = 2 if mode in ("multi", "empty") else 16 if mode == "sixteen" else 30 if mode == "endless" else 1
        return paramiko.AUTH_SUCCESSFUL if self.round >= rounds else self.challenge()


class MemoryFiles(paramiko.SFTPServerInterface):
    def list_folder(self, path):
        item = self.stat(path)
        item.filename = "fixture.txt"
        return [item]

    def stat(self, path):
        item = paramiko.SFTPAttributes()
        item.st_mode = stat.S_IFREG | 0o600
        item.st_size = len(b"shared-channel-content\n")
        item.st_uid = item.st_gid = 1000
        return item

    lstat = stat

    def open(self, path, flags, attr):
        handle = paramiko.SFTPHandle(flags)
        handle.readfile = io.BytesIO(b"shared-channel-content\n")
        return handle


agent_path = None
if mode == "agent_mfa":
    # A disposable local agent with two keys; never use the user's SSH agent.
    agent_path = os.path.join(tempfile.mkdtemp(prefix="ms-agent-"), "agent.sock")
    agent_listener = socket.socket(socket.AF_UNIX)
    agent_listener.bind(agent_path)
    agent_listener.listen(1)
    other_key = paramiko.RSAKey.generate(2048)

    def serve_agent():
        def exact(stream, count):
            result = b""
            while len(result) < count:
                chunk = stream.recv(count - len(result))
                if not chunk:
                    raise EOFError()
                result += chunk
            return result

        stream, _ = agent_listener.accept()
        try:
            while True:
                size = struct.unpack(">I", exact(stream, 4))[0]
                message = paramiko.Message(exact(stream, size))
                kind = ord(message.get_byte())
                response = paramiko.Message()
                if kind == 11:
                    response.add_byte(bytes([12]))
                    response.add_int(2)
                    for key in (client_key, other_key):
                        response.add_string(key.asbytes())
                        response.add_string("fixture")
                elif kind == 13:
                    blob, data, flags = message.get_binary(), message.get_binary(), message.get_int()
                    key = client_key if blob == client_key.asbytes() else other_key
                    algorithm = "rsa-sha2-512" if flags == 4 else "rsa-sha2-256" if flags == 2 else "ssh-rsa"
                    response.add_byte(bytes([14]))
                    response.add_string(key.sign_ssh_data(data, algorithm).asbytes())
                else:
                    response.add_byte(bytes([5]))
                payload = response.asbytes()
                stream.sendall(struct.pack(">I", len(payload)) + payload)
        except (EOFError, OSError):
            pass
        finally:
            stream.close()
            agent_listener.close()
            os.unlink(agent_path)
            os.rmdir(os.path.dirname(agent_path))

    threading.Thread(target=serve_agent, daemon=True).start()

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
listener.settimeout(10)
print(json.dumps({"port": listener.getsockname()[1], "key": key_text.getvalue(), "agent_sock": agent_path}), flush=True)
conn, _ = listener.accept()
listener.close()  # No second connection can rescue a lost first factor.
transport = paramiko.Transport(conn)
transport.add_server_key(host_key)
transport.set_subsystem_handler("sftp", paramiko.SFTPServer, MemoryFiles)
try:
    transport.start_server(server=Server())
    deadline = time.monotonic() + 15
    while transport.is_active() and time.monotonic() < deadline:
        time.sleep(0.01)
except (EOFError, OSError, paramiko.SSHException):
    pass
finally:
    transport.close()
