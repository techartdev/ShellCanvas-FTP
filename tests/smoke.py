"""Optional live protocol smoke test: pip install pyftpdlib, then python tests/smoke.py EXE."""
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import shutil
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer


def send(process, identity, method, params):
    payload = json.dumps({"v": 1, "type": "request", "id": identity,
                          "method": method, "params": params}).encode()
    process.stdin.write(struct.pack(">I", len(payload)) + payload)
    process.stdin.flush()
    length = struct.unpack(">I", process.stdout.read(4))[0]
    response = json.loads(process.stdout.read(length))
    assert response["id"] == identity, response
    assert response["type"] == "result", response
    return response["value"]


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "hello.txt").write_bytes(b"Hello from FTP\n")
        (root / "subdir").mkdir()
        authorizer = DummyAuthorizer()
        authorizer.add_user("tester", "test-secret", directory, perm="elr")
        handler = FTPHandler
        handler.authorizer = authorizer
        server = FTPServer(("127.0.0.1", 0), handler)
        port = server.socket.getsockname()[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        process = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            config = {"host": "127.0.0.1", "port": port, "username": "tester",
                      "password": "test-secret", "tls": False}
            catalog = send(process, 1, "system.adapter.initialize",
                           {"protocol": 1, "configuration": config})
            assert catalog["services"][0]["id"] == "files"
            page = send(process, 2, "files.list", {"path": None, "cursor": None, "limit": 1})
            assert page["next"]
            second = send(process, 3, "files.list", {"path": None, "cursor": page["next"], "limit": 1})
            entries = page["directory"]["entries"] + second["directory"]["entries"]
            item = next(entry for entry in entries if entry["name"] == "hello.txt")
            preview = send(process, 4, "files.preview", {"path": item["path"]})
            assert preview == "Hello from FTP\n", repr(preview)
            assert send(process, 5, "files.readText", {"path": item["path"]})["writable"] is False
            opened = send(process, 6, "files.download.open", {
                "id": "sample-1", "path": item["path"], "revision": item["revision"]})
            assert opened["size"] == len(b"Hello from FTP\n")
            chunk = send(process, 7, "files.download.read", {
                "id": "sample-1", "offset": 0, "maxBytes": 32768})
            assert bytes(chunk) == b"Hello from FTP\n"
            assert send(process, 8, "files.download.finish", {"id": "sample-1"}) is None
            assert send(process, 9, "files.transfer.abort", {"id": "unknown"}) is None
            print("PASS: FTP catalog, paged browse, preview, text read, download, abort")
        finally:
            process.terminate()
            process.wait(timeout=5)
            server.close_all()

        openssl = shutil.which("openssl")
        if openssl:
            cert = root / "server.pem"
            key = root / "server.key"
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tls_handler = type("TestTlsHandler", (TLS_FTPHandler,), {})
            tls_handler.authorizer = authorizer
            tls_handler.certfile = str(cert)
            tls_handler.keyfile = str(key)
            tls_handler.tls_control_required = True
            tls_handler.tls_data_required = True
            secure_server = FTPServer(("127.0.0.1", 0), tls_handler)
            secure_port = secure_server.socket.getsockname()[1]
            secure_thread = threading.Thread(target=secure_server.serve_forever, daemon=True)
            secure_thread.start()
            secure_process = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                secure_config = {"host": "localhost", "port": secure_port,
                                 "username": "tester", "password": "test-secret",
                                 "tls": True, "trustCertificate": True}
                send(secure_process, 1, "system.adapter.initialize",
                     {"protocol": 1, "configuration": secure_config})
                page = send(secure_process, 2, "files.list", {
                    "path": None, "cursor": None, "limit": 128})
                assert any(item["name"] == "hello.txt" for item in page["directory"]["entries"])
                print("PASS: explicit FTPS encrypted control and data")
            finally:
                secure_process.terminate()
                secure_process.wait(timeout=5)
                secure_server.close_all()


if __name__ == "__main__":
    main()
