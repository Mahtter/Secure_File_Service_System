import os
import socket
from threading import Thread
from Communication import send_msg, recv_msg, server_handshake, load_gs_public_key

SERVER_FILES_DIR = "server_files"

# T2: load the Group Server's Ed25519 public key once at startup.
# Every incoming token will be verified against this key before any request
# is honoured.  The File Server never sees the GS private key (T6).
gs_public_key = load_gs_public_key()


class FileServerThread(Thread):
    def __init__(self, conn, file_metadata):
        Thread.__init__(self)
        self.conn          = conn
        self.file_metadata = file_metadata  # {filename: {"group": str, "path": str}}

    def run(self):
        # T3 / T5: replace the raw socket with an encrypted SecureSession.
        # Each connection gets its own ephemeral X25519 key pair and AES session key.
        self.conn = server_handshake(self.conn)

        while True:
            try:
                req = recv_msg(self.conn)
                if not req:
                    break

                func  = req.get("func")
                p     = req.get("params", {})
                token = req.get("token")
                res   = None

                if func == "disconnect":
                    send_msg(self.conn, True)
                    break

                # T2 / T4: verify the Ed25519 signature AND the expiration timestamp
                # on every single request — reject immediately if either check fails.
                if token is None or not token.verify(gs_public_key):
                    send_msg(self.conn, {"ok": False, "error": "Invalid or expired token."})
                    continue

                if func == "listFiles":
                    # return only files whose group appears in the caller's token
                    res = [
                        fname for fname, meta in self.file_metadata.items()
                        if meta["group"] in token.groups
                    ]

                elif func == "upload":
                    group_name = p.get("groupName")
                    dest_file  = p.get("destFile")
                    file_data  = p.get("fileData")

                    if group_name in token.groups and dest_file and file_data is not None:
                        os.makedirs(SERVER_FILES_DIR, exist_ok=True)
                        server_path = os.path.join(SERVER_FILES_DIR, dest_file)
                        with open(server_path, "wb") as outfile:
                            outfile.write(file_data)
                        self.file_metadata[dest_file] = {"group": group_name, "path": server_path}
                        res = True
                    else:
                        res = False

                elif func == "download":
                    source_file = p.get("sourceFile")
                    meta        = self.file_metadata.get(source_file)

                    if meta and meta["group"] in token.groups:
                        with open(meta["path"], "rb") as infile:
                            res = {"ok": True, "fileName": source_file, "fileData": infile.read()}
                    else:
                        res = {"ok": False, "fileData": None}

                else:
                    res = None  # unknown request

                send_msg(self.conn, res)
            except Exception:
                break

        self.conn.close()


# ── Bootstrap ─────────────────────────────────────────────────────────────────
os.makedirs(SERVER_FILES_DIR, exist_ok=True)
files = {}

f_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
f_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
f_server.bind(("0.0.0.0", 2005))
f_server.listen(5)
print("File Server Started on port 2005...")

while True:
    conn, _ = f_server.accept()
    FileServerThread(conn, files).start()
