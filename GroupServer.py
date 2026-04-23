import socket
from threading import Thread
from Communication import (
    UserToken, send_msg, recv_msg,
    server_handshake,                  # T3 / T5
    hash_password, verify_password,    # T1
    load_or_create_signing_key,        # T2 / T6
)

# T2 / T6: load (or generate) the Ed25519 signing key pair once at startup.
# The private key stays here; the public key is written to gs_public_key.pem
# for the File Server to use.
signing_key = load_or_create_signing_key()


class GroupServerThread(Thread):
    def __init__(self, conn, users, groups):
        Thread.__init__(self)
        self.conn   = conn
        self.users  = users    # {username: {"groups": [], "dk": bytes, "salt": bytes}}
        self.groups = groups   # {groupname: {"owner": username, "members": []}}

    def run(self):
        # T3 / T5: replace the raw socket with an encrypted SecureSession.
        # X25519 ECDHE derives a fresh AES-256-GCM session key for this connection.
        self.conn = server_handshake(self.conn)

        while True:
            try:
                req = recv_msg(self.conn)
                if not req:
                    break

                func = req.get("func")
                p    = req.get("params", {})
                res  = None

                if func == "getToken":
                    user_name = p.get("userName")
                    password  = p.get("password")     # T1: password required
                    user_rec  = self.users.get(user_name)

                    # T1: verify password with PBKDF2-HMAC-SHA256 before issuing any token
                    if user_rec and verify_password(password, user_rec["salt"], user_rec["dk"]):
                        token = UserToken(user_name, user_rec["groups"])
                        token.sign(signing_key)        # T2: Ed25519 signature over token fields
                        res = token
                    else:
                        res = None  # authentication failed

                elif func == "createUser":
                    new_user = p.get("userName")
                    new_pass = p.get("password", "changeme")
                    token    = p.get("userToken")
                    if token and "ADMIN" in token.groups:
                        if new_user not in self.users:
                            dk, salt = hash_password(new_pass)  # T1: hash before storing
                            self.users[new_user] = {"groups": [], "dk": dk, "salt": salt}
                            res = True
                        else:
                            res = False
                    else:
                        res = False

                elif func == "createGroup":
                    group_name = p.get("groupName")
                    token      = p.get("userToken")
                    if token and group_name not in self.groups:
                        self.groups[group_name] = {"owner": token.userName, "members": [token.userName]}
                        self.users[token.userName]["groups"].append(group_name)
                        res = True
                    else:
                        res = False

                elif func == "addUserToGroup":
                    user_to_add = p.get("userName")
                    group_name  = p.get("groupName")
                    token       = p.get("userToken")
                    if token and group_name in self.groups and self.groups[group_name]["owner"] == token.userName:
                        if user_to_add in self.users and user_to_add not in self.groups[group_name]["members"]:
                            self.groups[group_name]["members"].append(user_to_add)
                            self.users[user_to_add]["groups"].append(group_name)
                            res = True
                        else:
                            res = False
                    else:
                        res = False

                elif func == "listMembers":
                    group_name = p.get("groupName")
                    token      = p.get("userToken")
                    if token and group_name in self.groups and self.groups[group_name]["owner"] == token.userName:
                        res = self.groups[group_name]["members"]
                    else:
                        res = None

                send_msg(self.conn, res)
            except Exception:
                break

        self.conn.close()


# ── Bootstrap ─────────────────────────────────────────────────────────────────
# T1: admin password is hashed with PBKDF2 at startup — never stored in plaintext
_admin_dk, _admin_salt = hash_password("adminpass")

users  = {"admin": {"groups": ["ADMIN"], "dk": _admin_dk, "salt": _admin_salt}}
groups = {"ADMIN": {"owner": "admin", "members": ["admin"]}}

g_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
g_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
g_server.bind(("172.0.0.4", 2004))
g_server.listen(5)
print("Group Server Started on port 2004...")
print("Default credentials: username=admin  password=adminpass")

while True:
    conn, _ = g_server.accept()
    GroupServerThread(conn, users, groups).start()
