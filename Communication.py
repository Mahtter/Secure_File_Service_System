import struct
import os
import time
import pickle

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC     # T1
from cryptography.hazmat.primitives.ciphers.aead import AESGCM        # T3
from cryptography.exceptions import InvalidKey, InvalidSignature

TOKEN_LIFETIME = 3600  # T4: tokens expire after 1 hour This will support Key rotation and defend against compromised keys by ensuring session tokens expire.


# ── T2: Signed User Token ─────────────────────────────────────────────────────
class UserToken:
    def __init__(self, userName, groups, expiration=None):
        self.userName   = userName
        self.groups     = sorted(groups)                              # canonical order for signing
        self.expiration = expiration or (time.time() + TOKEN_LIFETIME)  # T4: expiry embedded in token
        self.signature  = None                                        # bytes; set by sign()

    def _signable(self):
        # Deterministic bytes covering every field that must be tamper-evident.
        # The signature field itself is excluded so the bytes are stable before
        # and after signing.
        return f"{self.userName}|{','.join(self.groups)}|{round(self.expiration, 3)}".encode()

    def sign(self, private_key):
        # T2: attach an Ed25519 signature — only the Group Server calls this
        self.signature = private_key.sign(self._signable())

    def verify(self, public_key):
        # T2: verify signature with the GS public key
        # T4: also reject if the token has expired
        if self.signature is None:
            return False
        if time.time() > self.expiration:     # T4: expiration check
            return False
        try:
            public_key.verify(self.signature, self._signable())
            return True
        except InvalidSignature:
            return False


# ── T3 / T4 / T5: Encrypted Session ──────────────────────────────────────────
class SecureSession:
    """
    Wraps a raw TCP socket with:
      T3 — AES-256-GCM authenticated encryption (random 96-bit GCM IV per message)
      T4 — Random 128-bit application nonce per message; seen_nonces tracks them
      T5 — Session key comes from X25519 ECDHE + HKDF (set up by handshake helpers)
    """

    def __init__(self, sock, key):
        self.sock        = sock
        self.aesgcm      = AESGCM(key)   # T3: AES-256-GCM instance
        self.seen_nonces = set()          # T4: tracks every nonce received this session

    def close(self):
        self.sock.close()

    def send(self, msg):
        plaintext = pickle.dumps(msg)

        # T4: 128-bit random nonce — unique per message, never reused
        app_nonce = os.urandom(16)

        # T3: 96-bit random GCM IV — standard for AES-GCM (NIST SP 800-38D)
        gcm_iv = os.urandom(12)

        # The app_nonce is passed as AAD so GCM authenticates it alongside the
        # ciphertext.  An attacker who replays the message will be caught by the
        # seen_nonces check on the receiver; one who alters the nonce will fail
        # the GCM tag verification.
        ct = self.aesgcm.encrypt(gcm_iv, plaintext, app_nonce)

        # Wire layout: [16-byte nonce][12-byte GCM IV][ciphertext + 16-byte GCM tag]
        _raw_send(self.sock, app_nonce + gcm_iv + ct)

    def recv(self):
        data = _raw_recv(self.sock)
        if data is None:
            return None

        app_nonce = bytes(data[:16])   # must be bytes for set membership
        gcm_iv    = data[16:28]
        ct        = data[28:]

        # T4: reject any message whose nonce we have already processed
        if app_nonce in self.seen_nonces:
            raise ValueError("Replay attack detected: nonce already seen.")
        self.seen_nonces.add(app_nonce)

        # T3: decrypt and verify GCM authentication tag in one step;
        # raises InvalidTag automatically if ciphertext or AAD was tampered with
        plain = self.aesgcm.decrypt(gcm_iv, ct, app_nonce)
        return pickle.loads(plain)


# ── send_msg / recv_msg
def send_msg(conn, msg):
    # Dispatch on type: SecureSession → encrypted; raw socket → plain pickle
    if isinstance(conn, SecureSession):
        conn.send(msg)
    else:
        data = pickle.dumps(msg)
        conn.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(conn):
    if isinstance(conn, SecureSession):
        return conn.recv()
    else:
        raw_len = recvall(conn, 4)
        if not raw_len:
            return None
        msglen = struct.unpack(">I", raw_len)[0]
        data   = recvall(conn, msglen)
        return pickle.loads(data)

def recvall(sock, n):
    # Helper to handle TCP fragmentation 
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


# ── Internal raw framing (used only during the ECDHE handshake phase) ─────────
def _raw_send(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

def _raw_recv(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    return recvall(sock, struct.unpack(">I", raw_len)[0])


# ── T5: ECDHE Handshake helpers (X25519 + HKDF) ──────────────────────────────
def _derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    """
    HKDF-SHA256 (RFC 5869) turns the raw X25519 shared secret into a 256-bit
    AES session key.

    salt : 32 random bytes sent by the server — ensures unique key even if
           the same X25519 key pair were ever mistakenly reused (T5).
    info : protocol label — binds the derived key to this application so a key
           derived in a different context cannot be substituted.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"dfs-phase3-v1",
    ).derive(shared_secret)

def client_handshake(sock) -> SecureSession:
    """
    T5: ephemeral X25519 — client side.
    1. Generate a fresh key pair (never reused).
    2. Send the public key.
    3. Receive the server's public key + HKDF salt.
    4. Derive the shared AES-256 session key.
    """
    priv = x25519.X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _raw_send(sock, pub)

    reply  = _raw_recv(sock)          # server_pub (32 bytes) + salt (32 bytes)
    s_pub  = reply[:32]
    salt   = reply[32:]
    shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(s_pub))
    return SecureSession(sock, _derive_key(shared, salt))

def server_handshake(sock) -> SecureSession:
    """
    T5: ephemeral X25519 — server side.
    1. Receive the client's public key.
    2. Generate a fresh key pair + random HKDF salt.
    3. Send the server public key + salt.
    4. Derive the shared AES-256 session key.
    """
    c_pub_bytes = _raw_recv(sock)
    priv = x25519.X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    salt = os.urandom(32)
    _raw_send(sock, pub + salt)       # send both in one frame

    shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(c_pub_bytes))
    return SecureSession(sock, _derive_key(shared, salt))


# ── T1: Password hashing — using cryptography library PBKDF2HMAC ─────────────
def hash_password(password: str, salt: bytes = None):
    """
    Derive a 256-bit key from password + salt using PBKDF2-HMAC-SHA256.
    200,000 iterations meets NIST SP 800-63B for SHA-256.
    A fresh random 128-bit salt is generated per user so identical passwords
    produce distinct hashes (defeats rainbow tables).
    Returns (derived_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)       # T1: 128-bit random salt per user
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode()), salt

def verify_password(password: str, salt: bytes, expected_dk: bytes) -> bool:
    """
    kdf.verify() does a constant-time comparison internally (cryptography
    library), preventing timing side-channel attacks.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    try:
        kdf.verify(password.encode(), expected_dk)  # raises InvalidKey on mismatch
        return True
    except InvalidKey:
        return False


# ── T6: Ed25519 signing key management ───────────────────────────────────────
GS_PRIV = "gs_private_key.pem"
GS_PUB  = "gs_public_key.pem"

def load_or_create_signing_key():
    """
    Load the Group Server's Ed25519 signing private key from disk, or generate
    a new one on first run.  The private key file is created with mode 0600
    (owner read/write only) to limit exposure (T6).

    The matching public key is always re-exported to GS_PUB so the File Server
    can load it at startup to verify token signatures (T2 / T6).
    """
    if os.path.exists(GS_PRIV):
        with open(GS_PRIV, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # Write with restricted permissions — owner only (T6)
        fd = os.open(GS_PRIV, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)

    # Re-export public key every run so FS always has the current one (T2/T6)
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(GS_PUB, "wb") as f:
        f.write(pub)
    return key

def load_gs_public_key():
    """File Server calls this at startup to load the GS public key (T2)."""
    if not os.path.exists(GS_PUB):
        raise FileNotFoundError(f"'{GS_PUB}' not found — start GroupServer.py first.")
    with open(GS_PUB, "rb") as f:
        return serialization.load_pem_public_key(f.read())
