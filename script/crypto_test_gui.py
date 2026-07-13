import hashlib
import os
import re
import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils, x25519


def parse_hex_array(text: str) -> bytes:
    s = text.strip()
    if not s:
        return b""

    prefixed = re.findall(r"0[xX]([0-9a-fA-F]{1,2})", s)
    if prefixed:
        return bytes(int(x, 16) for x in prefixed)

    cleaned = re.sub(r"[\s,\{\}\[\]\(\);:_-]", "", s)
    if not cleaned:
        return b""
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError("Invalid hex. Use: 01 02, 0102, or {0x01, 0x02}.")
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even.")
    return bytes.fromhex(cleaned)


def parse_data(text: str, mode: str) -> bytes:
    if mode == "string":
        return text.encode("utf-8")
    return parse_hex_array(text)


def to_hex(data: bytes) -> str:
    return data.hex()


def to_c_array(data: bytes, per_line: int = 12) -> str:
    if not data:
        return "{ }"
    parts = [f"0x{b:02X}" for b in data]
    lines = []
    for i in range(0, len(parts), per_line):
        lines.append("    " + ", ".join(parts[i : i + per_line]))
    return "{\n" + ",\n".join(lines) + "\n}"


def set_text(widget: tk.Text, value: str) -> None:
    widget.delete("1.0", tk.END)
    widget.insert("1.0", value)


def get_text(widget: tk.Text) -> str:
    return widget.get("1.0", tk.END).strip()


def copy_to_clipboard(root: tk.Tk, value: str) -> None:
    root.clipboard_clear()
    root.clipboard_append(value)
    root.update()


def p256_private_from_raw(private_bytes: bytes):
    if len(private_bytes) != 32:
        raise ValueError("P-256 private key must be 32 bytes.")
    value = int.from_bytes(private_bytes, "big")
    if value <= 0:
        raise ValueError("P-256 private key must be non-zero.")
    return ec.derive_private_key(value, ec.SECP256R1())


def p256_public_from_raw(public_bytes: bytes):
    if len(public_bytes) == 64:
        public_bytes = b"\x04" + public_bytes
    if len(public_bytes) != 65 or public_bytes[0] != 0x04:
        raise ValueError("P-256 public key must be 64-byte x||y or 65-byte uncompressed 0x04||x||y.")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_bytes)


def p256_public_bytes(private_key) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def der_to_raw_rs(signature_der: bytes) -> bytes:
    r, s = utils.decode_dss_signature(signature_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def signature_to_der(sig: bytes) -> bytes:
    if len(sig) == 64:
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        return utils.encode_dss_signature(r, s)
    return sig


def x25519_public_from_private(private_bytes: bytes) -> bytes:
    if len(private_bytes) != 32:
        raise ValueError("X25519 private key must be 32 bytes.")
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def aes128_key_from_text(text: str) -> bytes:
    key = parse_hex_array(text)
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes.")
    return key


def aes_gcm_nonce_from_text(text: str) -> bytes:
    nonce = parse_hex_array(text)
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce/IV nen dai 12 byte.")
    return nonce


def aes_gcm_aad_from_text(text: str) -> bytes | None:
    aad = parse_hex_array(text)
    return aad if aad else None


class LabeledText(ttk.Frame):
    def __init__(self, parent, label: str, height: int = 4):
        super().__init__(parent)
        ttk.Label(self, text=label).pack(anchor="w")
        self.text = tk.Text(self, height=height, wrap="word", undo=True)
        self.text.pack(fill="both", expand=True)

    def get(self) -> str:
        return get_text(self.text)

    def set(self, value: str) -> None:
        set_text(self.text, value)


class CryptoTestGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secureboot Crypto Test GUI")
        self.root.geometry("1080x760")

        style = ttk.Style()
        style.configure("TButton", padding=(8, 4))
        style.configure("Status.TLabel", foreground="#0A6B3A")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.sha_tab = ttk.Frame(notebook)
        self.aes_tab = ttk.Frame(notebook)
        self.ecdh_tab = ttk.Frame(notebook)
        self.ecdsa_tab = ttk.Frame(notebook)
        notebook.add(self.sha_tab, text="SHA-256")
        notebook.add(self.aes_tab, text="AES-128 GCM")
        notebook.add(self.ecdh_tab, text="ECDH X25519")
        notebook.add(self.ecdsa_tab, text="ECDSA P-256")

        self.build_sha_tab()
        self.build_aes_tab()
        self.build_ecdh_tab()
        self.build_ecdsa_tab()

    def data_mode_selector(self, parent):
        mode = tk.StringVar(value="string")
        row = ttk.Frame(parent)
        ttk.Radiobutton(row, text="String UTF-8", variable=mode, value="string").pack(side="left")
        ttk.Radiobutton(row, text="Hex/C array", variable=mode, value="hex").pack(side="left", padx=(12, 0))
        return mode, row

    def output_box(self, parent, label: str, height: int = 4):
        frame = ttk.Frame(parent)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text=label).grid(row=0, column=0, sticky="w")
        text = tk.Text(frame, height=height, wrap="word")
        text.grid(row=1, column=0, sticky="nsew")
        ttk.Button(frame, text="Copy", command=lambda: copy_to_clipboard(self.root, get_text(text))).grid(
            row=1, column=1, sticky="ns", padx=(6, 0)
        )
        return frame, text

    def build_sha_tab(self):
        self.sha_tab.columnconfigure(0, weight=1)
        self.sha_mode, mode_row = self.data_mode_selector(self.sha_tab)
        mode_row.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))

        self.sha_input = LabeledText(self.sha_tab, "Input", height=8)
        self.sha_input.grid(row=1, column=0, sticky="nsew", padx=8)
        self.sha_tab.rowconfigure(1, weight=1)

        ttk.Button(self.sha_tab, text="Compute SHA-256", command=self.compute_sha256).grid(
            row=2, column=0, sticky="w", padx=8, pady=8
        )

        frame_hex, self.sha_hex = self.output_box(self.sha_tab, "Digest hex", height=3)
        frame_hex.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 8))
        frame_c, self.sha_c = self.output_box(self.sha_tab, "Digest C hex array", height=5)
        frame_c.grid(row=4, column=0, sticky="ew", padx=8, pady=(0, 8))

    def compute_sha256(self):
        try:
            data = parse_data(self.sha_input.get(), self.sha_mode.get())
            digest = hashlib.sha256(data).digest()
            set_text(self.sha_hex, to_hex(digest))
            set_text(self.sha_c, to_c_array(digest))
        except Exception as exc:
            messagebox.showerror("SHA-256 error", str(exc))

    def build_aes_tab(self):
        self.aes_tab.columnconfigure(0, weight=1)
        self.aes_mode, mode_row = self.data_mode_selector(self.aes_tab)
        mode_row.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))

        self.aes_data = LabeledText(self.aes_tab, "Plaintext for encrypt / ciphertext or ciphertext||tag for decrypt", height=5)
        self.aes_data.grid(row=1, column=0, sticky="nsew", padx=8)
        self.aes_key = LabeledText(self.aes_tab, "AES-128 key 16 byte", height=3)
        self.aes_key.grid(row=2, column=0, sticky="ew", padx=8, pady=(8, 0))
        self.aes_nonce = LabeledText(self.aes_tab, "IV/Nonce 12 byte", height=3)
        self.aes_nonce.grid(row=3, column=0, sticky="ew", padx=8, pady=(8, 0))
        self.aes_aad = LabeledText(self.aes_tab, "AAD hex/C array tuy chon", height=3)
        self.aes_aad.grid(row=4, column=0, sticky="ew", padx=8, pady=(8, 0))
        self.aes_tag_input = LabeledText(self.aes_tab, "16-byte tag for decrypt when ciphertext does not include tag", height=3)
        self.aes_tag_input.grid(row=5, column=0, sticky="ew", padx=8, pady=(8, 0))
        self.aes_tab.rowconfigure(1, weight=1)

        controls = ttk.Frame(self.aes_tab)
        controls.grid(row=6, column=0, sticky="w", padx=8, pady=8)
        ttk.Button(controls, text="Auto gen key", command=self.generate_aes_key).pack(side="left")
        ttk.Button(controls, text="Auto gen IV", command=self.generate_aes_nonce).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Encrypt", command=self.encrypt_aes_gcm).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Decrypt", command=self.decrypt_aes_gcm).pack(side="left", padx=(8, 0))

        frame_ct, self.aes_ciphertext = self.output_box(self.aes_tab, "Ciphertext", height=4)
        frame_ct.grid(row=7, column=0, sticky="ew", padx=8, pady=(0, 8))
        frame_tag, self.aes_tag = self.output_box(self.aes_tab, "Tag", height=3)
        frame_tag.grid(row=8, column=0, sticky="ew", padx=8, pady=(0, 8))
        frame_combined, self.aes_combined = self.output_box(self.aes_tab, "Ciphertext || tag", height=4)
        frame_combined.grid(row=9, column=0, sticky="ew", padx=8, pady=(0, 8))
        frame_plain, self.aes_plaintext = self.output_box(self.aes_tab, "Plaintext decrypt", height=4)
        frame_plain.grid(row=10, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.aes_status = ttk.Label(self.aes_tab, text="", style="Status.TLabel")
        self.aes_status.grid(row=11, column=0, sticky="w", padx=8, pady=(0, 8))

    def generate_aes_key(self):
        self.aes_key.set(to_c_array(os.urandom(16)))

    def generate_aes_nonce(self):
        self.aes_nonce.set(to_c_array(os.urandom(12)))

    def encrypt_aes_gcm(self):
        try:
            data = parse_data(self.aes_data.get(), self.aes_mode.get())
            key = aes128_key_from_text(self.aes_key.get())
            if not self.aes_nonce.get():
                self.generate_aes_nonce()
            nonce = aes_gcm_nonce_from_text(self.aes_nonce.get())
            aad = aes_gcm_aad_from_text(self.aes_aad.get())

            encrypted = AESGCM(key).encrypt(nonce, data, aad)
            ciphertext = encrypted[:-16]
            tag = encrypted[-16:]
            set_text(self.aes_ciphertext, to_c_array(ciphertext))
            set_text(self.aes_tag, to_c_array(tag))
            set_text(self.aes_combined, to_c_array(encrypted))
            set_text(self.aes_plaintext, "")
            self.aes_tag_input.set("")
            self.aes_status.configure(text="Encrypt OK")
        except Exception as exc:
            messagebox.showerror("AES-128 GCM encrypt error", str(exc))

    def decrypt_aes_gcm(self):
        try:
            ciphertext = parse_hex_array(self.aes_data.get())
            tag_text = self.aes_tag_input.get()
            tag = parse_hex_array(tag_text) if tag_text else b""
            if tag:
                if len(tag) != 16:
                    raise ValueError("AES-GCM tag must be 16 bytes.")
                encrypted = ciphertext + tag
            else:
                if len(ciphertext) < 16:
                    raise ValueError("Ciphertext||tag must contain at least a 16-byte tag.")
                encrypted = ciphertext
                ciphertext = encrypted[:-16]
                tag = encrypted[-16:]

            key = aes128_key_from_text(self.aes_key.get())
            nonce = aes_gcm_nonce_from_text(self.aes_nonce.get())
            aad = aes_gcm_aad_from_text(self.aes_aad.get())

            plaintext = AESGCM(key).decrypt(nonce, encrypted, aad)
            set_text(self.aes_ciphertext, to_c_array(ciphertext))
            set_text(self.aes_tag, to_c_array(tag))
            set_text(self.aes_combined, to_c_array(encrypted))
            set_text(self.aes_plaintext, to_c_array(plaintext))
            self.aes_status.configure(text="Decrypt OK")
        except Exception as exc:
            messagebox.showerror("AES-128 GCM decrypt error", str(exc))

    def key_row(self, parent, row: int, title: str):
        group = ttk.LabelFrame(parent, text=title)
        group.grid(row=row, column=0, sticky="nsew", padx=8, pady=8)
        group.columnconfigure(0, weight=1)
        private = LabeledText(group, "Private key 32 byte", height=3)
        public = LabeledText(group, "Public key 32 byte", height=3)
        private.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        public.grid(row=1, column=0, sticky="ew", padx=8, pady=(4, 8))
        return group, private, public

    def build_ecdh_tab(self):
        self.ecdh_tab.columnconfigure(0, weight=1)
        self.ecdh_tab.rowconfigure(0, weight=1)
        self.ecdh_tab.rowconfigure(1, weight=1)

        alice_group, self.alice_priv, self.alice_pub = self.key_row(self.ecdh_tab, 0, "Alice")
        bob_group, self.bob_priv, self.bob_pub = self.key_row(self.ecdh_tab, 1, "Bob")
        self.alice_priv.text.bind(
            "<FocusOut>",
            lambda _event: self.auto_derive_x25519_public(self.alice_priv, self.alice_pub),
        )
        self.bob_priv.text.bind(
            "<FocusOut>",
            lambda _event: self.auto_derive_x25519_public(self.bob_priv, self.bob_pub),
        )

        ttk.Button(alice_group, text="Auto gen Alice", command=lambda: self.generate_x25519(self.alice_priv, self.alice_pub)).grid(
            row=2, column=0, sticky="w", padx=8, pady=(0, 8)
        )
        ttk.Button(
            alice_group,
            text="Derive public from private",
            command=lambda: self.derive_x25519_public(self.alice_priv, self.alice_pub),
        ).grid(
            row=2, column=0, sticky="w", padx=(120, 8), pady=(0, 8)
        )
        ttk.Button(bob_group, text="Auto gen Bob", command=lambda: self.generate_x25519(self.bob_priv, self.bob_pub)).grid(
            row=2, column=0, sticky="w", padx=8, pady=(0, 8)
        )
        ttk.Button(
            bob_group,
            text="Derive public from private",
            command=lambda: self.derive_x25519_public(self.bob_priv, self.bob_pub),
        ).grid(
            row=2, column=0, sticky="w", padx=(120, 8), pady=(0, 8)
        )

        controls = ttk.Frame(self.ecdh_tab)
        controls.grid(row=2, column=0, sticky="w", padx=8, pady=8)
        ttk.Button(controls, text="Auto gen Alice + Bob", command=self.generate_both_x25519).pack(side="left")
        ttk.Button(controls, text="Compute shared key", command=self.compute_x25519_shared).pack(side="left", padx=(8, 0))

        frame_a, self.alice_shared = self.output_box(self.ecdh_tab, "Alice shared = X25519(Alice private, Bob public)", height=4)
        frame_a.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 8))
        frame_b, self.bob_shared = self.output_box(self.ecdh_tab, "Bob shared = X25519(Bob private, Alice public)", height=4)
        frame_b.grid(row=4, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.ecdh_status = ttk.Label(self.ecdh_tab, text="", style="Status.TLabel")
        self.ecdh_status.grid(row=5, column=0, sticky="w", padx=8, pady=(0, 8))

    def generate_x25519(self, private_box: LabeledText, public_box: LabeledText):
        private_key = x25519.X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        private_box.set(to_c_array(private_bytes))
        public_box.set(to_c_array(public_bytes))

    def derive_x25519_public(self, private_box: LabeledText, public_box: LabeledText):
        try:
            public_box.set(to_c_array(x25519_public_from_private(parse_hex_array(private_box.get()))))
        except Exception as exc:
            messagebox.showerror("X25519 public key error", str(exc))

    def auto_derive_x25519_public(self, private_box: LabeledText, public_box: LabeledText):
        try:
            private_bytes = parse_hex_array(private_box.get())
            if len(private_bytes) == 32:
                public_box.set(to_c_array(x25519_public_from_private(private_bytes)))
        except Exception:
            pass

    def generate_both_x25519(self):
        self.generate_x25519(self.alice_priv, self.alice_pub)
        self.generate_x25519(self.bob_priv, self.bob_pub)
        self.compute_x25519_shared()

    def compute_x25519_shared(self):
        try:
            alice_private = parse_hex_array(self.alice_priv.get())
            bob_private = parse_hex_array(self.bob_priv.get())
            if not self.alice_pub.get():
                self.alice_pub.set(to_c_array(x25519_public_from_private(alice_private)))
            if not self.bob_pub.get():
                self.bob_pub.set(to_c_array(x25519_public_from_private(bob_private)))
            alice_public = parse_hex_array(self.alice_pub.get())
            bob_public = parse_hex_array(self.bob_pub.get())
            if len(alice_private) != 32 or len(bob_private) != 32:
                raise ValueError("X25519 private key must be 32 bytes.")
            if len(alice_public) != 32 or len(bob_public) != 32:
                raise ValueError("X25519 public key must be 32 bytes.")

            alice_key = x25519.X25519PrivateKey.from_private_bytes(alice_private)
            bob_key = x25519.X25519PrivateKey.from_private_bytes(bob_private)
            alice_shared = alice_key.exchange(x25519.X25519PublicKey.from_public_bytes(bob_public))
            bob_shared = bob_key.exchange(x25519.X25519PublicKey.from_public_bytes(alice_public))

            set_text(self.alice_shared, to_c_array(alice_shared))
            set_text(self.bob_shared, to_c_array(bob_shared))
            self.ecdh_status.configure(
                text="MATCH: Alice shared == Bob shared" if alice_shared == bob_shared else "NOT MATCH"
            )
        except Exception as exc:
            messagebox.showerror("ECDH X25519 error", str(exc))

    def build_ecdsa_tab(self):
        self.ecdsa_tab.columnconfigure(0, weight=1)
        self.ecdsa_mode, mode_row = self.data_mode_selector(self.ecdsa_tab)
        mode_row.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))

        self.ecdsa_data = LabeledText(self.ecdsa_tab, "Raw data", height=5)
        self.ecdsa_data.grid(row=1, column=0, sticky="nsew", padx=8)
        self.ecdsa_priv = LabeledText(self.ecdsa_tab, "Private key P-256 scalar 32 byte", height=3)
        self.ecdsa_priv.grid(row=2, column=0, sticky="ew", padx=8, pady=(8, 0))
        self.ecdsa_pub = LabeledText(self.ecdsa_tab, "P-256 public key: 64-byte x||y or 65-byte 0x04||x||y", height=4)
        self.ecdsa_pub.grid(row=3, column=0, sticky="ew", padx=8, pady=(8, 0))
        self.ecdsa_priv.text.bind("<FocusOut>", lambda _event: self.auto_derive_p256_public())
        self.ecdsa_sig = LabeledText(self.ecdsa_tab, "Signature input for verify: DER or raw r||s", height=4)
        self.ecdsa_sig.grid(row=4, column=0, sticky="ew", padx=8, pady=(8, 0))
        self.ecdsa_tab.rowconfigure(1, weight=1)

        controls = ttk.Frame(self.ecdsa_tab)
        controls.grid(row=5, column=0, sticky="w", padx=8, pady=8)
        ttk.Button(controls, text="Auto gen P-256 key", command=self.generate_p256).pack(side="left")
        ttk.Button(controls, text="Derive public from private", command=self.derive_p256_public).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Sign", command=self.sign_p256).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Verify", command=self.verify_p256).pack(side="left", padx=(8, 0))

        frame_hash, self.ecdsa_hash = self.output_box(self.ecdsa_tab, "Data SHA-256", height=4)
        frame_hash.grid(row=6, column=0, sticky="ew", padx=8, pady=(0, 8))
        frame_der, self.ecdsa_der = self.output_box(self.ecdsa_tab, "Signature DER", height=4)
        frame_der.grid(row=7, column=0, sticky="ew", padx=8, pady=(0, 8))
        frame_raw, self.ecdsa_raw = self.output_box(self.ecdsa_tab, "Signature raw r||s", height=4)
        frame_raw.grid(row=8, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.ecdsa_status = ttk.Label(self.ecdsa_tab, text="", style="Status.TLabel")
        self.ecdsa_status.grid(row=9, column=0, sticky="w", padx=8, pady=(0, 8))

    def generate_p256(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_value = private_key.private_numbers().private_value.to_bytes(32, "big")
        self.ecdsa_priv.set(to_c_array(private_value))
        self.ecdsa_pub.set(to_c_array(p256_public_bytes(private_key)))

    def derive_p256_public(self):
        try:
            private_key = p256_private_from_raw(parse_hex_array(self.ecdsa_priv.get()))
            self.ecdsa_pub.set(to_c_array(p256_public_bytes(private_key)))
        except Exception as exc:
            messagebox.showerror("P-256 public key error", str(exc))

    def auto_derive_p256_public(self):
        try:
            private_bytes = parse_hex_array(self.ecdsa_priv.get())
            if len(private_bytes) == 32:
                private_key = p256_private_from_raw(private_bytes)
                self.ecdsa_pub.set(to_c_array(p256_public_bytes(private_key)))
        except Exception:
            pass

    def sign_p256(self):
        try:
            data = parse_data(self.ecdsa_data.get(), self.ecdsa_mode.get())
            private_key = p256_private_from_raw(parse_hex_array(self.ecdsa_priv.get()))
            public_bytes = p256_public_bytes(private_key)
            if not self.ecdsa_pub.get():
                self.ecdsa_pub.set(to_c_array(public_bytes))

            digest = hashlib.sha256(data).digest()
            sig_der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            sig_raw = der_to_raw_rs(sig_der)
            set_text(self.ecdsa_hash, to_c_array(digest))
            set_text(self.ecdsa_der, to_c_array(sig_der))
            set_text(self.ecdsa_raw, to_c_array(sig_raw))
            self.ecdsa_sig.set(to_c_array(sig_raw))
            self.ecdsa_status.configure(text="Signed OK")
        except Exception as exc:
            messagebox.showerror("ECDSA sign error", str(exc))

    def verify_p256(self):
        try:
            data = parse_data(self.ecdsa_data.get(), self.ecdsa_mode.get())
            if not self.ecdsa_pub.get() and self.ecdsa_priv.get():
                self.auto_derive_p256_public()
            public_key = p256_public_from_raw(parse_hex_array(self.ecdsa_pub.get()))
            sig_text = self.ecdsa_sig.get() or get_text(self.ecdsa_raw) or get_text(self.ecdsa_der)
            signature = signature_to_der(parse_hex_array(sig_text))
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            self.ecdsa_status.configure(text="VERIFY OK")
        except InvalidSignature:
            self.ecdsa_status.configure(text="VERIFY FAIL")
        except Exception as exc:
            messagebox.showerror("ECDSA verify error", str(exc))


def main():
    root = tk.Tk()
    CryptoTestGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
