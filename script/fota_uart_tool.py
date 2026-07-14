import argparse
import datetime as dt
import hashlib
import json
import struct
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover - shown in GUI at runtime
    serial = None
    list_ports = None

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID


PACK_START = 0xAC
PACK_END = 0xBB
COM_MAX_PAYLOAD_SIZE = 250

CMD_RESET = 0x04
CMD_UPDATE_BEGIN = 0x10
CMD_UPDATE_CHUNK = 0x11
CMD_UPDATE_END = 0x12

REPORT_STATUS = 0x80
REPORT_ACK = 0x81
REPORT_NACK = 0x82
REPORT_BOOT = 0x83
REPORT_JUMP = 0x84

SECURE_BOOT_MANIFEST_MAGIC = 0x53424D46
SECURE_BOOT_MANIFEST_VERSION = 1
SECURE_BOOT_MANIFEST_SIGNED_SIZE = 52

DEFAULT_CHUNK_SIZE = 200
MIN_CHUNK_SIZE = 8

RESULT_NAMES = {
    0: "OK",
    1: "ARGUMENT",
    2: "NO_VALID_IMAGE",
    3: "MANIFEST",
    4: "HASH",
    5: "SIGNATURE",
    6: "ROLLBACK",
    7: "FLASH",
    8: "STATE",
}


def crc16_mcrf4xx(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            crc &= 0xFFFF
    return crc


def pack_frame(payload: bytes) -> bytes:
    if not 1 <= len(payload) <= COM_MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload length must be 1..{COM_MAX_PAYLOAD_SIZE} bytes")
    header = struct.pack(">BH", PACK_START, len(payload))
    crc_input = header[1:] + payload
    crc = crc16_mcrf4xx(crc_input)
    return header + payload + struct.pack(">H", crc) + bytes([PACK_END])


def result_name(value: int) -> str:
    return RESULT_NAMES.get(value, f"UNKNOWN_{value}")


class FrameReader:
    def __init__(self, ser):
        self.ser = ser

    def read_payload(self, timeout_s: float) -> bytes | None:
        deadline = time.monotonic() + timeout_s
        state = "wait_start"
        length = 0
        payload = bytearray()
        crc_bytes = bytearray()

        while time.monotonic() < deadline:
            chunk = self.ser.read(1)
            if not chunk:
                continue
            byte = chunk[0]

            if state == "wait_start":
                if byte == PACK_START:
                    state = "len_hi"
                    payload.clear()
                    crc_bytes.clear()
            elif state == "len_hi":
                length = byte << 8
                crc_bytes.append(byte)
                state = "len_lo"
            elif state == "len_lo":
                length |= byte
                crc_bytes.append(byte)
                if not 1 <= length <= COM_MAX_PAYLOAD_SIZE:
                    state = "wait_start"
                else:
                    state = "payload"
            elif state == "payload":
                payload.append(byte)
                crc_bytes.append(byte)
                if len(payload) == length:
                    state = "crc_hi"
            elif state == "crc_hi":
                received_crc = byte << 8
                state = ("crc_lo", received_crc)
            elif isinstance(state, tuple) and state[0] == "crc_lo":
                received_crc = state[1] | byte
                if received_crc != crc16_mcrf4xx(bytes(crc_bytes)):
                    state = "wait_start"
                else:
                    state = "end"
            elif state == "end":
                state = "wait_start"
                if byte == PACK_END:
                    return bytes(payload)
        return None


def p256_public_raw(private_key) -> bytes:
    point = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    if len(point) != 65 or point[0] != 0x04:
        raise ValueError("Unexpected P-256 public key format")
    return point[1:]


def der_to_raw_rs(signature_der: bytes) -> bytes:
    r, s = utils.decode_dss_signature(signature_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def to_c_array(name: str, data: bytes, per_line: int = 12) -> str:
    items = [f"0x{b:02X}" for b in data]
    lines = []
    for i in range(0, len(items), per_line):
        lines.append("    " + ", ".join(items[i : i + per_line]))
    body = ",\n".join(lines) if lines else ""
    return f"const uint8_t {name}[{len(data)}] = {{\n{body}\n}};\n"


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def generate_key_cert(out_dir: str, common_name: str) -> tuple[str, str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.utcnow()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )

    key_path = out / "secure_boot_p256_private_key.pem"
    cert_path = out / "secure_boot_p256_cert.pem"
    pub_c_path = out / "secure_boot_public_key.generated.c"

    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pub_c_path.write_text(
        '#include "secure_boot.h"\n\n'
        "/* Copy this value into Core/Src/secure/secure_boot_public_key.c. */\n"
        + to_c_array("secure_boot_public_key", p256_public_raw(private_key)),
        encoding="utf-8",
    )
    return str(key_path), str(cert_path), str(pub_c_path)


def sign_firmware(firmware_path: str, key_path: str, version: int) -> dict:
    firmware = Path(firmware_path).read_bytes()
    private_key = load_private_key(key_path)
    image_hash = hashlib.sha256(firmware).digest()
    signed_region = struct.pack(
        "<IHHIII32s",
        SECURE_BOOT_MANIFEST_MAGIC,
        SECURE_BOOT_MANIFEST_VERSION,
        SECURE_BOOT_MANIFEST_SIGNED_SIZE,
        len(firmware),
        version,
        0,
        image_hash,
    )
    signature_der = private_key.sign(signed_region, ec.ECDSA(hashes.SHA256()))
    signature_raw = der_to_raw_rs(signature_der)
    return {
        "firmware_path": str(Path(firmware_path).resolve()),
        "image_size": len(firmware),
        "image_version": version,
        "image_sha256": image_hash.hex(),
        "manifest_signed_region": signed_region.hex(),
        "signature_raw": signature_raw.hex(),
        "public_key_raw": p256_public_raw(private_key).hex(),
    }


def parse_report(payload: bytes) -> dict:
    if len(payload) != 20:
        return {"raw": payload.hex(), "valid": False}
    return {
        "valid": True,
        "report": payload[0],
        "command": payload[1],
        "controller_state": payload[2],
        "result": payload[3],
        "update_state": payload[7],
        "received_size": struct.unpack_from("<I", payload, 8)[0],
        "expected_size": struct.unpack_from("<I", payload, 12)[0],
        "image_version": struct.unpack_from("<I", payload, 16)[0],
    }


def report_name(value: int) -> str:
    names = {
        REPORT_STATUS: "STATUS",
        REPORT_ACK: "ACK",
        REPORT_NACK: "NACK",
        REPORT_BOOT: "BOOT",
        REPORT_JUMP: "JUMP",
    }
    return names.get(value, f"0x{value:02X}")


class FotaClient:
    def __init__(self, port: str, baudrate: int, logger):
        if serial is None:
            raise RuntimeError("pyserial is not installed. Run: python -m pip install -r script/requirements.txt")
        self.ser = serial.Serial(port, baudrate=baudrate, timeout=0.01, write_timeout=2)
        self.reader = FrameReader(self.ser)
        self.log = logger

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def pulse_reset(self, mode: str):
        if mode == "none":
            return
        self.log(f"Pulse reset mode: {mode}")
        if mode in ("dtr", "dtr_rts"):
            self.ser.dtr = True
        if mode in ("rts", "dtr_rts"):
            self.ser.rts = True
        time.sleep(0.15)
        if mode in ("dtr", "dtr_rts"):
            self.ser.dtr = False
        if mode in ("rts", "dtr_rts"):
            self.ser.rts = False
        time.sleep(0.35)
        self.ser.reset_input_buffer()

    def reset_target(self, mode: str):
        self.ser.reset_input_buffer()
        self.log("TX RESET command")
        self.send_payload(bytes([CMD_RESET]))
        time.sleep(0.3)
        self.pulse_reset(mode)

    def send_payload(self, payload: bytes):
        self.ser.write(pack_frame(payload))
        self.ser.flush()

    def wait_report(self, command: int | None = None, timeout_s: float = 3.0) -> dict:
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            payload = self.reader.read_payload(max(0.05, deadline - time.monotonic()))
            if payload is None:
                continue
            report = parse_report(payload)
            last = report
            if report.get("valid"):
                self.log(
                    f"RX {report_name(report['report'])} cmd=0x{report['command']:02X} "
                    f"result={report['result']}({result_name(report['result'])}) "
                    f"rx={report['received_size']}/{report['expected_size']} "
                    f"update_state={report['update_state']}"
                )
                if command is None or report["command"] == command:
                    return report
            else:
                self.log(f"RX invalid payload: {payload.hex()}")
        if last is None:
            raise TimeoutError("Timeout waiting report")
        raise TimeoutError(f"Timeout waiting command 0x{command:02X}; last={last}")

    def send_command_expect_ack(self, payload: bytes, timeout_s: float = 3.0) -> dict:
        command = payload[0]
        self.send_payload(payload)
        report = self.wait_report(command=command, timeout_s=timeout_s)
        if report["report"] != REPORT_ACK or report["result"] != 0:
            raise RuntimeError(
                f"Command 0x{command:02X} failed: "
                f"{result_name(report['result'])} ({report})"
            )
        return report

    def wait_boot(self, timeout_s: float):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            report = self.wait_report(command=None, timeout_s=max(0.2, deadline - time.monotonic()))
            if report.get("report") == REPORT_BOOT:
                return report
        raise TimeoutError("Boot report not received")

    def transfer(
        self,
        signed: dict,
        chunk_size: int,
        delay_s: float,
    ):
        firmware = Path(signed["firmware_path"]).read_bytes()
        image_hash = bytes.fromhex(signed["image_sha256"])
        signature = bytes.fromhex(signed["signature_raw"])
        begin = (
            bytes([CMD_UPDATE_BEGIN])
            + struct.pack("<I", signed["image_size"])
            + struct.pack("<I", signed["image_version"])
            + image_hash
            + signature
        )
        if len(begin) != 105:
            raise ValueError(f"Internal error: update begin length is {len(begin)}")

        begin_report = self.send_command_expect_ack(begin, timeout_s=8.0)
        if begin_report["expected_size"] != signed["image_size"]:
            raise RuntimeError(
                f"Bootloader expected size {begin_report['expected_size']} "
                f"does not match firmware size {signed['image_size']}"
            )
        self.log("Bootloader accepted update")

        for offset in range(0, len(firmware), chunk_size):
            chunk = firmware[offset : offset + chunk_size]
            payload = bytes([CMD_UPDATE_CHUNK]) + struct.pack("<I", offset) + chunk
            report = self.send_command_expect_ack(payload, timeout_s=5.0)
            self.log(f"Chunk {offset + len(chunk)}/{len(firmware)} ACK")
            if delay_s > 0:
                time.sleep(delay_s)
            if report["received_size"] != offset + len(chunk):
                self.log("Warning: report received_size does not match host offset")
        self.send_command_expect_ack(bytes([CMD_UPDATE_END]), timeout_s=12.0)


class FotaToolGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Boot UART FOTA Tool")
        self.root.geometry("980x760")
        self.signed = None
        self.worker = None

        main = ttk.Frame(root)
        main.pack(fill="both", expand=True, padx=10, pady=10)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(6, weight=1)

        self.key_path = tk.StringVar()
        self.cert_path = tk.StringVar()
        self.fw_path = tk.StringVar()
        self.version = tk.StringVar(value="1")
        self.port = tk.StringVar()
        self.baud = tk.StringVar(value="115200")
        self.reset_mode = tk.StringVar(value="none")
        self.chunk_size = tk.StringVar(value=str(DEFAULT_CHUNK_SIZE))
        self.chunk_delay_ms = tk.StringVar(value="0")

        self._path_row(main, 0, "Private key", self.key_path, self.pick_key)
        self._path_row(main, 1, "Certificate", self.cert_path, self.pick_cert)
        self._path_row(main, 2, "Firmware", self.fw_path, self.pick_firmware)

        controls = ttk.Frame(main)
        controls.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Label(controls, text="Version").pack(side="left")
        ttk.Entry(controls, textvariable=self.version, width=10).pack(side="left", padx=(4, 12))
        ttk.Button(controls, text="Gen key/cert", command=self.generate_key_cert).pack(side="left")
        ttk.Button(controls, text="Sign firmware", command=self.sign_firmware).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Save signed info", command=self.save_signed_info).pack(side="left", padx=(8, 0))

        serial_row = ttk.Frame(main)
        serial_row.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        ttk.Label(serial_row, text="COM").pack(side="left")
        self.port_combo = ttk.Combobox(serial_row, textvariable=self.port, width=18)
        self.port_combo.pack(side="left", padx=(4, 8))
        ttk.Button(serial_row, text="Refresh", command=self.refresh_ports).pack(side="left")
        ttk.Label(serial_row, text="Baud").pack(side="left", padx=(12, 0))
        ttk.Entry(serial_row, textvariable=self.baud, width=10).pack(side="left", padx=(4, 12))
        ttk.Label(serial_row, text="Reset").pack(side="left")
        ttk.Combobox(
            serial_row,
            textvariable=self.reset_mode,
            values=["none", "dtr", "rts", "dtr_rts"],
            width=8,
            state="readonly",
        ).pack(side="left", padx=(4, 12))
        ttk.Label(serial_row, text="Chunk").pack(side="left")
        ttk.Entry(serial_row, textvariable=self.chunk_size, width=6).pack(side="left", padx=(4, 8))
        ttk.Label(serial_row, text="Delay ms").pack(side="left")
        ttk.Entry(serial_row, textvariable=self.chunk_delay_ms, width=6).pack(side="left", padx=(4, 0))

        actions = ttk.Frame(main)
        actions.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(10, 8))
        ttk.Button(actions, text="Start update", command=self.start_update).pack(side="left")

        self.log_text = tk.Text(main, height=22, wrap="word")
        self.log_text.grid(row=6, column=0, columnspan=3, sticky="nsew")
        self.refresh_ports()

    def _path_row(self, parent, row, label, var, command):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="ew", padx=6, pady=3)
        ttk.Button(parent, text="Browse", command=command).grid(row=row, column=2, sticky="e", pady=3)

    def log(self, msg: str):
        def append():
            self.log_text.insert("end", time.strftime("%H:%M:%S ") + msg + "\n")
            self.log_text.see("end")

        self.root.after(0, append)

    def refresh_ports(self):
        ports = []
        if list_ports is not None:
            ports = [p.device for p in list_ports.comports()]
        self.port_combo["values"] = ports
        if ports and not self.port.get():
            self.port.set(ports[0])

    def pick_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM key", "*.pem"), ("All files", "*.*")])
        if path:
            self.key_path.set(path)

    def pick_cert(self):
        path = filedialog.askopenfilename(filetypes=[("PEM cert", "*.pem"), ("All files", "*.*")])
        if path:
            self.cert_path.set(path)

    def pick_firmware(self):
        path = filedialog.askopenfilename(filetypes=[("Firmware", "*.bin *.hex *.elf"), ("All files", "*.*")])
        if path:
            self.fw_path.set(path)

    def run_worker(self, fn):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Busy", "A task is already running")
            return
        self.worker = threading.Thread(target=fn, daemon=True)
        self.worker.start()

    def generate_key_cert(self):
        out_dir = filedialog.askdirectory(title="Select output directory")
        if not out_dir:
            return
        try:
            key, cert, pub_c = generate_key_cert(out_dir, "STM32 Secure Boot FOTA")
            self.key_path.set(key)
            self.cert_path.set(cert)
            self.log(f"Generated key: {key}")
            self.log(f"Generated cert: {cert}")
            self.log(f"Generated public C array: {pub_c}")
        except Exception as exc:
            messagebox.showerror("Generate key/cert failed", str(exc))

    def sign_firmware(self):
        try:
            if not self.fw_path.get():
                raise ValueError("Select firmware file")
            if not self.key_path.get():
                raise ValueError("Select private key")
            version = int(self.version.get(), 0)
            self.signed = sign_firmware(self.fw_path.get(), self.key_path.get(), version)
            self.log(f"Signed FW size={self.signed['image_size']} version={version}")
            self.log(f"SHA256={self.signed['image_sha256']}")
            self.log(f"Signature={self.signed['signature_raw']}")
        except Exception as exc:
            messagebox.showerror("Sign failed", str(exc))

    def save_signed_info(self):
        if self.signed is None:
            self.sign_firmware()
            if self.signed is None:
                return
        default = Path(self.signed["firmware_path"]).with_suffix(".fota.json")
        path = filedialog.asksaveasfilename(initialfile=default.name, defaultextension=".json")
        if not path:
            return
        Path(path).write_text(json.dumps(self.signed, indent=2), encoding="utf-8")
        self.log(f"Saved signed info: {path}")

    def make_client(self) -> FotaClient:
        if not self.port.get():
            raise ValueError("Select COM port")
        return FotaClient(self.port.get(), int(self.baud.get(), 0), self.log)

    def start_update(self):
        def task():
            client = None
            try:
                if self.signed is None:
                    self.signed = sign_firmware(self.fw_path.get(), self.key_path.get(), int(self.version.get(), 0))
                chunk = int(self.chunk_size.get(), 0)
                if not MIN_CHUNK_SIZE <= chunk <= DEFAULT_CHUNK_SIZE:
                    raise ValueError(f"Chunk must be {MIN_CHUNK_SIZE}..{DEFAULT_CHUNK_SIZE}")
                delay_s = int(self.chunk_delay_ms.get(), 0) / 1000.0
                client = self.make_client()
                client.reset_target(self.reset_mode.get())
                self.log("Waiting BOOT status. If reset is not wired, press MCU reset now.")
                client.wait_boot(timeout_s=8.0)
                self.log("BOOT status received; starting firmware update")
                client.transfer(self.signed, chunk, delay_s)
                self.log("FOTA transfer complete")
            except Exception as exc:
                self.log(f"ERROR: {exc}")
            finally:
                if client:
                    client.close()

        self.run_worker(task)


def cli_sign(args) -> int:
    signed = sign_firmware(args.firmware, args.key, int(args.version, 0))
    print(json.dumps(signed, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(signed, indent=2), encoding="utf-8")
    return 0


def cli_gen_key(args) -> int:
    key, cert, pub_c = generate_key_cert(args.out_dir, args.common_name)
    print(f"key={key}")
    print(f"cert={cert}")
    print(f"public_c={pub_c}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="STM32 secure boot UART FOTA tool")
    sub = parser.add_subparsers(dest="cmd")

    gen = sub.add_parser("gen-key", help="generate ECDSA P-256 private key, cert and public C array")
    gen.add_argument("--out-dir", default="script/keys")
    gen.add_argument("--common-name", default="STM32 Secure Boot FOTA")
    gen.set_defaults(func=cli_gen_key)

    sign = sub.add_parser("sign", help="sign firmware and print FOTA metadata")
    sign.add_argument("--firmware", required=True)
    sign.add_argument("--key", required=True)
    sign.add_argument("--version", default="1")
    sign.add_argument("--out")
    sign.set_defaults(func=cli_sign)

    args = parser.parse_args()
    if hasattr(args, "func"):
        raise SystemExit(args.func(args))

    root = tk.Tk()
    FotaToolGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
