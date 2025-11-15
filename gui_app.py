"""
# gui_app.py — Pythonista GUI wrapper for Keybook + Carrier
# - SegmentedControl tabs (portable across Pythonista builds)
# - Background threads for heavy crypto (no UI freeze)
# - Safe UI updates via ui.delay(...)
# - Hard-stop if vault file missing (clear alert, no prompts)
# Fixes:
#  - Show/hide activity spinner on the MAIN thread (prevents UI hang)
#  - Status label during long PBKDF2 open
#  - No prompts if MyVault.keybook missing
# Adds:
#  - Fast header probe (edition_id, kdf_iters, payload_len) BEFORE PBKDF2
#  - Live status timer ("Opening vault... Ns")
#  - Safe main-thread spinner control
#  - Clear errors for missing file / bad creds
# Requires: keybook.py, carrier_ux.py (and optionally command_center_cli.py)

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

# gui_app.py — Pythonista GUI wrapper for Keybook + Carrier
# 

import os, time, threading, struct, base64
import ui

import keybook
try:
    import carrier_ux
except Exception:
    carrier_ux = None

try:
    import console
except Exception:
    console = None

APP_STATE = {
    "vault_path": "MyVault.keybook",
    "device_id": None,
    "handle": None,
    "last_bundle": None,
}

# ---------- small helpers ----------

def _alert(title, msg):
    try:
        if console:
            console.alert(title, msg, 'OK', hide_title_bar=True)
            return
    except Exception:
        pass
    try:
        ui.alert(title, msg, 'OK', hide_title_bar=True)
    except Exception:
        print(f"[{title}] {msg}")

def _prompt_text(title, message="", default=""):
    try:
        if console:
            return console.input_alert(title, message, default)
    except Exception:
        pass
    try:
        return ui.input_alert(title, message, default)
    except Exception:
        return input(f"{title} - {message}: ").strip() or default

def _prompt_secret(title, message=""):
    try:
        if console:
            v = console.password_alert(title, message)
            return v if v is not None else ""
    except Exception:
        pass
    return _prompt_text(title, message)

def _show_spinner(title):
    if console:
        ui.delay(lambda: console.show_activity(title), 0.0)

def _hide_spinner():
    if console:
        ui.delay(lambda: console.hide_activity(), 0.0)

def run_in_bg(do_work, on_done=None, on_error=None, spinner_title="Working..."):
    _show_spinner(spinner_title)
    def worker():
        try:
            result = do_work()
            if on_done:
                ui.delay(lambda: on_done(result), 0.0)
        except Exception as e:
            if on_error:
                ui.delay(lambda: on_error(e), 0.0)
        finally:
            _hide_spinner()
    threading.Thread(target=worker, daemon=True).start()

# ---------- fast header probe (no PBKDF2) ----------

MAGIC = b"KEYBOOK2"

def _probe_header(path):
    """
    Return dict with edition_id, kdf_iters, payload_len, device_ctx (fast).
    Raises FileNotFoundError/VaultCorrupt-like errors clearly if unreadable.
    """
    with open(path, "rb") as f:
        # read enough to cover header (edition, salts, nonce, iters, dev, salt_kdf, payload_len)
        blob = f.read(512)
    off = 0
    if len(blob) < len(MAGIC) + 1 + 1:
        raise IOError("File too small / truncated")
    if blob[:len(MAGIC)] != MAGIC:
        raise IOError("Not a KEYBOOK2 file")
    off += len(MAGIC)
    version = blob[off]; off += 1
    ed_len = blob[off]; off += 1
    need = off + ed_len + 32 + 32 + 4 + 2
    if len(blob) < need:
        raise IOError("Header truncated")
    edition_id = blob[off:off+ed_len].decode("utf-8"); off += ed_len
    salt_vault = blob[off:off+32]; off += 32
    nonce_vault = blob[off:off+32]; off += 32
    kdf_iters = struct.unpack(">I", blob[off:off+4])[0]; off += 4
    dev_len = struct.unpack(">H", blob[off:off+2])[0]; off += 2
    if len(blob) < off + dev_len + 32 + 8:
        raise IOError("Header device section truncated")
    device_ctx = blob[off:off+dev_len].decode("utf-8") if dev_len else None; off += dev_len
    salt_kdf = blob[off:off+32]; off += 32
    payload_len = struct.unpack(">Q", blob[off:off+8])[0]; off += 8
    return {
        "version": version,
        "edition_id": edition_id,
        "kdf_iters": kdf_iters,
        "device_ctx": device_ctx or None,
        "payload_len": payload_len,
    }

# ---------- Pane: Vault ----------

class VaultPane(ui.View):
    def __init__(self):
        super().__init__()
        self.background_color = 'white'

        self.vault_label = ui.Label(text='Vault file:', alignment=ui.ALIGN_LEFT)
        self.add_subview(self.vault_label)

        self.vault_field = ui.TextField(
            autocapitalization_type=ui.AUTOCAPITALIZE_NONE,
            text=APP_STATE["vault_path"]
        )
        self.add_subview(self.vault_field)

        self.device_field = ui.TextField(
            placeholder='Device ID (optional)',
            autocapitalization_type=ui.AUTOCAPITALIZE_NONE
        )
        self.add_subview(self.device_field)

        self.open_btn = ui.Button(title='Open Vault')
        self.open_btn.action = self._open_vault_action
        self.add_subview(self.open_btn)

        self.create_btn = ui.Button(title='Create Vault (text UI)')
        self.create_btn.action = self._create_vault_action
        self.add_subview(self.create_btn)

        # status line + timer
        self.status = ui.Label(text='', alignment=ui.ALIGN_LEFT, number_of_lines=0)
        self.add_subview(self.status)
        self._tick_start = None
        self._tick_running = False

        self.info_text = ui.TextView(editable=False)
        self.add_subview(self.info_text)

    def layout(self):
        W, H = self.width, self.height
        x, pad, line, gap = 10, 10, 32, 12
        y = 10

        self.vault_label.frame = (x, y, W - 2*x, 24); y += 24 + 6
        self.vault_field.frame = (x, y, W - 2*x, line); y += line + gap
        self.device_field.frame = (x, y, W - 2*x, line); y += line + gap

        self.open_btn.frame   = (x, y, W - 2*x, 44); y += 44 + gap
        self.create_btn.frame = (x, y, W - 2*x, 44); y += 44 + gap

        self.status.frame = (x, y, W - 2*x, 36); y += 36 + gap

        info_h = max(120, H - y - pad)
        self.info_text.frame = (x, y, W - 2*x, info_h)

    def _create_vault_action(self, sender):
        _alert(
            "Create Vault",
            "Use the Command Center (command_center_cli.py → option 1) to create MyVault.keybook.\n"
            "Return here afterwards and tap Open Vault."
        )

    def _set_busy(self, busy: bool, msg: str = ""):
        self.open_btn.enabled = not busy
        self.create_btn.enabled = not busy
        self.vault_field.enabled = not busy
        self.device_field.enabled = not busy
        self.status.text = msg

    def _start_tick(self):
        self._tick_start = time.time()
        self._tick_running = True
        self._tick()

    def _tick(self):
        if not self._tick_running:
            return
        elapsed = int(time.time() - (self._tick_start or time.time()))
        # append elapsed seconds to current status message
        base = self.status.text.split(" (")[0]
        self.status.text = f"{base} ({elapsed}s)"
        ui.delay(self._tick, 1.0)

    def _stop_tick(self):
        self._tick_running = False

    def _open_vault_action(self, sender):
        path = (self.vault_field.text or '').strip() or 'MyVault.keybook'
        APP_STATE["vault_path"] = path
        dev = (self.device_field.text or '').strip() or None

        if not os.path.exists(path):
            _alert(
                "Vault not found",
                f"File not found:\n{path}\n\nCreate a vault first (Command Center ▶ option 1), "
                "or change the path to an existing .keybook."
            )
            return

        # Fast header probe first (no PBKDF2) — shows iters + edition quickly
        try:
            hdr = _probe_header(path)
        except Exception as e:
            _alert("Read error", f"Could not read header: {e}")
            return

        # Prompt for secrets only after we know what we're opening
        passphrase = _prompt_secret('Passphrase', 'Enter passphrase:')
        if not passphrase:
            _alert("Input error", "Passphrase is required.")
            return
        pepper = _prompt_secret('Paper Pepper', 'Enter 32-char pepper:')
        if len(pepper) != 32:
            _alert("Input error", "Pepper must be exactly 32 characters.")
            return

        # Show what we're about to do
        kdf_info = f"Opening {os.path.basename(path)} | edition {hdr['edition_id']} | iters={hdr['kdf_iters']:,}"
        self._set_busy(True, kdf_info)
        self._start_tick()

        def do_work():
            # PBKDF2 + HMAC verify + decrypt payload (keybook.open_vault)
            return keybook.open_vault(path, passphrase, pepper, device_id=dev)

        def on_done(h):
            self._stop_tick()
            APP_STATE["handle"] = h
            APP_STATE["device_id"] = dev
            info = []
            info.append(f"Opened: {os.path.basename(h.path)}")
            info.append(f"Edition: {h.edition_id}")
            info.append(f"Device: {h.device_ctx or '(none)'}")
            info.append(f"Created: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(h.created_utc))}")
            info.append(f"KDF: PBKDF2-HMAC-SHA512 iters={h.kdf_iters:,}, dklen=32")
            self.info_text.text = "\n".join(info)
            self._set_busy(False, "")
            _alert("Success", f"Vault {h.edition_id} opened.")

        def on_error(e):
            self._stop_tick()
            msg = str(e)
            cls = e.__class__.__name__
            if isinstance(e, FileNotFoundError):
                msg = f"Vault file not found:\n{path}"
            elif cls == "InvalidUnlock":
                msg = "Credentials incorrect (passphrase/pepper/token)."
            elif cls == "VaultCorrupt":
                msg = "Vault is unreadable or failed integrity checks."
            self._set_busy(False, "")
            _alert("Error opening vault", msg)

        run_in_bg(do_work, on_done, on_error, spinner_title="Opening vault...")

# ---------- Pane: Derive ----------

class DerivePane(ui.View):
    def __init__(self):
        super().__init__()
        self.background_color = 'white'

        self.target_field = ui.TextField(
            placeholder='Target label (email/device/project)',
            autocapitalization_type=ui.AUTOCAPITALIZE_NONE
        )
        self.add_subview(self.target_field)

        self.derive_btn = ui.Button(title='Derive Key Bundle (enc/tran/hmac/aux1/aux2)')
        self.derive_btn.action = self._derive_action
        self.add_subview(self.derive_btn)

        self.out_text = ui.TextView(editable=False)
        self.add_subview(self.out_text)

    def layout(self):
        W, H = self.width, self.height
        x, pad, line, gap = 10, 10, 32, 12
        y = 10
        self.target_field.frame = (x, y, W - 2*x, line); y += line + gap
        self.derive_btn.frame = (x, y, W - 2*x, 44); y += 44 + gap
        out_h = max(120, H - y - pad)
        self.out_text.frame = (x, y, W - 2*x, out_h)

    def _derive_action(self, sender):
        h = APP_STATE.get("handle")
        if not h:
            _alert("Not ready", "Open a vault first on the Vault tab.")
            return
        target = (self.target_field.text or '').strip() or "sample"
        self.derive_btn.enabled = False

        def do_work():
            return keybook.derive_bundle(h, target=target)

        def on_done(bundle):
            APP_STATE["last_bundle"] = bundle
            lines = [f"Edition: {bundle['edition_id']}  Epoch: {bundle['epoch']}"]
            for k in ("enc", "tran", "hmac", "aux1", "aux2"):
                lines.append(f"{k}: {bundle[k].hex()}")
            self.out_text.text = "\n".join(lines)
            self.derive_btn.enabled = True
            _alert("Bundle ready", "Keys derived. (Displayed below)")

        def on_error(e):
            self.derive_btn.enabled = True
            _alert("Derive failed", str(e))

        run_in_bg(do_work, on_done, on_error, spinner_title="Deriving bundle...")

# ---------- Pane: Carrier ----------

class CarrierPane(ui.View):
    def __init__(self):
        super().__init__()
        self.background_color = 'white'
        self.lbl = ui.Label(
            text="Carrier tools run in a text submenu.\nTap to launch; you'll return here when done.",
            alignment=ui.ALIGN_LEFT, number_of_lines=0)
        self.add_subview(self.lbl)

        self.btn = ui.Button(title='Open Carrier Submenu')
        self.btn.action = self._open_carrier
        self.add_subview(self.btn)

        self.tip = ui.TextView(editable=False)
        self.tip.text = (
            "Tips:\n"
            " • Use two different channels (e.g., message photo + email text).\n"
            " • Run Health Check before first real use.\n"
            " • Commitment check catches tampering/swaps."
        )
        self.add_subview(self.tip)

    def layout(self):
        W, H = self.width, self.height
        x, pad = 10, 10
        y = 10
        self.lbl.frame = (x, y, W - 2*x, 60); y += 70
        self.btn.frame = (x, y, W - 2*x, 44); y += 54
        tip_h = max(120, H - y - pad)
        self.tip.frame = (x, y, W - 2*x, tip_h)

    def _open_carrier(self, sender):
        if carrier_ux is None:
            _alert("Carrier", "carrier_ux.py not found in this folder.")
            return
        try:
            _show_spinner("Carrier submenu...")
            carrier_ux.main_menu()
        finally:
            _hide_spinner()
        _alert("Carrier", "Carrier submenu closed.")

# ---------- Pane: Settings ----------

class SettingsPane(ui.View):
    def __init__(self):
        super().__init__()
        self.background_color = 'white'
        self.lbl = ui.Label(
            text="Minimal settings.\nMost options live in the Command Center or Carrier UI.",
            alignment=ui.ALIGN_LEFT, number_of_lines=0)
        self.add_subview(self.lbl)

        self.reset_btn = ui.Button(title='Reset session (forget handle)')
        self.reset_btn.action = self._reset_state
        self.add_subview(self.reset_btn)

    def layout(self):
        W, H = self.width, self.height
        x = 10; y = 10
        self.lbl.frame = (x, y, W - 2*x, 60); y += 70
        self.reset_btn.frame = (x, y, W - 2*x, 44)

    def _reset_state(self, sender):
        APP_STATE["handle"] = None
        APP_STATE["last_bundle"] = None
        _alert("Reset", "Session cleared (vault handle forgotten).")

# ---------- Root with SegmentedControl ----------

class Root(ui.View):
    def __init__(self):
        super().__init__()
        self.name = "Keybook GUI"
        self.background_color = 'white'

        self.seg = ui.SegmentedControl()
        self.seg.segments = ['Vault', 'Derive', 'Carrier', 'Settings']
        self.seg.selected_index = 0
        self.seg.action = self.on_seg
        self.add_subview(self.seg)

        self.container = ui.View()
        self.add_subview(self.container)

        self.panes = {
            0: VaultPane(),
            1: DerivePane(),
            2: CarrierPane(),
            3: SettingsPane(),
        }
        for idx, pane in self.panes.items():
            pane.flex = 'WH'
            pane.hidden = (idx != 0)
            self.container.add_subview(pane)

    def layout(self):
        W, H = self.width, self.height
        self.seg.frame = (10, 10, W - 20, 32)
        self.container.frame = (0, 52, W, H - 52)
        for pane in self.panes.values():
            pane.frame = self.container.bounds

    def on_seg(self, sender):
        idx = sender.selected_index
        for i, pane in self.panes.items():
            pane.hidden = (i != idx)

def main():
    Root().present('fullscreen')

if __name__ == '__main__':
    main()
