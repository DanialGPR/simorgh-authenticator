# Cyber Security Project 01 - 2FA Code Generator
# Graphic Interface code based on GTK v4.0
# Date of Development: November 2026
# Developrt: Danial Gholipour
# BSc. Computer Engineering - Software
# Islamic Azad University - Karaj Branch
# ORCID: 0009-0004-1372-5307



#---------------------------------------------------------------

import sys
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk
from simorgh.main import generate_totp, parse_otpauth_uri, seconds_remaining
from simorgh.storage import (
    MAX_ACCOUNTS, MIN_PASSWORD_LEN, AccountLimitError, AccountStore, Settings,
    UsernameTakenError, WrongPasswordError, WrongRecoveryKeyError,
    check_password, read_backup,
)

APP_ID = "io.github.DanialGPR.SimorghAuthenticator"
APP_NAME = "Simorgh Authenticator"

THEMES = [("System", "default"), ("Light", "light"), ("Dark", "dark")]
AUTO_LOCK_CHOICES = [("1 minute", 60), ("5 minutes", 300),
                     ("15 minutes", 900), ("Never", 0)]
CLIPBOARD_CHOICES = [("15 seconds", 15), ("30 seconds", 30),
                     ("60 seconds", 60), ("Never", 0)]


# ---------- small helpers ----------

def form_box(spacing=12):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
    for side in ("start", "end", "top", "bottom"):
        getattr(box, f"set_margin_{side}")(24)
    return box


def heading(text):
    label = Gtk.Label(label=text, wrap=True, justify=Gtk.Justification.CENTER)
    label.add_css_class("title-2")
    return label


def note(text):
    label = Gtk.Label(label=text, wrap=True, justify=Gtk.Justification.CENTER)
    label.add_css_class("dim-label")
    return label


def error_label():
    label = Gtk.Label(wrap=True)
    label.add_css_class("error")
    return label


def pill_button(text, callback, suggested=True):
    button = Gtk.Button(label=text, halign=Gtk.Align.CENTER)
    button.add_css_class("pill")
    if suggested:
        button.add_css_class("suggested-action")
    button.connect("clicked", callback)
    return button


def rows_group(*rows):
    group = Adw.PreferencesGroup()
    for row in rows:
        group.add(row)
    return group


def make_page(title, child, tag, start=(), end=()):
    header = Adw.HeaderBar()
    for widget in start:
        header.pack_start(widget)
    for widget in end:
        header.pack_end(widget)
    view = Adw.ToolbarView()
    view.add_top_bar(header)
    view.set_content(child)
    return Adw.NavigationPage(child=view, title=title, tag=tag)


def focus_later(widget):
    def _focus():
        widget.grab_focus()
        return GLib.SOURCE_REMOVE
    GLib.idle_add(_focus)


# ---------- add dialog ----------

class AddDialog(Adw.Dialog):
    def __init__(self, on_add):
        super().__init__(title="Add account", content_width=360)
        self.on_add = on_add

        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        add = Gtk.Button(label="Add")
        add.add_css_class("suggested-action")
        add.connect("clicked", self.submit)

        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        header.pack_start(cancel)
        header.pack_end(add)

        self.issuer = Adw.EntryRow(title="Service (e.g. GitHub)")
        self.account = Adw.EntryRow(title="Account (e.g. your email)")
        self.secret = Adw.PasswordEntryRow(title="Secret key or otpauth:// link")
        self.error = error_label()

        box = form_box()
        box.append(rows_group(self.issuer, self.account, self.secret))
        box.append(self.error)

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(box)
        self.set_child(view)

    def submit(self, *_):
        secret = self.secret.get_text().strip()
        entry = {
            "issuer": self.issuer.get_text().strip(),
            "account": self.account.get_text().strip(),
            "secret": secret,
            "digits": 6, "period": 30, "algorithm": "SHA1",
        }
        try:
            if secret.lower().startswith("otpauth://"):
                parsed = parse_otpauth_uri(secret)
                entry.update(parsed)
                entry["issuer"] = self.issuer.get_text().strip() or parsed["issuer"]
                entry["account"] = self.account.get_text().strip() or parsed["account"]
            generate_totp(entry["secret"], entry["digits"],
                          entry["period"], entry["algorithm"])
        except (ValueError, KeyError):
            self.error.set_text("Invalid secret key")
            return
        if not entry["issuer"]:
            self.error.set_text("Enter a service name")
            return
        self.on_add(entry)
        self.close()

class SecretsDialog(Adw.Dialog):
    """Password fields in a dialog. on_submit(values) returns an error text, or None to close."""

    def __init__(self, title, labels, button, on_submit, intro="", destructive=False):
        super().__init__(title=title, content_width=360)
        self.on_submit = on_submit

        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        ok = Gtk.Button(label=button)
        ok.add_css_class("destructive-action" if destructive else "suggested-action")
        ok.connect("clicked", self.submit)

        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        header.pack_start(cancel)
        header.pack_end(ok)

        self.rows = [Adw.PasswordEntryRow(title=label) for label in labels]
        self.error = error_label()
        box = form_box()
        if intro:
            box.append(note(intro))
        box.append(rows_group(*self.rows))
        box.append(self.error)

        for i, row in enumerate(self.rows):
            if i + 1 < len(self.rows):
                row.connect("entry-activated",
                            lambda _r, nxt=self.rows[i + 1]: nxt.grab_focus())
            else:
                row.connect("entry-activated", self.submit)

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(box)
        self.set_child(view)
        focus_later(self.rows[0])

    def submit(self, *_):
        error = self.on_submit([row.get_text() for row in self.rows])
        if error:
            self.error.set_text(error)
        else:
            self.close()


def text_area(height):
    view = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD, top_margin=8, bottom_margin=8,
                        left_margin=8, right_margin=8)
    scroll = Gtk.ScrolledWindow(child=view, min_content_height=height)
    scroll.add_css_class("card")
    return view, scroll


def buffer_text(view):
    buf = view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


class EditDialog(Adw.Dialog):
    def __init__(self, entry, on_save):
        super().__init__(title="Edit account", content_width=360)
        self.entry, self.on_save = entry, on_save

        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        save.connect("clicked", self.submit)
        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        header.pack_start(cancel)
        header.pack_end(save)

        self.issuer = Adw.EntryRow(title="Service")
        self.issuer.set_text(entry["issuer"])
        self.account = Adw.EntryRow(title="Account")
        self.account.set_text(entry["account"])
        self.notes, scroll = text_area(100)
        self.notes.get_buffer().set_text(entry.get("notes", ""))
        self.error = error_label()

        label = Gtk.Label(label="Notes (e.g. this service's recovery codes)", xalign=0)
        label.add_css_class("heading")
        box = form_box()
        box.append(rows_group(self.issuer, self.account))
        box.append(label)
        box.append(scroll)
        box.append(self.error)

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(box)
        self.set_child(view)

    def submit(self, *_):
        issuer = self.issuer.get_text().strip()
        if not issuer:
            self.error.set_text("Enter a service name")
            return
        self.on_save(self.entry["id"], issuer=issuer,
                     account=self.account.get_text().strip(),
                     notes=buffer_text(self.notes))
        self.close()


class ImportDialog(Adw.Dialog):
    def __init__(self, on_import):
        super().__init__(title="Import links", content_width=360)
        self.on_import = on_import

        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        go = Gtk.Button(label="Import")
        go.add_css_class("suggested-action")
        go.connect("clicked", self.submit)
        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        header.pack_start(cancel)
        header.pack_end(go)

        self.text, scroll = text_area(180)
        self.text.set_monospace(True)
        self.error = error_label()
        box = form_box()
        box.append(note("Paste otpauth://totp/... links, one per line."))
        box.append(scroll)
        box.append(self.error)

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(box)
        self.set_child(view)

    def submit(self, *_):
        entries, skipped = [], 0
        for line in buffer_text(self.text).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = parse_otpauth_uri(line)
                generate_totp(entry["secret"], entry["digits"],
                              entry["period"], entry["algorithm"])
            except (ValueError, KeyError):
                skipped += 1
                continue
            entries.append(entry)
        if not entries:
            self.error.set_text("No valid links found")
            return
        self.on_import(entries, skipped)
        self.close()

# ---------- one row per 2FA entry ----------

class CodeRow(Adw.ActionRow):
    def __init__(self, entry, on_copy, on_remove, on_edit, hide_codes):
        super().__init__(title=GLib.markup_escape_text(entry["issuer"]),
                         subtitle=GLib.markup_escape_text(entry["account"]),
                         activatable=True)
        self.entry = entry
        self.hidden_mode = hide_codes
        self.revealed_until = 0.0
        self.code_text = ""
        self.on_copy = on_copy

        self.add_prefix(Adw.Avatar(size=40, text=entry["issuer"], show_initials=True))

        self.code = Gtk.Label(valign=Gtk.Align.CENTER)
        self.code.add_css_class("title-3")
        self.code.add_css_class("monospace")
        self.secs = Gtk.Label(valign=Gtk.Align.CENTER, width_chars=3)
        self.secs.add_css_class("dim-label")

        copy = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER,
                          tooltip_text="Copy code")
        copy.add_css_class("flat")
        copy.connect("clicked", lambda *_: on_copy(self.code_text))

        menu = Gtk.MenuButton(icon_name="view-more-symbolic", valign=Gtk.Align.CENTER,
                              tooltip_text="More")
        menu.add_css_class("flat")
        popover = Gtk.Popover()
        actions = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        for label, callback in (("Edit", on_edit), ("Remove", on_remove)):
            button = Gtk.Button(label=label)
            button.add_css_class("flat")
            button.connect("clicked",
                           lambda _b, cb=callback: (popover.popdown(), cb(self.entry)))
            actions.append(button)
        popover.set_child(actions)
        menu.set_popover(popover)

        for widget in (self.code, self.secs, copy, menu):
            self.add_suffix(widget)
        self.connect("activated", self.on_activated)
        self.refresh()

    def on_activated(self, *_):
        if self.hidden_mode and time.monotonic() >= self.revealed_until:
            self.revealed_until = time.monotonic() + 10  # reveal for 10 s
            self.refresh()
        else:
            self.on_copy(self.code_text)

    def refresh(self):
        e = self.entry
        self.code_text = generate_totp(e["secret"], e["digits"],
                                       e["period"], e["algorithm"])
        half = len(self.code_text) // 2
        if self.hidden_mode and time.monotonic() >= self.revealed_until:
            shown = "•" * half + " " + "•" * (len(self.code_text) - half)
        else:
            shown = f"{self.code_text[:half]} {self.code_text[half:]}"
        self.code.set_text(shown)
        left = seconds_remaining(e["period"])
        self.secs.set_text(f"{left}s")
        if left <= 5:
            self.secs.add_css_class("error")
        else:
            self.secs.remove_css_class("error")

# ---------- main window ----------

class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=APP_NAME)
        self.set_default_size(420, 560)
        self.set_size_request(420, 560)
        self.set_resizable(False)

        self.app = app
        self.store = AccountStore()
        self.settings = app.settings
        self.account = None
        self.rows = []
        self.last_activity = time.monotonic()
        self._clip_timer = 0

        self.nav = Adw.NavigationView()
        self.toasts = Adw.ToastOverlay()
        self.toasts.set_child(self.nav)
        self.set_content(self.toasts)

        for name, callback in (("add", self.on_add), ("lock", self.on_lock),
                               ("search", self.on_search),
                               ("settings", self.on_settings),
                               ("about", self.on_about)):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

        key = Gtk.EventControllerKey()
        key.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        key.connect("key-pressed", self.on_activity)
        motion = Gtk.EventControllerMotion()
        motion.connect("motion", self.on_activity)
        self.add_controller(key)
        self.add_controller(motion)

        GLib.timeout_add(500, self.tick)
        self.show_start()

    # ----- timers, activity, lock -----

    def on_activity(self, *_):
        self.last_activity = time.monotonic()
        return False

    def tick(self):
        if self.account:
            limit = self.settings.get("auto_lock")
            if limit and time.monotonic() - self.last_activity > limit:
                self.lock()
            else:
                for row in self.rows:
                    row.refresh()
        return GLib.SOURCE_CONTINUE

    def lock(self):
        dialog = self.get_visible_dialog()
        if dialog:
            dialog.force_close()
        if self.account:
            self.account.lock()
        self.account = None
        self.rows = []
        self.show_start()

    def on_lock(self, *_):
        if self.account:
            self.lock()

    # ----- navigation -----

    def show_start(self):
        if self.store.list():
            self.nav.replace([self.build_accounts_page()])
        else:
            self.nav.replace([self.build_signup_page()])

    def open_codes(self, account):
        self.account = account
        self.last_activity = time.monotonic()
        self.nav.replace([self.build_codes_page()])

    # ----- auth pages -----

    def build_accounts_page(self):
        accounts = self.store.list()
        box = form_box()
        box.append(heading("Choose account"))

        group = Adw.PreferencesGroup()
        for acc in accounts:
            row = Adw.ActionRow(title=GLib.markup_escape_text(acc.username),
                                activatable=True)
            row.add_prefix(Adw.Avatar(size=40, text=acc.username, show_initials=True))
            row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            row.connect("activated", lambda _r, a=acc: self.show_password_page(a))
            group.add(row)
        box.append(group)

        if len(accounts) < MAX_ACCOUNTS:
            box.append(pill_button(
                "Restore from backup",
                lambda *_: self.restore_flow(self.start_restore),
                suggested=False))
        else:
            box.append(note(f"Maximum of {MAX_ACCOUNTS} accounts reached"))
        return make_page(APP_NAME, box, "accounts")

    def build_signup_page(self, entries=None, prefill=""):
        restoring = entries is not None
        box = form_box()
        box.append(heading("Restore account" if restoring else "Create account"))

        username = Adw.EntryRow(title="Username")
        username.set_text(prefill)
        pw = Adw.PasswordEntryRow(title=f"Password (min {MIN_PASSWORD_LEN} characters)")
        pw2 = Adw.PasswordEntryRow(title="Repeat password")
        box.append(rows_group(username, pw, pw2))
        if restoring:
            box.append(note(f"{len(entries)} accounts will be restored. "
                            "Choose a username and a password for this computer."))
        else:
            box.append(note("Your data is encrypted with this password. "
                            "You'll get a recovery key next. Keep it safe."))
        error = error_label()
        box.append(error)

        def submit(*_):
            if pw.get_text() != pw2.get_text():
                error.set_text("Passwords don't match")
                return
            try:
                account, recovery = self.store.create(
                    username.get_text(), pw.get_text(), entries=entries)
            except (ValueError, UsernameTakenError, AccountLimitError) as exc:
                error.set_text(str(exc))
                return
            self.nav.replace([self.build_recovery_page(
                account, recovery,
                "Save this key somewhere safe. It's the only way to "
                "reset your password. It won't be shown again.")])

        username.connect("entry-activated", lambda *_: pw.grab_focus())
        pw.connect("entry-activated", lambda *_: pw2.grab_focus())
        pw2.connect("entry-activated", submit)
        box.append(pill_button("Restore" if restoring else "Create", submit))
        if not restoring:
            box.append(pill_button(
                "Restore from backup",
                lambda *_: self.restore_flow(self.start_restore),
                suggested=False))
        focus_later(pw if restoring else username)
        return make_page("Restore account" if restoring else "Create account", box,
                         "signup-restore" if restoring else "signup")
    
    def build_recovery_page(self, account, key, intro):
        box = form_box()
        box.append(heading("Your recovery key"))
        box.append(note(intro))

        parts = key.split("-")
        shown = "-".join(parts[:4]) + "\n" + "-".join(parts[4:])
        label = Gtk.Label(label=shown, selectable=True, justify=Gtk.Justification.CENTER)
        label.add_css_class("title-3")
        label.add_css_class("monospace")
        box.append(label)

        def copy(*_):
            self.get_clipboard().set(key)
            self.toasts.add_toast(Adw.Toast(title="Recovery key copied", timeout=2))

        box.append(pill_button("Copy key", copy, suggested=False))

        check = Gtk.CheckButton(label="I have saved this key", halign=Gtk.Align.CENTER)
        box.append(check)
        done = pill_button("Continue", lambda *_: self.open_codes(account))
        done.set_sensitive(False)
        check.connect("toggled", lambda c: done.set_sensitive(c.get_active()))
        box.append(done)
        return make_page("Recovery key", box, "recovery-key")

    def show_password_page(self, account):
        box = form_box()
        avatar = Adw.Avatar(size=72, text=account.username, show_initials=True,
                            halign=Gtk.Align.CENTER)
        box.append(avatar)
        box.append(heading(account.username))

        pw = Adw.PasswordEntryRow(title="Password")
        box.append(rows_group(pw))
        error = error_label()
        box.append(error)

        def submit(*_):
            try:
                account.unlock(pw.get_text())
            except WrongPasswordError:
                error.set_text("Wrong password")
                pw.set_text("")
                return
            except (ValueError, KeyError):
                error.set_text("Account file is corrupted")
                return
            self.open_codes(account)

        pw.connect("entry-activated", submit)
        box.append(pill_button("Unlock", submit))
        forgot = Gtk.Button(label="Forgot password?", halign=Gtk.Align.CENTER)
        forgot.add_css_class("flat")
        forgot.connect("clicked", lambda *_: self.nav.push(self.build_reset_page(account)))
        box.append(forgot)

        self.nav.push(make_page("Unlock", box, "password"))
        focus_later(pw)

    def build_reset_page(self, account):
        box = form_box()
        box.append(heading("Reset password"))
        rec = Adw.EntryRow(title="Recovery key")
        pw = Adw.PasswordEntryRow(title=f"New password (min {MIN_PASSWORD_LEN})")
        pw2 = Adw.PasswordEntryRow(title="Repeat new password")
        box.append(rows_group(rec, pw, pw2))
        error = error_label()
        box.append(error)

        def submit(*_):
            if pw.get_text() != pw2.get_text():
                error.set_text("Passwords don't match")
                return
            try:
                new_key = account.reset_with_recovery(rec.get_text(), pw.get_text())
            except WrongRecoveryKeyError:
                error.set_text("Wrong recovery key")
                return
            except ValueError as exc:
                error.set_text(str(exc))
                return
            self.nav.replace([self.build_recovery_page(
                account, new_key,
                "Password changed. Your old recovery key no longer works. "
                "Save this new one.")])

        box.append(pill_button("Reset password", submit))
        focus_later(rec)
        return make_page("Reset password", box, "reset")

    # ----- codes page -----

    def build_codes_page(self):
        self.search = Gtk.SearchEntry(placeholder_text="Search accounts")
        for side in ("start", "end", "top"):
            getattr(self.search, f"set_margin_{side}")(12)
        self.search.connect("search-changed", self.on_search_changed)

        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE,
                                   valign=Gtk.Align.START)
        self.listbox.add_css_class("boxed-list")
        for side in ("start", "end", "top", "bottom"):
            getattr(self.listbox, f"set_margin_{side}")(12)
        self.listbox.set_filter_func(self.matches)

        self.empty = Adw.StatusPage(icon_name="system-search-symbolic")
        self.body = Gtk.Stack(vexpand=True)
        self.body.add_named(Gtk.ScrolledWindow(child=self.listbox), "list")
        self.body.add_named(self.empty, "empty")

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.append(self.search)
        content.append(self.body)

        add = Gtk.Button(icon_name="list-add-symbolic", action_name="win.add",
                         tooltip_text="Add account (Ctrl+N)")
        lock = Gtk.Button(icon_name="system-lock-screen-symbolic",
                          action_name="win.lock", tooltip_text="Lock (Ctrl+L)")
        menu = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=self.app.menu)
        page = make_page(self.account.username, content, "codes",
                         start=(add, lock), end=(menu,))
        self.reload()
        return page

    def matches(self, row):
        query = self.search.get_text().strip().lower()
        if not query:
            return True
        return (query in row.entry["issuer"].lower()
                or query in row.entry["account"].lower())

    def on_search_changed(self, *_):
        self.listbox.invalidate_filter()
        self.update_view()

    def on_search(self, *_):
        if self.account:
            self.search.grab_focus()

    def update_view(self):
        if any(self.matches(row) for row in self.rows):
            self.body.set_visible_child_name("list")
            return
        has_any = bool(self.rows)
        self.empty.set_title("No results" if has_any else "No accounts yet")
        self.empty.set_description(
            "Try a different search" if has_any else "Press + to add your first account")
        self.body.set_visible_child_name("empty")

    def reload(self):
        self.listbox.remove_all()
        self.rows = []
        for entry in self.account.entries:
            row = CodeRow(entry, self.copy_code, self.confirm_remove,
                          self.edit_entry, self.settings.get("hide_codes"))
            self.listbox.append(row)
            self.rows.append(row)
        self.update_view()

    def on_add(self, *_):
        if self.account:
            AddDialog(self.add_entry).present(self)

    def add_entry(self, entry):
        self.account.add(entry)
        self.reload()
        self.toasts.add_toast(Adw.Toast(title="Account added", timeout=2))

    def confirm_remove(self, entry):
        dialog = Adw.AlertDialog(
            heading="Remove account?",
            body=(f"Remove {entry['issuer']} ({entry['account']})? "
                  "You may lose access to that service if you have no other "
                  "way to sign in."))
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("remove", "Remove")
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def on_response(_dialog, response):
            if response == "remove" and self.account:
                self.account.remove(entry["id"])
                self.reload()

        dialog.connect("response", on_response)
        dialog.present(self)

    # ----- clipboard -----

    def copy_code(self, code):
        self.get_clipboard().set(code)
        self.toast("Code copied")
        if self._clip_timer:
            GLib.source_remove(self._clip_timer)
            self._clip_timer = 0
        seconds = self.settings.get("clipboard_clear")
        if seconds:
            self._clip_timer = GLib.timeout_add_seconds(seconds, self.clear_clipboard)

    def clear_clipboard(self):
        self._clip_timer = 0
        clipboard = self.get_clipboard()
        if clipboard.is_local():  # only if nothing else was copied meanwhile
            clipboard.set_content(None)
        return GLib.SOURCE_REMOVE

    # ----- helpers -----

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=2))

    # ----- edit / import -----

    def edit_entry(self, entry):
        EditDialog(entry, self.save_entry).present(self)

    def save_entry(self, entry_id, **fields):
        self.account.update(entry_id, **fields)
        self.reload()

    def import_dialog(self, *_):
        ImportDialog(self.import_entries).present(self)

    def import_entries(self, entries, skipped):
        added = self.account.merge_entries(entries)
        self.reload()
        text = f"Imported {added} accounts"
        if skipped:
            text += f", skipped {skipped} invalid"
        self.toast(text)

    # ----- backup / restore -----

    def backup(self, *_):
        def submit(values):
            if values[0] != values[1]:
                return "Passwords don't match"
            try:
                check_password(values[0])
            except ValueError as exc:
                return str(exc)
            self.save_backup_file(values[0])
            return None

        SecretsDialog(
            "Back up accounts", ["Backup password", "Repeat backup password"],
            "Continue", submit,
            intro="The backup is encrypted with this password. It can differ "
                  "from your account password, but you'll need it to restore.",
        ).present(self)

    def save_backup_file(self, password):
        chooser = Gtk.FileDialog(
            title="Save backup",
            initial_name=f"{self.account.username}-{time.strftime('%Y-%m-%d')}"
                         ".simorgh-backup")

        def saved(dialog, result):
            try:
                file = dialog.save_finish(result)
            except GLib.Error:
                return
            if not self.account:
                return
            try:
                self.account.export_backup(file.get_path(), password)
            except OSError:
                self.toast("Could not write the backup file")
                return
            self.toast("Backup saved")

        chooser.save(self, None, saved)

    def restore_flow(self, on_data):
        chooser = Gtk.FileDialog(title="Choose backup file")

        def picked(dialog, result):
            try:
                file = dialog.open_finish(result)
            except GLib.Error:
                return
            path = file.get_path()

            def submit(values):
                try:
                    data = read_backup(path, values[0])
                    data["entries"], data["username"]
                except WrongPasswordError:
                    return "Wrong backup password"
                except (ValueError, KeyError, OSError, AttributeError, TypeError):
                    return "Not a valid backup file"
                on_data(data)
                return None

            SecretsDialog("Backup password", ["Backup password"],
                          "Restore", submit).present(self)

        chooser.open(self, None, picked)

    def start_restore(self, data):
        self.nav.push(self.build_signup_page(
            entries=data["entries"], prefill=data["username"]))

    def restore_into_account(self, *_):
        def got(data):
            if not self.account:
                return
            added = self.account.merge_entries(data["entries"])
            self.reload()
            self.toast(f"Restored {added} new accounts")

        self.restore_flow(got)

    # ----- account actions -----

    def change_password(self, *_):
        def submit(values):
            old, new, new2 = values
            if new != new2:
                return "Passwords don't match"
            try:
                self.account.change_password(old, new)
            except WrongPasswordError:
                return "Wrong current password"
            except ValueError as exc:
                return str(exc)
            self.toast("Password changed")
            return None

        SecretsDialog(
            "Change password",
            ["Current password", f"New password (min {MIN_PASSWORD_LEN})",
             "Repeat new password"],
            "Change", submit).present(self)

    def new_recovery(self, *_):
        def submit(values):
            try:
                key = self.account.regenerate_recovery(values[0])
            except WrongPasswordError:
                return "Wrong password"
            self.nav.push(self.build_recovery_page(
                self.account, key,
                "New recovery key created. The old one no longer works."))
            return None

        SecretsDialog("New recovery key", ["Password"], "Create", submit).present(self)

    def delete_account(self, *_):
        def submit(values):
            try:
                self.account.delete(values[0])
            except WrongPasswordError:
                return "Wrong password"
            self.account = None
            self.rows = []
            self.show_start()
            return None

        SecretsDialog(
            "Delete account", ["Password"], "Delete", submit, destructive=True,
            intro="This permanently deletes this account and all its 2FA entries "
                  "from this computer. Make a backup first.",
        ).present(self)

    # ----- settings page -----

    def choice_row(self, title, key, choices):
        row = Adw.ComboRow(title=title,
                           model=Gtk.StringList.new([name for name, _v in choices]))
        current = self.settings.get(key)
        for i, (_name, value) in enumerate(choices):
            if value == current:
                row.set_selected(i)
        row.connect("notify::selected",
                    lambda r, _p: self.settings.set(key, choices[r.get_selected()][1]))
        return row

    def on_hide_toggled(self, row, _param):
        self.settings.set("hide_codes", row.get_active())
        self.reload()

    def build_settings_page(self):
        page = Adw.PreferencesPage()

        look = Adw.PreferencesGroup(title="Appearance")
        theme = Adw.ComboRow(title="Theme",
                             model=Gtk.StringList.new([n for n, _v in THEMES]))
        current = self.settings.get("theme")
        theme.set_selected(next(
            (i for i, (_n, v) in enumerate(THEMES) if v == current), 0))
        theme.connect("notify::selected",
                      lambda r, _p: self.app.set_theme(THEMES[r.get_selected()][1]))
        look.add(theme)
        page.add(look)

        security = Adw.PreferencesGroup(title="Security")
        security.add(self.choice_row("Auto-lock after", "auto_lock", AUTO_LOCK_CHOICES))
        security.add(self.choice_row("Clear clipboard after", "clipboard_clear",
                                     CLIPBOARD_CHOICES))
        hide = Adw.SwitchRow(title="Hide codes until clicked",
                             active=self.settings.get("hide_codes"))
        hide.connect("notify::active", self.on_hide_toggled)
        security.add(hide)
        page.add(security)

        account = Adw.PreferencesGroup(title="Account")
        for title, subtitle, callback in (
            ("Change password", "Re-encrypts your account with a new password",
             self.change_password),
            ("Back up accounts", "Save an encrypted backup file", self.backup),
            ("Restore from backup", "Add entries from a backup file",
             self.restore_into_account),
            ("Import links", "Paste otpauth:// links from other apps",
             self.import_dialog),
            ("New recovery key", "Replaces your current recovery key",
             self.new_recovery),
        ):
            row = Adw.ActionRow(title=title, subtitle=subtitle, activatable=True)
            row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            row.connect("activated", callback)
            account.add(row)
        page.add(account)

        danger = Adw.PreferencesGroup(title="Danger zone")
        delete = Adw.ActionRow(title="Delete account",
                               subtitle="Permanently removes this account from this computer",
                               activatable=True)
        delete.add_css_class("error")
        delete.connect("activated", self.delete_account)
        danger.add(delete)
        page.add(danger)

        return make_page("Settings", page, "settings")

    def on_settings(self, *_):
        if self.account and not self.nav.find_page("settings"):
            self.nav.push(self.build_settings_page())

    def on_about(self, *_):
        Adw.AboutDialog(
            application_name=APP_NAME,
            developer_name="DanialGPR", version="1.0.0",
            comments="Offline two-factor (TOTP) code generator",
            website="https://github.com/DanialGPR/simorgh-authenticator",
        ).present(self)

# ---------- application ----------

class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)
        self.settings = Settings()
        self.menu = Gio.Menu()
        self.menu.append("Settings", "win.settings")
        self.menu.append(f"About {APP_NAME}", "win.about")

    def set_theme(self, value, save=True):
        scheme = {
            "default": Adw.ColorScheme.DEFAULT,
            "light": Adw.ColorScheme.FORCE_LIGHT,
            "dark": Adw.ColorScheme.FORCE_DARK,
        }.get(value, Adw.ColorScheme.DEFAULT)
        self.get_style_manager().set_color_scheme(scheme)
        if save:
            self.settings.set("theme", value)

    def do_activate(self):
        dev_icons = Path(__file__).resolve().parents[2] / "data" / "icons"
        if dev_icons.is_dir():  # running from the source tree, not installed
            Gtk.IconTheme.get_for_display(Gdk.Display.get_default()) \
                .add_search_path(str(dev_icons))
        Gtk.Window.set_default_icon_name(APP_ID)

        self.set_accels_for_action("win.add", ["<Ctrl>n"])
        self.set_accels_for_action("win.lock", ["<Ctrl>l"])
        self.set_accels_for_action("win.search", ["<Ctrl>f"])
        self.set_accels_for_action("win.settings", ["<Ctrl>comma"])
        self.set_theme(self.settings.get("theme"), save=False)
        win = self.props.active_window or MainWindow(self)
        win.present()

def main():
    sys.exit(App().run(sys.argv))


if __name__ == "__main__":
    main()