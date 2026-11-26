# Cyber Security Project 01 - 2FA Code Generator
# Graphic Interface code based on TKinter
# Date of Development: November 2026
# Developrt: Danial Gholipour
# BSc. Computer Engineering - Software
# Islamic Azad University - Karaj Branch
# ORCID: 0009-0004-1372-5307



#---------------------------------------------------------------

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

from simorgh.storage import Vault, WrongPasswordError

APP_ID = "io.github.DanialGPR.SimorghAuthenticator"
MIN_PASSWORD_LEN = 8


class UnlockPage(Gtk.Box):
    def __init__(self, vault: Vault, on_success):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_valign(Gtk.Align.CENTER)
        for side in ("start", "end", "top", "bottom"):
            getattr(self, f"set_margin_{side}")(24)

        self.vault = vault
        self.on_success = on_success
        self.creating = not vault.exists()

        title = Gtk.Label(
            label="Create master password" if self.creating else "Unlock vault")
        title.add_css_class("title-2")
        self.append(title)

        group = Adw.PreferencesGroup()
        self.pw = Adw.PasswordEntryRow(title="Password")
        group.add(self.pw)
        self.confirm = None
        if self.creating:
            self.confirm = Adw.PasswordEntryRow(title="Repeat password")
            group.add(self.confirm)
        self.append(group)

        self.error = Gtk.Label()
        self.error.add_css_class("error")
        self.append(self.error)

        button = Gtk.Button(label="Create" if self.creating else "Unlock")
        button.add_css_class("suggested-action")
        button.add_css_class("pill")
        button.set_halign(Gtk.Align.CENTER)
        button.connect("clicked", self.submit)
        self.append(button)

        if self.creating:
            self.pw.connect("entry-activated", lambda *_: self.confirm.grab_focus())
            self.confirm.connect("entry-activated", self.submit)
        else:
            self.pw.connect("entry-activated", self.submit)

    def submit(self, *_):
        password = self.pw.get_text()
        try:
            if self.creating:
                if len(password) < MIN_PASSWORD_LEN:
                    self.error.set_text(f"At least {MIN_PASSWORD_LEN} characters")
                    return
                if password != self.confirm.get_text():
                    self.error.set_text("Passwords don't match")
                    return
                self.vault.create(password)
            else:
                self.vault.unlock(password)
        except WrongPasswordError:
            self.error.set_text("Wrong password")
            self.pw.set_text("")
            return
        except (ValueError, KeyError):
            self.error.set_text("Vault file is corrupted")
            return
        self.on_success()


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="TOTP App")
        self.set_default_size(380, 560)
        self.set_size_request(380, 560)
        self.set_resizable(False)
        self.vault = Vault()

        header = Adw.HeaderBar()
        self.add_button = Gtk.Button(icon_name="list-add-symbolic")
        self.add_button.set_tooltip_text("Add account")
        self.add_button.set_visible(False)  # shown after unlock
        header.pack_start(self.add_button)
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic",
                                       menu_model=app.menu))

        self.stack = Gtk.Stack()
        self.stack.add_named(UnlockPage(self.vault, self.show_main), "unlock")
        self.stack.add_named(
            Adw.StatusPage(icon_name="dialog-password-symbolic",
                           title="No accounts yet",
                           description="Press + to add your first account"),
            "main")

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(self.stack)
        self.set_content(view)

    def show_main(self):
        self.stack.set_visible_child_name("main")
        self.add_button.set_visible(True)


class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)

        action = Gio.SimpleAction.new_stateful(
            "theme", GLib.VariantType.new("s"), GLib.Variant.new_string("default"))
        action.connect("activate", self.on_theme)
        self.add_action(action)

        section = Gio.Menu()
        section.append("System", "app.theme('default')")
        section.append("Light", "app.theme('light')")
        section.append("Dark", "app.theme('dark')")
        self.menu = Gio.Menu()
        self.menu.append_section("Theme", section)

    def on_theme(self, action, value):
        scheme = {
            "default": Adw.ColorScheme.DEFAULT,
            "light": Adw.ColorScheme.FORCE_LIGHT,
            "dark": Adw.ColorScheme.FORCE_DARK,
        }[value.get_string()]
        self.get_style_manager().set_color_scheme(scheme)
        action.set_state(value)

    def do_activate(self):
        win = self.props.active_window or MainWindow(self)
        win.present()


def main():
    sys.exit(App().run(sys.argv))


if __name__ == "__main__":
    main()