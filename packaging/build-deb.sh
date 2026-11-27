#!/usr/bin/env bash
set -euo pipefail

APP_ID="io.github.DanialGPR.SimorghAuthenticator"
PKG="simorgh-authenticator"

cd "$(dirname "$0")/.."
[ -f LICENSE ] || { echo "LICENSE file missing in project root"; exit 1; }

VERSION=$(grep -m1 '^version' pyproject.toml | cut -d'"' -f2)
ROOT="build/${PKG}_${VERSION}_all"

rm -rf "$ROOT"
install -d "$ROOT/DEBIAN" \
  "$ROOT/usr/bin" \
  "$ROOT/usr/lib/python3/dist-packages" \
  "$ROOT/usr/share/applications" \
  "$ROOT/usr/share/icons/hicolor/scalable/apps" \
  "$ROOT/usr/share/doc/$PKG"

cp -r src/simorgh "$ROOT/usr/lib/python3/dist-packages/"
find "$ROOT" -name __pycache__ -type d -prune -exec rm -rf {} +

install -m 755 packaging/simorgh-authenticator "$ROOT/usr/bin/$PKG"
install -m 644 "packaging/$APP_ID.desktop" "$ROOT/usr/share/applications/"
install -m 644 "data/icons/hicolor/scalable/apps/$APP_ID.svg" \
  "$ROOT/usr/share/icons/hicolor/scalable/apps/"

SYMBOLIC="data/icons/hicolor/symbolic/apps/$APP_ID-symbolic.svg"
if [ -f "$SYMBOLIC" ]; then
  install -d "$ROOT/usr/share/icons/hicolor/symbolic/apps"
  install -m 644 "$SYMBOLIC" "$ROOT/usr/share/icons/hicolor/symbolic/apps/"
fi

install -m 644 LICENSE "$ROOT/usr/share/doc/$PKG/copyright"

chmod -R u=rwX,go=rX "$ROOT"
INSTALLED_KB=$(du -sk "$ROOT" | cut -f1)

cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-4.0 (>= 4.10), gir1.2-adw-1 (>= 1.5), python3-cryptography
Maintainer: DanialGPR <91204429+DanialGPR@users.noreply.github.com>
Installed-Size: $INSTALLED_KB
Homepage: https://github.com/DanialGPR/simorgh-authenticator
Description: Offline two-factor (TOTP) authenticator for GNOME
 Simorgh Authenticator generates time-based one-time codes for any service
 that supports TOTP two-factor authentication. Accounts are protected by a
 master password, with encrypted backups and a recovery key. Nothing ever
 leaves your computer.
EOF

dpkg-deb --root-owner-group --build "$ROOT"
echo "Built: $ROOT.deb"
