#!/bin/bash
# Runs in the guest, as root, for the apply_package_updates scenarios of scripts/vm-test.sh
# (P3-AGENT-UPDATES). Test scaffolding only: it builds tiny packages and a local repository, so the
# real upgrade needs no Debian mirror and changes nothing but these packages.
#
#   vm-test-packages.sh build NAME VERSION [POSTINST]   /srv/fvt/debs/NAME_VERSION_all.deb
#   vm-test-packages.sh publish DEB...                  the local repository lists exactly these
#
# fvt-demo ships /usr/libexec/fvt-demo, a copy of sleep(1) whose bytes differ per version, so a
# service running it uses an old executable once it is upgraded (what needrestart looks for).
set -euo pipefail

case ${1:?} in
    build)
        name=${2:?} version=${3:?} postinst=${4:-}
        d=$(mktemp -d)
        mkdir -p "$d/DEBIAN"
        printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: vm-test <vm-test@example.com>\nDescription: fleet-agent VM test package\n' \
            "$name" "$version" > "$d/DEBIAN/control"
        if [ "$name" = fvt-demo ]; then
            mkdir -p "$d/usr/libexec"
            cp /usr/bin/sleep "$d/usr/libexec/fvt-demo"
            printf '%s' "$version" >> "$d/usr/libexec/fvt-demo"
        fi
        if [ -n "$postinst" ]; then
            printf '#!/bin/sh\nset -e\n%s\n' "$postinst" > "$d/DEBIAN/postinst"
            chmod 0755 "$d/DEBIAN/postinst"
        fi
        mkdir -p /srv/fvt/debs
        dpkg-deb --root-owner-group --build "$d" "/srv/fvt/debs/${name}_${version}_all.deb" > /dev/null
        rm -rf "$d"
        ;;
    publish)
        shift
        rm -rf /srv/fvt/repo
        mkdir -p /srv/fvt/repo
        for deb in "$@"; do
            cp "/srv/fvt/debs/$deb" /srv/fvt/repo/
            {
                dpkg-deb -f "/srv/fvt/repo/$deb"
                echo "Filename: ./$deb"
                echo "Size: $(stat -c %s "/srv/fvt/repo/$deb")"
                echo "SHA256: $(sha256sum "/srv/fvt/repo/$deb" | cut -d' ' -f1)"
                echo
            } >> /srv/fvt/repo/Packages
        done
        chmod -R a+rX /srv/fvt
        ;;
    *)
        echo "usage: vm-test-packages.sh build|publish ..." >&2
        exit 2
        ;;
esac
