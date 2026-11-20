#!/bin/bash
# Runs in the guest, as root, for the apply_package_updates scenarios of scripts/vm-test.sh
# (P3-AGENT-UPDATES). Test scaffolding only: it builds tiny packages and a local repository, so the
# real upgrade needs no Debian mirror and changes nothing but these packages.
#
#   vm-test-packages.sh build NAME VERSION [POSTINST [CONTROL]]
#                                                       /srv/fvt/debs/NAME_VERSION_all.deb; CONTROL is
#                                                       one more control field, e.g. "Conflicts: x"
#   vm-test-packages.sh publish DEB...                  the local repository lists exactly these
#
# fvt-demo ships /usr/libexec/fvt-demo, a copy of sleep(1) whose bytes differ per version, so a
# service running it uses an old executable once it is upgraded (what needrestart looks for).
#
# For the in-use scenario (FR-2.6, VT-APPLICABILITY): fvt-listen-* ship /usr/libexec/NAME, which listens
# on the TCP address and port it is given; fvt-lib and fvt-idlelib ship a shared library (a copy of
# zlib's) under /usr/lib/fvt whose bytes differ per version; fvt-uselib and fvt-idle ship /usr/libexec/NAME, which maps the given
# file into memory and waits, as a program maps a library.
set -euo pipefail

case ${1:?} in
    build)
        name=${2:?} version=${3:?} postinst=${4:-} control=${5:-}
        d=$(mktemp -d)
        mkdir -p "$d/DEBIAN"
        printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: vm-test <vm-test@example.com>\nDescription: fleet-agent VM test package\n' \
            "$name" "$version" > "$d/DEBIAN/control"
        [ -z "$control" ] || printf '%s\n' "$control" >> "$d/DEBIAN/control"
        if [ "$name" = fvt-demo ]; then
            mkdir -p "$d/usr/libexec"
            cp /usr/bin/sleep "$d/usr/libexec/fvt-demo"
            printf '%s' "$version" >> "$d/usr/libexec/fvt-demo"
        fi
        case $name in
            fvt-listen-*)
                mkdir -p "$d/usr/libexec"
                printf '%s\n' '#!/usr/bin/python3' 'import socket, sys, time' \
                    's = socket.socket(socket.AF_INET, socket.SOCK_STREAM)' \
                    's.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)' \
                    's.bind((sys.argv[1], int(sys.argv[2])))' 's.listen()' 'time.sleep(86400)' > "$d/usr/libexec/$name"
                chmod 0755 "$d/usr/libexec/$name"
                ;;
            fvt-lib | fvt-idlelib)
                # A real shared library (a copy of zlib's), so the scan counts the package as native code.
                mkdir -p "$d/usr/lib/fvt"
                cp "$(readlink -f /usr/lib/x86_64-linux-gnu/libz.so.1)" "$d/usr/lib/fvt/lib$name.so.1"
                printf '%s' "$version" >> "$d/usr/lib/fvt/lib$name.so.1"
                ;;
            fvt-uselib | fvt-idle)
                mkdir -p "$d/usr/libexec"
                printf '%s\n' '#!/usr/bin/python3' 'import mmap, sys, time' \
                    'with open(sys.argv[1], "rb") as f:' '    m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)' \
                    'time.sleep(86400)' > "$d/usr/libexec/$name"
                chmod 0755 "$d/usr/libexec/$name"
                ;;
        esac
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
