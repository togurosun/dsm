#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PERM_FULL = "rwxpdDaARWcCo"
PERM_RW = "rwxpd-aARWc--"
PERM_RO = "r-x---a-R-c--"
PERM_TRAVERSE = "--x----------"
INHERIT_DEFAULT = "fd--"
INHERIT_TRAVERSE = "---n"
TOKEN_RE = re.compile(r"PRJ_[0-9]{4}[_-][0-9]{2}")


def run(cmd, dry_run=False, check=True):
    if dry_run:
        print("[DRY-RUN] " + " ".join(shlex_quote(x) for x in cmd))
        return 0
    result = subprocess.run(cmd)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result.returncode


def shlex_quote(s):
    import shlex
    return shlex.quote(s)


def group_exists(group):
    if shutil.which("getent"):
        if subprocess.run(["getent", "group", group], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return True
    if shutil.which("wbinfo"):
        if subprocess.run(["wbinfo", f"--group-info={group}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return True
    return False


def extract_token(folder_name):
    m = TOKEN_RE.search(folder_name)
    return m.group(0) if m else None


def token_variants(token):
    variants = []
    for v in (token, token.replace("-", "_"), token.replace("_", "-")):
        if v not in variants:
            variants.append(v)
    return variants


def first_existing_group(domain, suffix, variants):
    for token in variants:
        candidate = f"{domain}\\GRP-S-{token}-{suffix}"
        if group_exists(candidate):
            return candidate
    return None


def prepare_folder(path, dry_run=False, reset_acl=False, break_inherit=False, create_missing=False):
    p = Path(path)
    if not p.exists():
        if create_missing:
            if dry_run:
                print(f"[DRY-RUN] mkdir -p {p}")
            else:
                p.mkdir(parents=True, exist_ok=True)
        else:
            print(f"Pominięto brakujący katalog: {p}")
            return False
    run(["synoacltool", "-set-archive", str(p), "has_ACL"], dry_run=dry_run, check=False)
    run(["synoacltool", "-set-archive", str(p), "is_support_ACL"], dry_run=dry_run, check=False)
    if reset_acl:
        run(["synoacltool", "-del", str(p)], dry_run=dry_run, check=False)
    if break_inherit:
        run(["synoacltool", "-del-archive", str(p), "is_inherit"], dry_run=dry_run, check=False)
    return True


def grant_admins(path, admin_groups, dry_run=False):
    for g in admin_groups:
        if g == "administrators" or group_exists(g):
            run(["synoacltool", "-add", path, f"group:{g}:allow:{PERM_FULL}:{INHERIT_DEFAULT}"], dry_run=dry_run, check=False)


def grant_traverse_parents(target, group, dry_run=False):
    current = Path(target).parent
    while str(current) not in ("/", "/volume1"):
        run(["synoacltool", "-add", str(current), f"group:{group}:allow:{PERM_TRAVERSE}:{INHERIT_TRAVERSE}"], dry_run=dry_run, check=False)
        current = current.parent


def process_path(path, domain, admin_groups, dry_run=False, reset_acl=False, break_inherit=False, create_missing=False):
    folder_name = os.path.basename(path.rstrip("/"))
    token = extract_token(folder_name)
    if not token:
        print(f"Pominięto {path} - brak wzorca PRJ_YYYY_MM lub PRJ_YYYY-MM")
        return

    variants = token_variants(token)
    rw_group = first_existing_group(domain, "T", variants)
    ro_group = first_existing_group(domain, "S", variants)

    print(f"Folder: {folder_name}")
    print(f"Token: {token}")
    print(f"RW: {rw_group or 'brak dopasowanej grupy'}")
    print(f"RO: {ro_group or 'brak dopasowanej grupy'}")

    if not prepare_folder(path, dry_run=dry_run, reset_acl=reset_acl, break_inherit=break_inherit, create_missing=create_missing):
        return

    grant_admins(path, admin_groups, dry_run=dry_run)

    if rw_group:
        run(["synoacltool", "-add", path, f"group:{rw_group}:allow:{PERM_RW}:{INHERIT_DEFAULT}"], dry_run=dry_run, check=False)
        grant_traverse_parents(path, rw_group, dry_run=dry_run)

    if ro_group:
        run(["synoacltool", "-add", path, f"group:{ro_group}:allow:{PERM_RO}:{INHERIT_DEFAULT}"], dry_run=dry_run, check=False)
        grant_traverse_parents(path, ro_group, dry_run=dry_run)

    run(["synoacltool", "-enforce-inherit", path], dry_run=dry_run, check=False)
    run(["synoacltool", "-get", path], dry_run=dry_run, check=False)


def main():
    parser = argparse.ArgumentParser(description="Automatyczne nadawanie ACL na Synology DSM na podstawie nazwy folderu projektu.")
    parser.add_argument("paths", nargs="*", help="Ścieżki katalogów do przetworzenia. Jeśli brak, skanowany jest --base-dir")
    parser.add_argument("--base-dir", default="/volume1/FIRMA/PION", help="Katalog bazowy do skanowania")
    parser.add_argument("--domain", default="FIRMA", help="Prefiks domeny AD")
    parser.add_argument("--dry-run", action="store_true", help="Pokaż komendy bez wykonywania")
    parser.add_argument("--reset-acl", action="store_true", help="Usuń istniejące ACL na katalogu docelowym")
    parser.add_argument("--break-inherit", action="store_true", help="Usuń bit is_inherit na katalogu docelowym")
    parser.add_argument("--create-missing", action="store_true", help="Twórz brakujące katalogi")
    args = parser.parse_args()

    admin_groups = [
        f"{args.domain}\\Administratorzy domeny",
        f"{args.domain}\\Administratorzy przedsiębiorstwa",
        "administrators",
    ]

    if args.paths:
        for p in args.paths:
            process_path(p, args.domain, admin_groups, dry_run=args.dry_run, reset_acl=args.reset_acl, break_inherit=args.break_inherit, create_missing=args.create_missing)
    else:
        for entry in sorted(Path(args.base_dir).iterdir()):
            if entry.is_dir():
                process_path(str(entry), args.domain, admin_groups, dry_run=args.dry_run, reset_acl=args.reset_acl, break_inherit=args.break_inherit, create_missing=args.create_missing)


if __name__ == "__main__":
    if shutil.which("synoacltool") is None:
        print("Brak narzędzia synoacltool w PATH", file=sys.stderr)
    main()
