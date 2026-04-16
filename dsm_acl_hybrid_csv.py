#!/usr/bin/env python3
import argparse
import csv
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


def q(s):
    import shlex
    return shlex.quote(str(s))


def run(cmd, dry_run=False, check=False):
    if dry_run:
        print("[DRY-RUN] " + " ".join(q(x) for x in cmd))
        return 0
    result = subprocess.run(cmd)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result.returncode


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


def first_existing_group(domain, templates, suffix, variants):
    for tpl in templates:
        for token in variants:
            candidate = tpl.replace("{domain}", domain).replace("{token}", token).replace("{suffix}", suffix)
            if group_exists(candidate):
                return candidate
    return None


def parse_bool(v, default=False):
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "tak"}


def prepare_folder(path, dry_run=False, reset_acl=False, break_inherit=False, create_missing=False):
    p = Path(path)
    if not p.exists():
        if create_missing:
            if dry_run:
                print(f"[DRY-RUN] mkdir -p {q(p)}")
            else:
                p.mkdir(parents=True, exist_ok=True)
        else:
            print(f"Pominięto brakujący katalog: {p}")
            return False
    run(["synoacltool", "-set-archive", str(p), "has_ACL"], dry_run=dry_run)
    run(["synoacltool", "-set-archive", str(p), "is_support_ACL"], dry_run=dry_run)
    if reset_acl:
        run(["synoacltool", "-del", str(p)], dry_run=dry_run)
    if break_inherit:
        run(["synoacltool", "-del-archive", str(p), "is_inherit"], dry_run=dry_run)
    return True


def grant_admins(path, admin_groups, dry_run=False):
    for g in admin_groups:
        if g == "administrators" or group_exists(g):
            run(["synoacltool", "-add", path, f"group:{g}:allow:{PERM_FULL}:{INHERIT_DEFAULT}"], dry_run=dry_run)


def grant_traverse_parents(target, group, dry_run=False, stop_path="/volume1"):
    current = Path(target).parent
    stop = Path(stop_path)
    while str(current) not in ("/", str(stop)):
        run(["synoacltool", "-add", str(current), f"group:{group}:allow:{PERM_TRAVERSE}:{INHERIT_TRAVERSE}"], dry_run=dry_run)
        current = current.parent


def load_mapping(csv_path):
    rows = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            if not row:
                continue
            row = {k.strip(): (v.strip() if v is not None else "") for k, v in row.items()}
            if not any(row.values()):
                continue
            if row.get("enabled", "1").lower() in {"0", "false", "no", "n", "nie"}:
                continue
            rows.append(row)
    return rows


def match_rule(path_str, folder_name, token, rules):
    for rule in rules:
        pattern = rule.get("folder_regex", "")
        if not pattern:
            continue
        if re.search(pattern, folder_name) or re.search(pattern, path_str):
            return rule
    return None


def resolve_groups(rule, path, folder_name, token, domain, templates):
    variants = token_variants(token) if token else []

    def field(name):
        return rule.get(name, "").strip()

    rw_group = field("rw_group")
    ro_group = field("ro_group")
    full_group = field("full_group")

    if not rw_group and parse_bool(field("auto_rw"), True) and token:
        rw_group = first_existing_group(domain, templates, field("rw_suffix") or "T", variants)
    if not ro_group and parse_bool(field("auto_ro"), True) and token:
        ro_group = first_existing_group(domain, templates, field("ro_suffix") or "S", variants)
    if not full_group and parse_bool(field("auto_full"), False) and token:
        full_group = first_existing_group(domain, templates, field("full_suffix") or "A", variants)

    return full_group, rw_group, ro_group


def process_path(path, rules, domain, admin_groups, templates, dry_run=False, default_reset_acl=False,
                 default_break_inherit=False, default_create_missing=False, traverse=True, stop_path="/volume1"):
    folder_name = Path(path).name
    token = extract_token(folder_name)
    rule = match_rule(path, folder_name, token, rules)

    if not rule:
        print(f"Pominięto {path} - brak dopasowanej reguły CSV")
        return

    full_group, rw_group, ro_group = resolve_groups(rule, path, folder_name, token, domain, templates)
    reset_acl = parse_bool(rule.get("reset_acl"), default_reset_acl)
    break_inherit = parse_bool(rule.get("break_inherit"), default_break_inherit)
    create_missing = parse_bool(rule.get("create_missing"), default_create_missing)

    print(f"Folder: {folder_name}")
    print(f"Ścieżka: {path}")
    print(f"Token: {token or 'brak'}")
    print(f"Reguła: {rule.get('rule_name', 'bez nazwy')}")
    print(f"FULL: {full_group or 'brak'}")
    print(f"RW: {rw_group or 'brak'}")
    print(f"RO: {ro_group or 'brak'}")

    if not prepare_folder(path, dry_run=dry_run, reset_acl=reset_acl, break_inherit=break_inherit, create_missing=create_missing):
        return

    grant_admins(path, admin_groups, dry_run=dry_run)

    if full_group:
        run(["synoacltool", "-add", path, f"group:{full_group}:allow:{PERM_FULL}:{INHERIT_DEFAULT}"], dry_run=dry_run)
        if traverse:
            grant_traverse_parents(path, full_group, dry_run=dry_run, stop_path=stop_path)

    if rw_group:
        run(["synoacltool", "-add", path, f"group:{rw_group}:allow:{PERM_RW}:{INHERIT_DEFAULT}"], dry_run=dry_run)
        if traverse:
            grant_traverse_parents(path, rw_group, dry_run=dry_run, stop_path=stop_path)

    if ro_group:
        run(["synoacltool", "-add", path, f"group:{ro_group}:allow:{PERM_RO}:{INHERIT_DEFAULT}"], dry_run=dry_run)
        if traverse:
            grant_traverse_parents(path, ro_group, dry_run=dry_run, stop_path=stop_path)

    run(["synoacltool", "-enforce-inherit", path], dry_run=dry_run)
    run(["synoacltool", "-get", path], dry_run=dry_run)


def main():
    parser = argparse.ArgumentParser(description="Hybrydowe nadawanie ACL na Synology DSM: reguły z CSV + automatyczne dopasowanie grup po nazwie folderu.")
    parser.add_argument("--csv", required=True, help="Plik CSV z regułami mapowania")
    parser.add_argument("paths", nargs="*", help="Ścieżki katalogów do przetworzenia")
    parser.add_argument("--base-dir", default="/volume1/FIRMA/PION", help="Katalog bazowy do skanowania")
    parser.add_argument("--domain", default="FIRMA", help="Prefiks domeny AD")
    parser.add_argument("--dry-run", action="store_true", help="Tylko pokaż komendy")
    parser.add_argument("--reset-acl", action="store_true", help="Domyślne czyszczenie ACL")
    parser.add_argument("--break-inherit", action="store_true", help="Domyślne zerwanie dziedziczenia")
    parser.add_argument("--create-missing", action="store_true", help="Tworzenie brakujących katalogów")
    parser.add_argument("--no-traverse", action="store_true", help="Nie nadawaj traverse na katalogach nadrzędnych")
    parser.add_argument("--stop-path", default="/volume1", help="Najwyższy katalog dla traverse")
    parser.add_argument("--group-template", action="append", default=[], help="Szablon grupy, np. '{domain}\\GRP-S-{token}-{suffix}'")
    args = parser.parse_args()

    if shutil.which("synoacltool") is None:
        print("Brak narzędzia synoacltool w PATH", file=sys.stderr)

    rules = load_mapping(args.csv)
    templates = args.group_template or ["{domain}\\GRP-S-{token}-{suffix}"]
    admin_groups = [
        f"{args.domain}\\Administratorzy domeny",
        f"{args.domain}\\Administratorzy przedsiębiorstwa",
        "administrators",
    ]

    if args.paths:
        targets = args.paths
    else:
        targets = [str(p) for p in sorted(Path(args.base_dir).iterdir()) if p.is_dir()]

    for target in targets:
        process_path(
            target,
            rules,
            args.domain,
            admin_groups,
            templates,
            dry_run=args.dry_run,
            default_reset_acl=args.reset_acl,
            default_break_inherit=args.break_inherit,
            default_create_missing=args.create_missing,
            traverse=not args.no_traverse,
            stop_path=args.stop_path,
        )


if __name__ == "__main__":
    main()
