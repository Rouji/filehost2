#!/usr/bin/env python3
"""Migrate storage layout from files/<4hex>/<uuid> to files/<2hex>/<2hex>/<uuid>.

Leaves a relative symlink at the old path pointing to the new location,
so the running (old) binary keeps working during the transition.

Usage:
    migrate_storage_layout.py [--store PATH] [--apply]

Without --apply only prints what would be done.
"""

import argparse
import os
import re
import sys

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
OLD_DIR_RE = re.compile(r"^[0-9a-f]{4}$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="files", help="store root (default: files)")
    ap.add_argument("--apply", action="store_true", help="actually move files")
    args = ap.parse_args()

    root = args.store.rstrip("/")
    if not os.path.isdir(root):
        sys.exit(f"error: {root} is not a directory")

    moved = skipped = 0
    for dir_entry in os.scandir(root):
        entry = dir_entry.name
        if not OLD_DIR_RE.fullmatch(entry) or not dir_entry.is_dir(follow_symlinks=False):
            continue

        for file_entry in os.scandir(dir_entry.path):
            name = file_entry.name
            old_path = os.path.join(dir_entry.path, name)
            if not UUID_RE.fullmatch(name):
                print(f"skip: unexpected entry {old_path}")
                skipped += 1
                continue

            new_path = os.path.join(root, name[0:2], name[2:4], name)
            if os.path.lexists(new_path):
                print(f"skip: {new_path} already exists")
                skipped += 1
                continue

            print(f"move: {old_path} -> {new_path}")
            if args.apply:
                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                os.rename(old_path, new_path)
                target = os.path.relpath(new_path, dir_entry.path)
                os.symlink(target, old_path)
            moved += 1

        if args.apply:
            try:
                os.rmdir(dir_entry.path)
            except OSError:
                pass  # not empty (non-UUID leftovers)

    verb = "moved" if args.apply else "would move"
    print(f"\n{moved} files {verb}, {skipped} skipped")
    if not args.apply and moved:
        print("run again with --apply to perform the migration")


if __name__ == "__main__":
    main()
