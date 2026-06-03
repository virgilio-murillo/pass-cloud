#!/usr/bin/env python3
"""nsync — secure notes sync CLI."""
import argparse
import getpass
import os
import subprocess
import sys
import time

from nsync import auth, config, crypto, store, sync


def _get_creds(cfg: dict) -> dict:
    return auth.authenticate(cfg)


def _type_out(text: str) -> None:
    """Simulate typing via OS keystroke injection."""
    import platform, time as _t
    _t.sleep(0.5)  # give user time to focus target field
    if platform.system() == "Darwin":
        # Escape for AppleScript
        escaped = (text.replace("\\", "\\\\")
                       .replace('"', '\\"')
                       .replace("\n", "\\n")
                       .replace("\r", "\\r"))
        subprocess.run(["osascript", "-e",
            f'tell application "System Events" to keystroke "{escaped}"'], check=True)
    else:
        subprocess.run(["xdotool", "type", "--clearmodifiers", text], check=True)


def _clipboard(text: str, seconds: int = 45) -> None:
    """Copy to clipboard, clear after timeout."""
    try:
        p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
        p.communicate(text.encode())
        print(f"Copied to clipboard. Clearing in {seconds}s...")
        time.sleep(seconds)
        subprocess.run(["pbcopy"], input=b"", check=False)
        print("Clipboard cleared.")
    except FileNotFoundError:
        # Not macOS — try xclip
        try:
            p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            p.communicate(text.encode())
            print(f"Copied to clipboard. Clearing in {seconds}s...")
            time.sleep(seconds)
            subprocess.run(["xclip", "-selection", "clipboard"], input=b"", check=False)
            print("Clipboard cleared.")
        except FileNotFoundError:
            print(text)


def cmd_setup(args: argparse.Namespace) -> None:
    """First-time setup: create config, authenticate, cache refresh token."""
    print("=== nsync setup ===")
    region = input("AWS Region: ").strip()
    user_pool_id = input("User Pool ID: ").strip()
    client_id = input("Client ID: ").strip()
    identity_pool_id = input("Identity Pool ID: ").strip()
    bucket = input("Bucket name: ").strip()
    username = input("Cognito username: ").strip()
    device_id = input("Device ID (e.g. arch-trusted, mac-work): ").strip()
    trusted = input("Is this a trusted device? [y/N]: ").strip().lower() == "y"

    cloud_key = input("Cloud key (leave empty to generate new): ").strip()
    if not cloud_key:
        cloud_key = crypto.generate_key()
        print(f"\nGenerated cloud key (save this for other devices):\n{cloud_key}\n")

    cfg = config.init_config(
        region=region, user_pool_id=user_pool_id, client_id=client_id,
        identity_pool_id=identity_pool_id, bucket=bucket, username=username,
        cloud_key=cloud_key, device_id=device_id, trusted=trusted,
    )

    print("\nAuthenticating (you'll need your TOTP code)...")
    totp = input("TOTP code: ").strip()
    creds = auth.authenticate(cfg, totp_code=totp)
    print("✓ Authenticated. Refresh token cached — no TOTP needed next time.")

    # Initialize empty store if none exists
    remote, etag = sync.pull_store(creds, cfg)
    if remote is None:
        st = store.empty_store(cfg["device_id"])
        sync.push_store(creds, cfg, st)
        print("✓ Initialized empty store in S3.")
    else:
        print(f"✓ Found existing store with {len(remote['entries'])} entries.")

    print("✓ Setup complete.")


def _require_cloud_key(cfg: dict) -> None:
    if not cfg.get("cloud_key"):
        sys.exit("No cloud_key configured. Untrusted devices cannot read the store.\n"
                 "Use a trusted device or run 'nsync setup' with the cloud key.")


def cmd_get(args: argparse.Namespace) -> None:
    cfg = config.load()
    _require_cloud_key(cfg)
    creds = _get_creds(cfg)
    remote, etag = sync.pull_store(creds, cfg)
    if remote is None:
        sys.exit("No store found. Run 'nsync setup' first.")
    val = store.get(remote, args.path)
    if val is None:
        sys.exit(f"Entry not found: {args.path}")
    if args.type:
        _type_out(val.split("\n")[0])
    elif args.clip:
        _clipboard(val.split("\n")[0])
    else:
        print(val)


def _edit_content() -> str | None:
    """Open $EDITOR for multiline input. Returns content or None if empty."""
    import tempfile
    editor = os.environ.get("EDITOR", "vim")
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="nsync_")
    os.close(fd)
    os.chmod(path, 0o600)
    try:
        rc = subprocess.call(f'{editor} "{path}"', shell=True)
        if rc != 0:
            return None
        with open(path) as f:
            content = f.read()
        return content.rstrip("\n") if content.strip() else None
    finally:
        os.unlink(path)


def cmd_add(args: argparse.Namespace) -> None:
    cfg = config.load()
    _require_cloud_key(cfg)
    creds = _get_creds(cfg)
    if not sys.stdin.isatty():
        content = sys.stdin.read().strip()
    elif args.edit:
        content = _edit_content()
        if content is None:
            sys.exit("Editor returned empty content — aborted.")
    else:
        content = getpass.getpass("Entry value: ")

    if cfg["trusted"]:
        # Trusted: modify store directly
        remote, etag = sync.pull_store(creds, cfg)
        if remote is None: remote = store.empty_store(cfg["device_id"])
        if store.get(remote, args.path) is not None and not args.force:
            if input(f"'{args.path}' exists. Overwrite? [y/N]: ").strip().lower() != "y":
                return
        store.add(remote, args.path, content, cfg["device_id"])
        sync.push_store(creds, cfg, remote)
        print(f"✓ Added '{args.path}'")
    else:
        # Untrusted: submit as pending
        pending = store.make_pending("add", args.path, content, cfg["device_id"])
        key = sync.push_pending(creds, cfg, pending)
        print(f"✓ Submitted as pending (needs approval on trusted device)")


def cmd_rm(args: argparse.Namespace) -> None:
    cfg = config.load()
    _require_cloud_key(cfg)
    creds = _get_creds(cfg)

    if cfg["trusted"]:
        remote, etag = sync.pull_store(creds, cfg)
        if remote is None or store.get(remote, args.path) is None:
            sys.exit(f"Entry not found: {args.path}")
        store.remove(remote, args.path, cfg["device_id"])
        sync.push_store(creds, cfg, remote)
        print(f"✓ Removed '{args.path}'")
    else:
        pending = store.make_pending("delete", args.path, "", cfg["device_id"])
        sync.push_pending(creds, cfg, pending)
        print(f"✓ Submitted delete as pending (needs approval on trusted device)")


def cmd_ls(args: argparse.Namespace) -> None:
    cfg = config.load()
    _require_cloud_key(cfg)
    creds = _get_creds(cfg)
    remote, etag = sync.pull_store(creds, cfg)
    if remote is None:
        sys.exit("No store found.")
    for path in store.ls(remote):
        print(path)


def cmd_pull(args: argparse.Namespace) -> None:
    """Pull and show diff (trusted devices get approval prompt)."""
    cfg = config.load()
    _require_cloud_key(cfg)
    creds = _get_creds(cfg)
    remote, etag = sync.pull_store(creds, cfg)
    if remote is None:
        print("No remote store found.")
        return
    print(f"Store: {len(remote['entries'])} entries, last modified by {remote['metadata'].get('modified_by', '?')}")
    print(f"  at {remote['metadata'].get('last_modified', '?')}")


def cmd_approve(args: argparse.Namespace) -> None:
    """Review and approve/reject pending changes (trusted only)."""
    cfg = config.load()
    if not cfg["trusted"]:
        sys.exit("Only trusted devices can approve changes.")

    creds = _get_creds(cfg)
    pending_list = sync.list_pending(creds, cfg)
    if not pending_list:
        print("No pending changes.")
        return

    remote, etag = sync.pull_store(creds, cfg)
    if remote is None:
        remote = store.empty_store(cfg["device_id"])

    for s3_key, p in pending_list:
        print(f"\n--- Pending from {p['device']} at {p['timestamp']} ---")
        print(f"  Action: {p['action']}")
        print(f"  Path:   {p['path']}")
        if p["action"] in ("add", "modify"):
            existing = store.get(remote, p["path"])
            if existing:
                print(f"  Current: {existing[:60]}{'...' if len(existing) > 60 else ''}")
            print(f"  New:     {p['content'][:60]}{'...' if len(p['content']) > 60 else ''}")

        choice = input("  Approve? [y/N/q]: ").strip().lower()
        if choice == "q":
            break
        if choice == "y":
            if p["action"] == "add":
                store.add(remote, p["path"], p["content"], cfg["device_id"])
            elif p["action"] == "delete":
                store.remove(remote, p["path"], cfg["device_id"])
            sync.delete_pending(creds, cfg, s3_key)
            print("  ✓ Approved")
        else:
            sync.delete_pending(creds, cfg, s3_key)
            print("  ✗ Rejected")

    sync.push_store(creds, cfg, remote)
    print("\n✓ Store updated.")


def cmd_rotate_key(args: argparse.Namespace) -> None:
    """Generate new cloud key, re-encrypt store."""
    cfg = config.load()
    if not cfg["trusted"]:
        sys.exit("Only trusted devices can rotate keys.")

    creds = _get_creds(cfg)
    remote, etag = sync.pull_store(creds, cfg)
    if remote is None:
        sys.exit("No store found.")

    new_key = crypto.generate_key()
    cfg_new = {**cfg, "cloud_key": new_key}
    sync.push_store(creds, cfg_new, remote)  # push first — if this fails, nothing changes
    cfg["cloud_key"] = new_key
    config.save(cfg)
    print(f"✓ Key rotated. New cloud key:\n{new_key}")
    print("\nUpdate ~/.config/nsync/config.json on all other devices with this key.")


def cmd_import_pass(args: argparse.Namespace) -> None:
    """Import entries from pass (trusted only). Reads ~/.password-store/."""
    import os
    cfg = config.load()
    if not cfg["trusted"]:
        sys.exit("Only trusted devices can import from pass.")

    creds = _get_creds(cfg)
    remote, etag = sync.pull_store(creds, cfg)
    if remote is None: remote = store.empty_store(cfg["device_id"])

    pass_dir = os.environ.get("PASSWORD_STORE_DIR", os.path.expanduser("~/.password-store"))
    if not os.path.isdir(pass_dir):
        sys.exit(f"pass store not found at {pass_dir}")

    count = 0
    for root, _, files in os.walk(pass_dir):
        for f in files:
            if not f.endswith(".gpg"):
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, pass_dir).removesuffix(".gpg")
            try:
                result = subprocess.run(
                    ["gpg", "--quiet", "--yes", "--batch", "--decrypt", full],
                    capture_output=True, text=True, check=True,
                )
                store.add(remote, rel, result.stdout, cfg["device_id"])
                count += 1
            except subprocess.CalledProcessError:
                print(f"  ⚠ Failed to decrypt: {rel}")

    sync.push_store(creds, cfg, remote)
    print(f"✓ Imported {count} entries from pass.")


def main() -> None:
    p = argparse.ArgumentParser(prog="nsync", description="Secure notes sync")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("setup", help="First-time setup")

    g = sub.add_parser("get", help="Get an entry")
    g.add_argument("path", help="Entry path (e.g. email/gmail)")
    g.add_argument("-c", "--clip", action="store_true", help="Copy to clipboard")
    g.add_argument("-t", "--type", action="store_true", help="Type it out (simulate keystrokes)")

    a = sub.add_parser("add", help="Add/update an entry")
    a.add_argument("path", help="Entry path")
    a.add_argument("-f", "--force", action="store_true", help="Overwrite without confirmation")
    a.add_argument("-e", "--edit", action="store_true", help="Open $EDITOR for multiline input")

    r = sub.add_parser("rm", help="Remove an entry")
    r.add_argument("path", help="Entry path")

    sub.add_parser("ls", help="List entries")
    sub.add_parser("pull", help="Pull remote store info")
    sub.add_parser("approve", help="Approve pending changes (trusted only)")
    sub.add_parser("rotate-key", help="Rotate cloud key (trusted only)")
    sub.add_parser("import-pass", help="Import from pass store (trusted only)")

    args = p.parse_args()
    cmds = {
        "setup": cmd_setup, "get": cmd_get, "add": cmd_add, "rm": cmd_rm,
        "ls": cmd_ls, "pull": cmd_pull, "approve": cmd_approve,
        "rotate-key": cmd_rotate_key, "import-pass": cmd_import_pass,
    }
    fn = cmds.get(args.command)
    if fn is None:
        p.print_help()
        sys.exit(1)
    fn(args)


if __name__ == "__main__":
    main()
