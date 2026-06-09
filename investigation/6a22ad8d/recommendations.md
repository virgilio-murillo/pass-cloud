# secure-notes-sync-agent: Actionable Recommendations

_Updated: 2026-05-24T21:13:41-06:00_

## 🔴 Fix Now (Confirmed Bug)

### nsync_picker.py is broken — TypeError on every launch

`sync.pull_store()` returns `(dict, etag)` tuple. Picker treats it as a dict.

```bash
# Fix:
sed -i '' 's/remote = sync.pull_store(creds, cfg)/remote, _ = sync.pull_store(creds, cfg)/' \
  ~/work/github/secure-notes-sync/cli/nsync_picker.py
```

Or edit manually: change line `remote = sync.pull_store(creds, cfg)` to `remote, _ = sync.pull_store(creds, cfg)`.

---

## 🟡 Security Concerns

### nsync-gui auto-updates without signature verification

`scripts/nsync-gui` fetches itself from GitHub raw URL and overwrites the local file with no hash check.
**Risk:** GitHub account compromise → all instances auto-update to malicious code with store access.

**Mitigation options:**
1. Disable auto-update: remove `_bg_update_check` thread and `[U]` update handler
2. Add SHA-256 pin: verify `hashlib.sha256(content.encode()).hexdigest()` against known value before writing

### nsync-genpass hardcodes us-west-2

Will fail for users without Bedrock access in us-west-2.

```bash
# Quick fix — set env var before calling:
BEDROCK_REGION=us-east-1 nsync-genpass "16 chars, mixed case, digits, symbols"
```

Permanent fix: replace `region_name="us-west-2"` with `region_name=os.environ.get("BEDROCK_REGION", "us-west-2")` in `scripts/nsync-genpass`.

---

## 🟢 Verify Everything Works

```bash
# Run test suite
cd ~/work/github/secure-notes-sync/cli
pip install -e .
pytest tests/ -v

# Verify CLI
nsync ls
nsync pull

# Verify TUI
nsync-gui

# Verify picker (after bug fix)
python3 ~/work/github/secure-notes-sync/cli/nsync_picker.py
```

---

## 📋 Agent Prompt: What to Add

The current prompt is accurate but missing:

1. **All 5 scripts** and their purposes (nsync-gui, nsync-genpass, nsync-type.sh, pass-nsync.bash, nsync_picker.py)
2. **Stealth naming**: AWS resources use `config-sync-*` prefix
3. **S3 uses SSE-S3** (not KMS) — intentional
4. **Refresh token is 3650 days** for trusted devices
5. **Version history** feature in store (previous values preserved on overwrite)
6. **Test suite** exists: `cli/tests/test_nsync.py` (pytest)
7. **generate-setup.sh** for onboarding new devices
8. **nsync_picker.py bug** (until fixed)
9. **Bedrock dependency** for nsync-genpass

---

## AWS Console Steps (if needed)

**Check Cognito UserPool:**
```
AWS Console → Cognito → User pools → config-sync-users → Sign-in experience → MFA
```
Verify: MFA = Required, TOTP = enabled, SMS = disabled.

**Check S3 bucket:**
```
AWS Console → S3 → config-sync-{account-id} → Properties → Server-side encryption
```
Verify: SSE-S3 (not KMS).

**Check IAM role:**
```
AWS Console → IAM → Roles → config-sync-auth-role → Permissions
```
Verify: S3 policy scoped to `config-sync-{account}` bucket.

**Check pending objects:**
```bash
aws s3 ls s3://config-sync-<ACCOUNT_ID>/pending/ --region <REGION>
```
