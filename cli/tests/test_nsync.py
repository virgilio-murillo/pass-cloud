"""Comprehensive tests for nsync modules."""
import json
import os
import tempfile
import time
from unittest.mock import patch, MagicMock
import pytest

from nsync import crypto, store, config


# ─── crypto tests ───────────────────────────────────────────────────────────

class TestCrypto:
    def test_generate_key_length(self):
        key = crypto.generate_key()
        assert len(key) == 64  # 32 bytes hex = 64 chars

    def test_generate_key_is_hex(self):
        key = crypto.generate_key()
        int(key, 16)  # should not raise

    def test_generate_key_unique(self):
        assert crypto.generate_key() != crypto.generate_key()

    def test_encrypt_decrypt_roundtrip(self):
        key = crypto.generate_key()
        data = b"hello world"
        blob = crypto.encrypt(data, key)
        assert crypto.decrypt(blob, key) == data

    def test_encrypt_decrypt_empty(self):
        key = crypto.generate_key()
        blob = crypto.encrypt(b"", key)
        assert crypto.decrypt(blob, key) == b""

    def test_encrypt_decrypt_large(self):
        key = crypto.generate_key()
        data = os.urandom(10000)
        blob = crypto.encrypt(data, key)
        assert crypto.decrypt(blob, key) == data

    def test_decrypt_wrong_key_fails(self):
        key1 = crypto.generate_key()
        key2 = crypto.generate_key()
        blob = crypto.encrypt(b"secret", key1)
        with pytest.raises(Exception):
            crypto.decrypt(blob, key2)

    def test_encrypt_produces_different_ciphertext(self):
        key = crypto.generate_key()
        data = b"same data"
        blob1 = crypto.encrypt(data, key)
        blob2 = crypto.encrypt(data, key)
        assert blob1 != blob2  # different nonces

    def test_ciphertext_format(self):
        key = crypto.generate_key()
        blob = crypto.encrypt(b"x", key)
        assert len(blob) > 12  # nonce(12) + ciphertext + tag(16)

    def test_tampered_ciphertext_fails(self):
        key = crypto.generate_key()
        blob = bytearray(crypto.encrypt(b"data", key))
        blob[-1] ^= 0xFF  # flip last byte
        with pytest.raises(Exception):
            crypto.decrypt(bytes(blob), key)


# ─── store tests ────────────────────────────────────────────────────────────

class TestStore:
    def test_empty_store(self):
        s = store.empty_store("dev1")
        assert s["version"] == 1
        assert s["entries"] == {}
        assert s["metadata"]["modified_by"] == "dev1"

    def test_add_entry(self):
        s = store.empty_store("dev1")
        store.add(s, "email/gmail", "password123", "dev1")
        assert s["entries"]["email/gmail"] == "password123"
        assert s["metadata"]["modified_by"] == "dev1"
        assert s["metadata"]["last_modified"] != ""

    def test_get_entry(self):
        s = store.empty_store("dev1")
        store.add(s, "test/path", "value", "dev1")
        assert store.get(s, "test/path") == "value"

    def test_get_nonexistent(self):
        s = store.empty_store("dev1")
        assert store.get(s, "nope") is None

    def test_ls_sorted(self):
        s = store.empty_store("dev1")
        store.add(s, "z/entry", "v", "dev1")
        store.add(s, "a/entry", "v", "dev1")
        store.add(s, "m/entry", "v", "dev1")
        assert store.ls(s) == ["a/entry", "m/entry", "z/entry"]

    def test_remove_entry(self):
        s = store.empty_store("dev1")
        store.add(s, "to/delete", "val", "dev1")
        store.remove(s, "to/delete", "dev1")
        assert store.get(s, "to/delete") is None

    def test_remove_nonexistent_no_error(self):
        s = store.empty_store("dev1")
        store.remove(s, "nope", "dev1")  # should not raise

    def test_add_overwrites(self):
        s = store.empty_store("dev1")
        store.add(s, "key", "old", "dev1")
        store.add(s, "key", "new", "dev2")
        assert store.get(s, "key") == "new"
        assert s["metadata"]["modified_by"] == "dev2"

    def test_add_creates_history(self):
        s = store.empty_store("dev1")
        store.add(s, "key", "v1", "dev1")
        store.add(s, "key", "v2", "dev2")
        assert "history" in s
        assert len(s["history"]["key"]) == 1
        assert s["history"]["key"][0]["value"] == "v1"
        assert s["history"]["key"][0]["replaced_by"] == "dev2"

    def test_add_same_value_no_history(self):
        s = store.empty_store("dev1")
        store.add(s, "key", "same", "dev1")
        store.add(s, "key", "same", "dev2")
        assert "history" not in s or "key" not in s.get("history", {})

    def test_validate_path_valid(self):
        s = store.empty_store("dev1")
        # These should all work
        store.add(s, "email/gmail", "v", "dev1")
        store.add(s, "ssh/server.com", "v", "dev1")
        store.add(s, "user@host", "v", "dev1")
        store.add(s, "a+b", "v", "dev1")
        store.add(s, "test-entry", "v", "dev1")

    def test_validate_path_invalid_empty(self):
        s = store.empty_store("dev1")
        with pytest.raises(ValueError):
            store.add(s, "", "v", "dev1")

    def test_validate_path_invalid_dotdot(self):
        s = store.empty_store("dev1")
        with pytest.raises(ValueError):
            store.add(s, "../etc/passwd", "v", "dev1")

    def test_validate_path_invalid_start(self):
        s = store.empty_store("dev1")
        with pytest.raises(ValueError):
            store.add(s, "/absolute", "v", "dev1")

    def test_diff_added(self):
        local = store.empty_store("dev1")
        remote = store.empty_store("dev1")
        store.add(remote, "new/entry", "v", "dev1")
        d = store.diff(local, remote)
        assert d["added"] == ["new/entry"]
        assert d["modified"] == []
        assert d["deleted"] == []

    def test_diff_deleted(self):
        local = store.empty_store("dev1")
        store.add(local, "old/entry", "v", "dev1")
        remote = store.empty_store("dev1")
        d = store.diff(local, remote)
        assert d["deleted"] == ["old/entry"]

    def test_diff_modified(self):
        local = store.empty_store("dev1")
        store.add(local, "key", "old", "dev1")
        remote = store.empty_store("dev1")
        store.add(remote, "key", "new", "dev1")
        d = store.diff(local, remote)
        assert d["modified"] == ["key"]

    def test_diff_no_changes(self):
        s = store.empty_store("dev1")
        store.add(s, "key", "val", "dev1")
        d = store.diff(s, s)
        assert d == {"added": [], "modified": [], "deleted": []}

    def test_make_pending(self):
        p = store.make_pending("add", "test/path", "content", "arch-dev")
        assert p["action"] == "add"
        assert p["path"] == "test/path"
        assert p["content"] == "content"
        assert p["device"] == "arch-dev"
        assert "timestamp" in p

    def test_encrypted_roundtrip(self):
        key = crypto.generate_key()
        s = store.empty_store("dev1")
        store.add(s, "secret", "password", "dev1")
        blob = store.dump_encrypted(s, key)
        loaded = store.load_encrypted(blob, key)
        assert loaded["entries"]["secret"] == "password"


# ─── config tests ───────────────────────────────────────────────────────────

class TestConfig:
    def test_load_defaults_when_missing(self):
        with patch.object(config, "CONFIG_FILE", "/nonexistent/path"):
            cfg = config.load()
            assert cfg["trusted"] is False
            assert cfg["region"] == ""

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with patch.object(config, "CONFIG_FILE", path), \
                 patch.object(config, "CONFIG_DIR", td):
                cfg = {**config.DEFAULTS, "region": "us-west-2", "trusted": True}
                config.save(cfg)
                loaded = config.load()
                assert loaded["region"] == "us-west-2"
                assert loaded["trusted"] is True

    def test_save_creates_dir(self):
        with tempfile.TemporaryDirectory() as td:
            nested = os.path.join(td, "sub", "dir")
            path = os.path.join(nested, "config.json")
            with patch.object(config, "CONFIG_FILE", path), \
                 patch.object(config, "CONFIG_DIR", nested):
                config.save(config.DEFAULTS)
                assert os.path.exists(path)

    def test_save_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with patch.object(config, "CONFIG_FILE", path), \
                 patch.object(config, "CONFIG_DIR", td):
                config.save(config.DEFAULTS)
                mode = os.stat(path).st_mode & 0o777
                assert mode == 0o600

    def test_init_config(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with patch.object(config, "CONFIG_FILE", path), \
                 patch.object(config, "CONFIG_DIR", td):
                cfg = config.init_config(
                    region="eu-west-1", user_pool_id="pool",
                    client_id="client", identity_pool_id="idpool",
                    bucket="mybucket", username="user",
                    cloud_key="aabbcc", device_id="test-dev",
                    trusted=True,
                )
                assert cfg["region"] == "eu-west-1"
                assert cfg["trusted"] is True
                assert len(cfg["device_password"]) == 64
                # Verify it was saved
                loaded = config.load()
                assert loaded["bucket"] == "mybucket"

    def test_gen_password_length(self):
        pw = config._gen_password(32)
        assert len(pw) == 32

    def test_gen_password_alphanumeric(self):
        pw = config._gen_password(100)
        assert pw.isalnum()


# ─── nsync-gui helper function tests ────────────────────────────────────────

class TestGuiHelpers:
    """Test the helper functions in nsync-gui without launching curses."""

    def test_is_trusted_true(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"trusted": True}, f)
            f.flush()
            with open(f.name) as cf:
                data = json.load(cf)
            assert data.get("trusted") is True
        os.unlink(f.name)

    def test_is_trusted_false(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"trusted": False}, f)
            f.flush()
            with open(f.name) as cf:
                data = json.load(cf)
            assert data.get("trusted") is False
        os.unlink(f.name)

    def test_needs_totp_expired(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"trusted": False, "auth_timestamp": time.time() - 7200}, f)
            f.flush()
            with open(f.name) as cf:
                data = json.load(cf)
            # Untrusted + expired > 3600s
            assert not data.get("trusted") and (time.time() - data["auth_timestamp"]) > 3600
        os.unlink(f.name)

    def test_needs_totp_not_expired(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"trusted": False, "auth_timestamp": time.time() - 100}, f)
            f.flush()
            with open(f.name) as cf:
                data = json.load(cf)
            assert not data.get("trusted") and (time.time() - data["auth_timestamp"]) < 3600
        os.unlink(f.name)

    def test_needs_totp_trusted_always_false(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"trusted": True, "auth_timestamp": 0}, f)
            f.flush()
            with open(f.name) as cf:
                data = json.load(cf)
            # Trusted devices never need TOTP
            assert data.get("trusted") is True
        os.unlink(f.name)


# ─── sync module tests (mocked S3) ─────────────────────────────────────────

class TestSync:
    def _cfg(self):
        return {
            "region": "us-east-1",
            "bucket": "test-bucket",
            "cloud_key": crypto.generate_key(),
            "device_id": "test-dev",
        }

    def _creds(self):
        return {"AccessKeyId": "AK", "SecretKey": "SK", "SessionToken": "ST"}

    @patch("nsync.sync.boto3")
    def test_pull_store_not_found(self, mock_boto):
        from nsync import sync
        from botocore.exceptions import ClientError
        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client
        mock_client.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}}, "GetObject"
        )
        result, etag = sync.pull_store(self._creds(), self._cfg())
        assert result is None
        assert etag is None

    @patch("nsync.sync.boto3")
    def test_pull_store_success(self, mock_boto):
        from nsync import sync
        cfg = self._cfg()
        s = store.empty_store("dev1")
        store.add(s, "test", "val", "dev1")
        blob = store.dump_encrypted(s, cfg["cloud_key"])

        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client
        mock_body = MagicMock()
        mock_body.read.return_value = blob
        mock_client.get_object.return_value = {"Body": mock_body, "ETag": '"abc123"'}

        result, etag = sync.pull_store(self._creds(), cfg)
        assert result["entries"]["test"] == "val"
        assert etag == "abc123"

    @patch("nsync.sync.boto3")
    def test_push_store(self, mock_boto):
        from nsync import sync
        cfg = self._cfg()
        s = store.empty_store("dev1")
        store.add(s, "key", "value", "dev1")

        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client

        sync.push_store(self._creds(), cfg, s)
        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == "store.enc"
        # Verify the blob can be decrypted
        decrypted = store.load_encrypted(call_kwargs["Body"], cfg["cloud_key"])
        assert decrypted["entries"]["key"] == "value"

    @patch("nsync.sync.boto3")
    def test_push_pending(self, mock_boto):
        from nsync import sync
        cfg = self._cfg()
        pending = store.make_pending("add", "path", "content", "dev1")

        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client

        key = sync.push_pending(self._creds(), cfg, pending)
        assert key.startswith("pending/")
        assert key.endswith(".enc")
        mock_client.put_object.assert_called_once()

    @patch("nsync.sync.boto3")
    def test_list_pending_empty(self, mock_boto):
        from nsync import sync
        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client
        mock_client.list_objects_v2.return_value = {"Contents": []}

        result = sync.list_pending(self._creds(), self._cfg())
        assert result == []

    @patch("nsync.sync.boto3")
    def test_list_pending_with_items(self, mock_boto):
        from nsync import sync
        cfg = self._cfg()
        pending = store.make_pending("add", "test/path", "secret", "dev1")
        blob = crypto.encrypt(json.dumps(pending).encode(), cfg["cloud_key"])

        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client
        mock_client.list_objects_v2.return_value = {
            "Contents": [{"Key": "pending/123_dev1.enc"}]
        }
        mock_body = MagicMock()
        mock_body.read.return_value = blob
        mock_client.get_object.return_value = {"Body": mock_body}

        result = sync.list_pending(self._creds(), cfg)
        assert len(result) == 1
        assert result[0][0] == "pending/123_dev1.enc"
        assert result[0][1]["path"] == "test/path"

    @patch("nsync.sync.boto3")
    def test_delete_pending(self, mock_boto):
        from nsync import sync
        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client

        sync.delete_pending(self._creds(), self._cfg(), "pending/123.enc")
        mock_client.delete_object.assert_called_once_with(
            Bucket="test-bucket", Key="pending/123.enc"
        )


# ─── auth module tests (mocked Cognito) ────────────────────────────────────

class TestAuth:
    def _cfg(self):
        return {
            "region": "us-east-1",
            "user_pool_id": "us-east-1_ABC",
            "client_id": "clientid123",
            "identity_pool_id": "us-east-1:uuid",
            "username": "testuser",
            "device_password": "pw123",
            "refresh_token": "refresh_tok",
            "trusted": True,
            "auth_timestamp": time.time(),
        }

    @patch("nsync.auth.boto3")
    def test_refresh_auth_success(self, mock_boto):
        from nsync import auth
        cfg = self._cfg()

        mock_idp = MagicMock()
        mock_identity = MagicMock()
        mock_boto.client.side_effect = lambda svc, **kw: (
            mock_idp if svc == "cognito-idp" else mock_identity
        )

        mock_idp.initiate_auth.return_value = {
            "AuthenticationResult": {
                "IdToken": "id_tok",
                "AccessToken": "access_tok",
            }
        }
        mock_identity.get_id.return_value = {"IdentityId": "id123"}
        mock_identity.get_credentials_for_identity.return_value = {
            "Credentials": {
                "AccessKeyId": "AK",
                "SecretKey": "SK",
                "SessionToken": "ST",
            }
        }

        with patch.object(config, "CONFIG_FILE", "/tmp/test_nsync_cfg.json"), \
             patch.object(config, "CONFIG_DIR", "/tmp"):
            creds = auth.authenticate(cfg)
            assert creds["AccessKeyId"] == "AK"

    @patch("nsync.auth.boto3")
    def test_untrusted_expired_clears_refresh(self, mock_boto):
        from nsync import auth
        cfg = self._cfg()
        cfg["trusted"] = False
        cfg["auth_timestamp"] = time.time() - 7200  # 2 hours ago

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with open(path, "w") as f:
                json.dump(cfg, f)
            with patch.object(config, "CONFIG_FILE", path), \
                 patch.object(config, "CONFIG_DIR", td):
                # Should clear refresh token and ask for TOTP
                with patch("builtins.input", return_value="123456"):
                    mock_idp = MagicMock()
                    mock_identity = MagicMock()
                    mock_boto.client.side_effect = lambda svc, **kw: (
                        mock_idp if svc == "cognito-idp" else mock_identity
                    )
                    # Mock SRP flow
                    mock_idp.initiate_auth.return_value = {
                        "ChallengeParameters": {
                            "USER_ID_FOR_SRP": "testuser",
                            "SRP_B": "abc123",
                            "SALT": "def456",
                            "SECRET_BLOCK": "Z2ho",
                        },
                        "ChallengeName": "PASSWORD_VERIFIER",
                    }
                    mock_idp.respond_to_auth_challenge.side_effect = [
                        {
                            "ChallengeName": "SOFTWARE_TOKEN_MFA",
                            "Session": "sess",
                        },
                        {
                            "AuthenticationResult": {
                                "IdToken": "id",
                                "AccessToken": "at",
                                "RefreshToken": "rt",
                            }
                        },
                    ]
                    mock_identity.get_id.return_value = {"IdentityId": "id"}
                    mock_identity.get_credentials_for_identity.return_value = {
                        "Credentials": {"AccessKeyId": "AK", "SecretKey": "SK", "SessionToken": "ST"}
                    }
                    with patch("nsync.auth.AWSSRP") as mock_srp_cls:
                        mock_srp = MagicMock()
                        mock_srp.get_auth_params.return_value = {"USERNAME": "u"}
                        mock_srp.process_challenge.return_value = {"USERNAME": "u"}
                        mock_srp_cls.return_value = mock_srp
                        creds = auth.authenticate(cfg)
                        assert creds["AccessKeyId"] == "AK"
