"""S3 push/pull/pending operations."""
import json
import boto3
from botocore.exceptions import ClientError
from nsync import crypto, store


def _s3(creds: dict, region: str):
    return boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"],
    )


def pull_store(creds: dict, cfg: dict) -> tuple[dict | None, str | None]:
    """Download and decrypt store.enc. Returns (store_dict, etag) or (None, None)."""
    try:
        resp = _s3(creds, cfg["region"]).get_object(Bucket=cfg["bucket"], Key="store.enc")
        etag = resp.get("ETag", "").strip('"')
        return store.load_encrypted(resp["Body"].read(), cfg["cloud_key"]), etag
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return None, None
        raise


def push_store(creds: dict, cfg: dict, st: dict) -> None:
    """Encrypt and upload store.enc."""
    blob = store.dump_encrypted(st, cfg["cloud_key"])
    _s3(creds, cfg["region"]).put_object(Bucket=cfg["bucket"], Key="store.enc", Body=blob)


def push_pending(creds: dict, cfg: dict, pending: dict) -> str:
    """Encrypt and upload a pending change. Returns the S3 key."""
    import time
    ts = int(time.time())
    key = f"pending/{ts}_{cfg['device_id']}.enc"
    blob = crypto.encrypt(json.dumps(pending).encode(), cfg["cloud_key"])
    _s3(creds, cfg["region"]).put_object(Bucket=cfg["bucket"], Key=key, Body=blob)
    return key


def list_pending(creds: dict, cfg: dict) -> list[tuple[str, dict]]:
    """List and decrypt all pending changes. Returns [(s3_key, pending_dict), ...]."""
    s3 = _s3(creds, cfg["region"])
    result = []
    try:
        resp = s3.list_objects_v2(Bucket=cfg["bucket"], Prefix="pending/")
        for obj in resp.get("Contents", []):
            data = s3.get_object(Bucket=cfg["bucket"], Key=obj["Key"])["Body"].read()
            pending = json.loads(crypto.decrypt(data, cfg["cloud_key"]))
            result.append((obj["Key"], pending))
    except ClientError:
        pass
    return sorted(result, key=lambda x: x[0])


def delete_pending(creds: dict, cfg: dict, s3_key: str) -> None:
    _s3(creds, cfg["region"]).delete_object(Bucket=cfg["bucket"], Key=s3_key)
