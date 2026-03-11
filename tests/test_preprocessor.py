"""
Unit tests for assessment/ai/preprocessor.py

No AWS credentials or API keys required — pure unit tests.
"""
import pytest
from assessment.ai.preprocessor import preprocess


# ─── IAM preprocessor ────────────────────────────────────────────────────────

class TestIAMPreprocessor:
    def _user(self, **kwargs):
        base = {
            "username": "testuser",
            "arn": "arn:aws:iam::123456789012:user/testuser",
            "created": "2022-01-01",
            "password_last_used": "2024-01-01",
            "mfa_enabled": True,
            "access_keys": [],
            "attached_policies": [],
            "inline_policies": [],
            "groups": [],
        }
        base.update(kwargs)
        return base

    def test_clean_user_not_flagged(self):
        raw = {
            "account_summary": {"users": 1},
            "password_policy": {"minimum_password_length": 14},
            "root_account": {"mfa_active": True},
            "users": [self._user()],
            "roles_with_star_policies": [],
            "attached_admin_policies": [],
        }
        result = preprocess("iam", raw)
        assert result["total_users"] == 1
        assert result["flagged_users"] == []

    def test_user_without_mfa_flagged(self):
        raw = {
            "account_summary": {},
            "password_policy": {},
            "root_account": {},
            "users": [self._user(mfa_enabled=False)],
            "roles_with_star_policies": [],
            "attached_admin_policies": [],
        }
        result = preprocess("iam", raw)
        assert len(result["flagged_users"]) == 1
        assert "no MFA" in result["flagged_users"][0]["_issues"]

    def test_user_with_stale_key_flagged(self):
        raw = {
            "account_summary": {},
            "password_policy": {},
            "root_account": {},
            "users": [self._user(
                mfa_enabled=True,
                access_keys=[{"key_id": "AKIA****", "status": "Active", "age_days": 95, "stale": True, "critical_age": False}]
            )],
            "roles_with_star_policies": [],
            "attached_admin_policies": [],
        }
        result = preprocess("iam", raw)
        assert len(result["flagged_users"]) == 1
        assert any("stale" in issue for issue in result["flagged_users"][0]["_issues"])

    def test_user_with_critical_key_flagged(self):
        raw = {
            "account_summary": {},
            "password_policy": {},
            "root_account": {},
            "users": [self._user(
                mfa_enabled=True,
                access_keys=[{"key_id": "AKIA****", "status": "Active", "age_days": 200, "stale": True, "critical_age": True}]
            )],
            "roles_with_star_policies": [],
            "attached_admin_policies": [],
        }
        result = preprocess("iam", raw)
        assert len(result["flagged_users"]) == 1
        assert any("CRITICAL" in issue for issue in result["flagged_users"][0]["_issues"])

    def test_user_with_admin_policy_flagged(self):
        raw = {
            "account_summary": {},
            "password_policy": {},
            "root_account": {},
            "users": [self._user(
                mfa_enabled=True,
                attached_policies=["arn:aws:iam::aws:policy/AdministratorAccess"]
            )],
            "roles_with_star_policies": [],
            "attached_admin_policies": [],
        }
        result = preprocess("iam", raw)
        assert len(result["flagged_users"]) == 1
        assert any("AdministratorAccess" in issue for issue in result["flagged_users"][0]["_issues"])

    def test_multiple_users_partial_flagging(self):
        raw = {
            "account_summary": {},
            "password_policy": {},
            "root_account": {},
            "users": [
                self._user(username="good"),
                self._user(username="bad", mfa_enabled=False),
            ],
            "roles_with_star_policies": [],
            "attached_admin_policies": [],
        }
        result = preprocess("iam", raw)
        assert result["total_users"] == 2
        assert len(result["flagged_users"]) == 1
        assert result["flagged_users"][0]["username"] == "bad"


# ─── S3 preprocessor ─────────────────────────────────────────────────────────

class TestS3Preprocessor:
    def _bucket(self, **kwargs):
        base = {
            "name": "test-bucket",
            "region": "us-east-1",
            "all_public_access_blocked": True,
            "acl_public_read": False,
            "acl_public_write": False,
            "policy_allows_public": False,
            "encryption": "AES256",
            "versioning": "Enabled",
            "logging_enabled": True,
        }
        base.update(kwargs)
        return base

    def test_clean_bucket_not_flagged(self):
        raw = {
            "account_public_access_block": {"block_public_acls": True},
            "buckets": [self._bucket()],
        }
        result = preprocess("s3", raw)
        assert result["total_buckets"] == 1
        assert result["flagged_buckets"] == []
        assert result["clean_bucket_count"] == 1

    def test_public_acl_read_flagged(self):
        raw = {
            "account_public_access_block": {},
            "buckets": [self._bucket(acl_public_read=True)],
        }
        result = preprocess("s3", raw)
        assert len(result["flagged_buckets"]) == 1
        assert "public ACL read" in result["flagged_buckets"][0]["_issues"]

    def test_unencrypted_bucket_flagged(self):
        raw = {
            "account_public_access_block": {},
            "buckets": [self._bucket(encryption="none")],
        }
        result = preprocess("s3", raw)
        assert len(result["flagged_buckets"]) == 1
        assert any("encryption" in i for i in result["flagged_buckets"][0]["_issues"])

    def test_policy_summary_removed_from_flagged(self):
        bucket = self._bucket(policy_allows_public=True)
        bucket["bucket_policy_summary"] = [{"effect": "Allow", "principal": "*"}]
        raw = {"account_public_access_block": {}, "buckets": [bucket]}
        result = preprocess("s3", raw)
        assert "bucket_policy_summary" not in result["flagged_buckets"][0]

    def test_count_tracking(self):
        raw = {
            "account_public_access_block": {},
            "buckets": [
                self._bucket(name="good"),
                self._bucket(name="bad", encryption="none"),
                self._bucket(name="also-bad", acl_public_read=True),
            ],
        }
        result = preprocess("s3", raw)
        assert result["total_buckets"] == 3
        assert len(result["flagged_buckets"]) == 2
        assert result["clean_bucket_count"] == 1


# ─── EC2 preprocessor ────────────────────────────────────────────────────────

class TestEC2Preprocessor:
    def test_risky_sg_included(self):
        raw = {
            "region": "us-east-1",
            "security_groups": [
                {"group_id": "sg-bad", "inbound_open_to_world": [{"port": "22", "cidr": "0.0.0.0/0"}], "inbound_sensitive_ports_open": ["port 22 (SSH)"]},
                {"group_id": "sg-good", "inbound_open_to_world": [], "inbound_sensitive_ports_open": []},
            ],
            "instances": [],
            "public_snapshots": [],
            "ebs_encryption_default": {"enabled": True},
            "vpc_summary": [],
        }
        result = preprocess("ec2", raw)
        assert result["total_security_groups"] == 2
        assert len(result["risky_security_groups"]) == 1
        assert result["risky_security_groups"][0]["group_id"] == "sg-bad"

    def test_imdsv2_missing_flags_instance(self):
        raw = {
            "region": "us-east-1",
            "security_groups": [],
            "instances": [{
                "instance_id": "i-abc",
                "imdsv2_required": False,
                "unencrypted_volumes": [],
                "issues": [],
            }],
            "public_snapshots": [],
            "ebs_encryption_default": {},
            "vpc_summary": [],
        }
        result = preprocess("ec2", raw)
        assert len(result["flagged_instances"]) == 1
        assert any("IMDSv2" in i for i in result["flagged_instances"][0]["_issues"])

    def test_clean_instance_not_flagged(self):
        raw = {
            "region": "us-east-1",
            "security_groups": [],
            "instances": [{
                "instance_id": "i-good",
                "imdsv2_required": True,
                "unencrypted_volumes": [],
                "issues": [],
            }],
            "public_snapshots": [],
            "ebs_encryption_default": {},
            "vpc_summary": [],
        }
        result = preprocess("ec2", raw)
        assert result["flagged_instances"] == []
        assert result["total_instances"] == 1


# ─── Lambda preprocessor ─────────────────────────────────────────────────────

class TestLambdaPreprocessor:
    def _fn(self, **kwargs):
        base = {
            "name": "my-function",
            "arn": "arn:aws:lambda:us-east-1:123:function:my-function",
            "runtime": "python3.11",
            "deprecated_runtime": False,
            "function_url": None,
            "resource_policy": {"exists": False},
            "has_suspicious_env_vars": False,
            "suspicious_env_vars": [],
            "env_var_count": 0,
            "env_encrypted": False,
        }
        base.update(kwargs)
        return base

    def test_clean_function_not_flagged(self):
        raw = {"region": "us-east-1", "functions": [self._fn()]}
        result = preprocess("lambda", raw)
        assert result["flagged_functions"] == []
        assert result["clean_function_count"] == 1

    def test_deprecated_runtime_flagged(self):
        raw = {"region": "us-east-1", "functions": [self._fn(runtime="python3.6", deprecated_runtime=True)]}
        result = preprocess("lambda", raw)
        assert len(result["flagged_functions"]) == 1
        assert any("deprecated runtime" in i for i in result["flagged_functions"][0]["_issues"])

    def test_public_function_url_flagged(self):
        raw = {
            "region": "us-east-1",
            "functions": [self._fn(function_url={"public": True, "url": "https://abc.lambda-url.us-east-1.on.aws/", "auth_type": "NONE"})]
        }
        result = preprocess("lambda", raw)
        assert len(result["flagged_functions"]) == 1
        assert any("public function URL" in i for i in result["flagged_functions"][0]["_issues"])

    def test_suspicious_env_vars_flagged(self):
        raw = {
            "region": "us-east-1",
            "functions": [self._fn(
                has_suspicious_env_vars=True,
                suspicious_env_vars=["DB_PASSWORD"],
                env_var_count=3,
                env_encrypted=False,
            )]
        }
        result = preprocess("lambda", raw)
        assert len(result["flagged_functions"]) == 1
        issues = result["flagged_functions"][0]["_issues"]
        assert any("suspicious env vars" in i for i in issues)


# ─── KMS preprocessor ────────────────────────────────────────────────────────

class TestKMSPreprocessor:
    def _key(self, **kwargs):
        base = {
            "key_id": "mrk-abc123",
            "arn": "arn:aws:kms:us-east-1:123:key/abc123",
            "enabled": True,
            "key_state": "Enabled",
            "deletion_pending": False,
            "rotation_enabled": True,
            "policy_analysis": {"statement_count": 1, "issues": []},
        }
        base.update(kwargs)
        return base

    def test_clean_key_not_flagged(self):
        raw = {"region": "us-east-1", "keys": [self._key()]}
        result = preprocess("kms", raw)
        assert result["flagged_keys"] == []
        assert result["clean_key_count"] == 1

    def test_rotation_disabled_flagged(self):
        raw = {"region": "us-east-1", "keys": [self._key(rotation_enabled=False)]}
        result = preprocess("kms", raw)
        assert len(result["flagged_keys"]) == 1
        assert any("rotation" in i for i in result["flagged_keys"][0]["_issues"])

    def test_deletion_pending_flagged(self):
        raw = {"region": "us-east-1", "keys": [self._key(deletion_pending=True, deletion_date="2025-01-01")]}
        result = preprocess("kms", raw)
        assert len(result["flagged_keys"]) == 1
        assert any("deletion" in i for i in result["flagged_keys"][0]["_issues"])

    def test_public_key_policy_flagged(self):
        raw = {
            "region": "us-east-1",
            "keys": [self._key(policy_analysis={"issues": ["Principal * — key is publicly accessible"]})]
        }
        result = preprocess("kms", raw)
        assert len(result["flagged_keys"]) == 1


# ─── EKS preprocessor ────────────────────────────────────────────────────────

class TestEKSPreprocessor:
    def _cluster(self, **kwargs):
        base = {
            "name": "prod-cluster",
            "kubernetes_version": "1.29",
            "deprecated_version": False,
            "endpoint_open_to_world": False,
            "public_access_cidrs": ["10.0.0.0/8"],
            "logging": {"audit_logging": True, "api_logging": True},
            "secrets_encryption": {"enabled": True},
        }
        base.update(kwargs)
        return base

    def test_clean_cluster_not_flagged(self):
        raw = {"region": "us-east-1", "clusters": [self._cluster()]}
        result = preprocess("eks", raw)
        assert result["flagged_clusters"] == []
        assert result["clean_cluster_count"] == 1

    def test_public_endpoint_flagged(self):
        raw = {"region": "us-east-1", "clusters": [self._cluster(endpoint_open_to_world=True, public_access_cidrs=["0.0.0.0/0"])]}
        result = preprocess("eks", raw)
        assert len(result["flagged_clusters"]) == 1
        assert any("endpoint public" in i for i in result["flagged_clusters"][0]["_issues"])

    def test_audit_logging_disabled_flagged(self):
        raw = {"region": "us-east-1", "clusters": [
            self._cluster(logging={"audit_logging": False, "api_logging": True})
        ]}
        result = preprocess("eks", raw)
        assert len(result["flagged_clusters"]) == 1
        assert any("audit" in i for i in result["flagged_clusters"][0]["_issues"])

    def test_secrets_not_encrypted_flagged(self):
        raw = {"region": "us-east-1", "clusters": [
            self._cluster(secrets_encryption={"enabled": False})
        ]}
        result = preprocess("eks", raw)
        assert len(result["flagged_clusters"]) == 1

    def test_deprecated_k8s_version_flagged(self):
        raw = {"region": "us-east-1", "clusters": [
            self._cluster(deprecated_version=True, kubernetes_version="1.24")
        ]}
        result = preprocess("eks", raw)
        assert len(result["flagged_clusters"]) == 1
        assert any("deprecated" in i for i in result["flagged_clusters"][0]["_issues"])


# ─── SecretsManager preprocessor ─────────────────────────────────────────────

class TestSecretsManagerPreprocessor:
    def _secret(self, **kwargs):
        base = {
            "name": "prod/db/password",
            "arn": "arn:aws:secretsmanager:us-east-1:123:secret:prod/db/password",
            "rotation_enabled": True,
            "rotation_overdue": False,
            "days_since_rotation": 30,
            "uses_default_kms": False,
            "resource_policy": {"exists": False},
            "tags": {},
        }
        base.update(kwargs)
        return base

    def test_clean_secret_not_flagged(self):
        raw = {"region": "us-east-1", "secrets": [self._secret()]}
        result = preprocess("secrets_manager", raw)
        assert result["flagged_secrets"] == []
        assert result["clean_secret_count"] == 1

    def test_rotation_disabled_flagged(self):
        raw = {"region": "us-east-1", "secrets": [self._secret(rotation_enabled=False)]}
        result = preprocess("secrets_manager", raw)
        assert len(result["flagged_secrets"]) == 1
        assert any("rotation not enabled" in i for i in result["flagged_secrets"][0]["_issues"])

    def test_rotation_overdue_flagged(self):
        raw = {"region": "us-east-1", "secrets": [
            self._secret(rotation_enabled=True, rotation_overdue=True, days_since_rotation=120)
        ]}
        result = preprocess("secrets_manager", raw)
        assert len(result["flagged_secrets"]) == 1
        assert any("overdue" in i for i in result["flagged_secrets"][0]["_issues"])

    def test_default_kms_flagged(self):
        raw = {"region": "us-east-1", "secrets": [self._secret(uses_default_kms=True)]}
        result = preprocess("secrets_manager", raw)
        assert len(result["flagged_secrets"]) == 1

    def test_tags_removed_from_flagged(self):
        secret = self._secret(rotation_enabled=False, tags={"Env": "prod", "Owner": "alice"})
        raw = {"region": "us-east-1", "secrets": [secret]}
        result = preprocess("secrets_manager", raw)
        assert "tags" not in result["flagged_secrets"][0]


# ─── Ports preprocessor ──────────────────────────────────────────────────────

class TestPortsPreprocessor:
    def test_open_ports_extracted(self):
        raw = {
            "target": "example.com",
            "nmap_result": {
                "target": "example.com",
                "open_ports": [
                    {"protocol": "tcp", "port": 80, "service": "http"},
                    {"protocol": "tcp", "port": 443, "service": "https"},
                ],
            }
        }
        result = preprocess("ports", raw)
        assert result["target"] == "example.com"
        assert len(result["open_ports"]) == 2
        assert "nmap_error" not in result

    def test_nmap_error_preserved(self):
        raw = {
            "target": "dead.example.com",
            "nmap_result": {"error": "nmap timeout", "open_ports": []},
        }
        result = preprocess("ports", raw)
        assert result["nmap_error"] == "nmap timeout"


# ─── Unknown module passthrough ───────────────────────────────────────────────

class TestPassthrough:
    def test_unknown_module_returns_raw(self):
        raw = {"some": "data", "nested": {"key": "value"}}
        result = preprocess("nonexistent_module", raw)
        assert result == raw

    def test_empty_dict_safe(self):
        result = preprocess("iam", {})
        assert isinstance(result, dict)
        assert "flagged_users" in result
        assert result["total_users"] == 0
