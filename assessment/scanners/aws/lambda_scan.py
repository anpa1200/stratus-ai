"""
AWS Lambda scanner — function URLs, resource policies, env var secrets, runtimes, permissions.
"""
import json
import logging
import re
from assessment.scanners.base import BaseScanner
from assessment.config import DEPRECATED_LAMBDA_RUNTIMES

logger = logging.getLogger(__name__)

# Patterns that suggest secrets embedded in environment variables
_SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)


class LambdaScanner(BaseScanner):
    name = "lambda"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        lmb = self.session.client("lambda", region_name=self.region)
        result = {
            "region": self.region,
            "functions": _scan_functions(lmb),
        }
        return result, []


def _scan_functions(lmb) -> list:
    functions = []
    try:
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                fname = fn["FunctionName"]
                info = {
                    "name": fname,
                    "arn": fn["FunctionArn"],
                    "runtime": fn.get("Runtime", ""),
                    "handler": fn.get("Handler", ""),
                    "role": fn.get("Role", ""),
                    "memory_mb": fn.get("MemorySize", 128),
                    "timeout_sec": fn.get("Timeout", 3),
                    "last_modified": fn.get("LastModified", ""),
                    "deprecated_runtime": fn.get("Runtime", "") in DEPRECATED_LAMBDA_RUNTIMES,
                }

                # Check for function URL (publicly accessible HTTP endpoint)
                try:
                    url_resp = lmb.get_function_url_config(FunctionName=fname)
                    info["function_url"] = {
                        "url": url_resp.get("FunctionUrl", ""),
                        "auth_type": url_resp.get("AuthType", ""),
                        "public": url_resp.get("AuthType") == "NONE",
                        "cors": url_resp.get("Cors", {}),
                    }
                except lmb.exceptions.ResourceNotFoundException:
                    info["function_url"] = None
                except Exception:
                    info["function_url"] = None

                # Check resource-based policy for public/cross-account access
                try:
                    pol_resp = lmb.get_policy(FunctionName=fname)
                    policy_doc = json.loads(pol_resp["Policy"])
                    info["resource_policy"] = _analyze_lambda_policy(policy_doc)
                except lmb.exceptions.ResourceNotFoundException:
                    info["resource_policy"] = {"exists": False}
                except Exception as e:
                    info["resource_policy"] = {"error": str(e)}

                # Check environment variables for potential secrets
                try:
                    fn_config = lmb.get_function_configuration(FunctionName=fname)
                    env_vars = fn_config.get("Environment", {}).get("Variables", {})
                    info["env_var_count"] = len(env_vars)
                    # Flag keys that look like secrets (don't log values)
                    suspicious_keys = [k for k in env_vars if _SECRET_PATTERNS.search(k)]
                    info["suspicious_env_vars"] = suspicious_keys
                    info["has_suspicious_env_vars"] = bool(suspicious_keys)
                    # Check encryption
                    info["kms_key_arn"] = fn_config.get("KMSKeyArn", "")
                    info["env_encrypted"] = bool(fn_config.get("KMSKeyArn"))
                except Exception:
                    pass

                # VPC config — functions without VPC can reach internet
                vpc = fn.get("VpcConfig", {})
                info["in_vpc"] = bool(vpc.get("VpcId"))
                info["vpc_id"] = vpc.get("VpcId", "")

                functions.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return functions


def _analyze_lambda_policy(policy_doc: dict) -> dict:
    """Check Lambda resource policy for overly permissive statements."""
    issues = []
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", "")
        # Public access: Principal is * or {"Service": "..."} without condition
        if principal == "*":
            if not stmt.get("Condition"):
                issues.append("Principal: * with no condition — publicly invocable")
        elif isinstance(principal, dict):
            aws_principal = principal.get("AWS", "")
            if aws_principal == "*":
                issues.append("Principal AWS: * — any AWS account can invoke")
    return {
        "exists": True,
        "statement_count": len(policy_doc.get("Statement", [])),
        "issues": issues,
    }
