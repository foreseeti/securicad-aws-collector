# Copyright 2019-2021 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

from boto3.session import Session  # type: ignore
from botocore.client import BaseClient  # type: ignore
from botocore.exceptions import ClientError  # type: ignore

from securicad.aws_collector import region_collector, utils
from securicad.aws_collector.exceptions import AwsRegionError

log = logging.getLogger("securicad-aws-collector")


def get_account_data(
    credentials: Dict[str, str], threads: Optional[int]
) -> Optional[Dict[str, Any]]:
    session = Session(**credentials)

    client_lock: Lock = Lock()
    client_cache: Dict[str, BaseClient] = {}
    unpaginated = utils.get_unpaginated(session, client_lock, client_cache)
    paginate = utils.get_paginate(session, client_lock, client_cache)

    tasks: List[Callable[[], Tuple[List[str], Any]]] = []

    def sts_get_caller_identity() -> Tuple[List[str], Any]:
        log.debug("Executing sts get-caller-identity")
        return ["account_id"], unpaginated("sts", "get_caller_identity")["Account"]

    tasks.append(sts_get_caller_identity)

    def iam_list_account_aliases() -> Tuple[List[str], Any]:
        log.debug("Executing iam list-account-aliases")
        return ["account_aliases"], paginate(
            "iam", "list_account_aliases", key="AccountAliases"
        )

    tasks.append(iam_list_account_aliases)

    return utils.execute_tasks(tasks, threads)


def collect(
    credentials: Dict[str, str],
    regions: List[str],
    account_data: Dict[str, Any],
    include_inspector: bool,
    threads: Optional[int],
) -> None:
    session = Session(**credentials)

    account_data["global"] = get_global_data(session, threads)
    account_data["regions"] = []
    region_names = set()
    for region in regions:
        if not utils.is_valid_region(session, region):
            log.warning(f'"{region}" is not a valid AWS Region')
            continue
        if region in region_names:
            log.warning(f'Duplicate AWS Region "{region}"')
            continue
        log.info(f'Collecting AWS environment information of region "{region}"')
        region_data = {"region_name": region}
        region_collector.collect(credentials, region_data, include_inspector, threads)
        account_data["regions"].append(region_data)
        region_names.add(region)
    if not account_data["regions"]:
        raise AwsRegionError("No valid AWS Region found")


def get_global_data(session: Session, threads: Optional[int]) -> Dict[str, Any]:
    client_lock: Lock = Lock()
    client_cache: Dict[str, BaseClient] = {}
    unpaginated = utils.get_unpaginated(session, client_lock, client_cache)
    paginate = utils.get_paginate(session, client_lock, client_cache)

    tasks: List[Callable[[], Tuple[List[str], Any]]] = []

    def iam_list_users() -> Tuple[List[str], Any]:
        log.debug(
            "Executing iam list-virtual-mfa-devices, list-users, list-access-keys, list-attached-user-policies, list-user-policies, get-user-policy, list-groups-for-user, list-mfa-devices, get-login-profile"
        )

        def get_virtual_mfa_devices() -> List[Dict[str, Any]]:
            return paginate("iam", "list_virtual_mfa_devices", key="VirtualMFADevices")

        def get_user_virtual_mfa_devices() -> Dict[str, List[Dict[str, Any]]]:
            virtual_mfa_devices = get_virtual_mfa_devices()
            user_virtual_mfa_devices: Dict[str, List[Dict[str, Any]]] = {}
            for virtual_mfa_device in virtual_mfa_devices:
                if (
                    "User" not in virtual_mfa_device
                    or "UserName" not in virtual_mfa_device["User"]
                ):
                    continue
                user_name = virtual_mfa_device["User"]["UserName"]
                if user_name not in user_virtual_mfa_devices:
                    user_virtual_mfa_devices[user_name] = []
                user_virtual_mfa_devices[user_name].append(virtual_mfa_device)
            return user_virtual_mfa_devices

        def get_access_keys(user_name: str) -> List[Dict[str, Any]]:
            return paginate(
                "iam",
                "list_access_keys",
                key="AccessKeyMetadata",
                param={"UserName": user_name},
            )

        def get_attached_policies(user_name: str) -> List[Dict[str, Any]]:
            return paginate(
                "iam",
                "list_attached_user_policies",
                key="AttachedPolicies",
                param={"UserName": user_name},
            )

        def get_user_policy(user_name: str, policy_name: str) -> Dict[str, Any]:
            return unpaginated(
                "iam",
                "get_user_policy",
                param={"UserName": user_name, "PolicyName": policy_name},
            )

        def get_user_policies(user_name: str) -> List[Dict[str, Any]]:
            policy_names = paginate(
                "iam",
                "list_user_policies",
                key="PolicyNames",
                param={"UserName": user_name},
            )
            return [
                get_user_policy(user_name, policy_name) for policy_name in policy_names
            ]

        def get_groups(user_name: str) -> List[Dict[str, Any]]:
            return paginate(
                "iam",
                "list_groups_for_user",
                key="Groups",
                param={"UserName": user_name},
            )

        def get_mfa_devices(user_name: str) -> List[Dict[str, Any]]:
            return paginate(
                "iam",
                "list_mfa_devices",
                key="MFADevices",
                param={"UserName": user_name},
            )

        def get_login_profile(user_name: str) -> Optional[Dict[str, Any]]:
            try:
                # TODO: Don't wrap result in dict
                return {
                    "LoginProfile": unpaginated(
                        "iam", "get_login_profile", param={"UserName": user_name}
                    )["LoginProfile"]
                }
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    return None
                raise

        user_virtual_mfa_devices = get_user_virtual_mfa_devices()
        users = paginate("iam", "list_users", key="Users")
        for user in users:
            user_name = user["UserName"]
            user["AccessKeyMetadata"] = get_access_keys(user_name)
            user["AttachedPolicies"] = get_attached_policies(user_name)
            user["UserPolicies"] = get_user_policies(user_name)
            user["Groups"] = get_groups(user_name)
            user["MFADevices"] = get_mfa_devices(user_name)
            if user_name in user_virtual_mfa_devices:
                user["VirtualMFADevices"] = user_virtual_mfa_devices[user_name]
            # TODO: Use key "LoginProfile"
            user["HasLoginProfile"] = get_login_profile(user_name)
        return ["iam", "Users"], users

    tasks.append(iam_list_users)

    def iam_list_roles() -> Tuple[List[str], Any]:
        log.debug(
            "Executing iam list-roles, list-attached-role-policies, list-role-policies, get-role-policy"
        )

        def get_attached_policies(role_name: str) -> List[Dict[str, Any]]:
            return paginate(
                "iam",
                "list_attached_role_policies",
                key="AttachedPolicies",
                param={"RoleName": role_name},
            )

        def get_role_policy(role_name: str, policy_name: str) -> Dict[str, Any]:
            return unpaginated(
                "iam",
                "get_role_policy",
                param={"RoleName": role_name, "PolicyName": policy_name},
            )

        def get_role_policies(role_name: str) -> List[Dict[str, Any]]:
            policy_names = paginate(
                "iam",
                "list_role_policies",
                key="PolicyNames",
                param={"RoleName": role_name},
            )
            return [
                get_role_policy(role_name, policy_name) for policy_name in policy_names
            ]

        roles = paginate("iam", "list_roles", key="Roles")
        for role in roles:
            role_name = role["RoleName"]
            role["AttachedPolicies"] = get_attached_policies(role_name)
            role["RolePolicies"] = get_role_policies(role_name)
        return ["iam", "Roles"], roles

    tasks.append(iam_list_roles)

    def iam_list_groups() -> Tuple[List[str], Any]:
        log.debug(
            "Executing iam list-groups, list-attached-group-policies, list-group-policies, get-group-policy"
        )

        def get_attached_policies(group_name: str) -> List[Dict[str, Any]]:
            return paginate(
                "iam",
                "list_attached_group_policies",
                key="AttachedPolicies",
                param={"GroupName": group_name},
            )

        def get_group_policy(group_name: str, policy_name: str) -> Dict[str, Any]:
            return unpaginated(
                "iam",
                "get_group_policy",
                param={"GroupName": group_name, "PolicyName": policy_name},
            )

        def get_group_policies(group_name: str) -> List[Dict[str, Any]]:
            policy_names = paginate(
                "iam",
                "list_group_policies",
                key="PolicyNames",
                param={"GroupName": group_name},
            )
            return [
                get_group_policy(group_name, policy_name)
                for policy_name in policy_names
            ]

        groups = paginate("iam", "list_groups", key="Groups")
        for group in groups:
            group_name = group["GroupName"]
            group["AttachedPolicies"] = get_attached_policies(group_name)
            group["GroupPolicies"] = get_group_policies(group_name)
        return ["iam", "Groups"], groups

    tasks.append(iam_list_groups)

    def iam_list_policies() -> Tuple[List[str], Any]:
        log.debug("Executing iam list-policies, get-policy-version")

        def get_policy_version(policy_arn: str, version_id: str) -> Dict[str, Any]:
            return unpaginated(
                "iam",
                "get_policy_version",
                param={"PolicyArn": policy_arn, "VersionId": version_id},
            )["PolicyVersion"]

        # TODO: Remove OnlyAttached to get all policies?
        policies = paginate(
            "iam", "list_policies", key="Policies", param={"OnlyAttached": True}
        )
        for policy in policies:
            policy_arn = policy["Arn"]
            # TODO: Use list_policy_versions instead to get all policy versions?
            version_id = policy["DefaultVersionId"]
            policy["Statement"] = get_policy_version(policy_arn, version_id)[
                "Document"
            ]["Statement"]
        return ["iam", "Policies"], policies

    tasks.append(iam_list_policies)

    def iam_list_instance_profiles() -> Tuple[List[str], Any]:
        log.debug("Executing iam list-instance-profiles")

        return ["iam", "InstanceProfiles"], paginate(
            "iam", "list_instance_profiles", key="InstanceProfiles"
        )

    tasks.append(iam_list_instance_profiles)

    def s3api_list_buckets() -> Tuple[List[str], Any]:
        log.debug(
            "Executing s3api list-buckets, get-bucket-encryption, get-bucket-policy-status, get-bucket-policy, get-bucket-tagging"
        )

        def get_encryption(bucket_name: str) -> Dict[str, Any]:
            return unpaginated(
                "s3", "get_bucket_encryption", param={"Bucket": bucket_name}
            )["ServerSideEncryptionConfiguration"]

        def get_policy_status(bucket_name: str) -> Dict[str, Any]:
            return unpaginated(
                "s3", "get_bucket_policy_status", param={"Bucket": bucket_name}
            )["PolicyStatus"]

        def get_policy(bucket_name: str) -> Dict[str, Any]:
            return json.loads(
                unpaginated("s3", "get_bucket_policy", param={"Bucket": bucket_name})[
                    "Policy"
                ]
            )

        def get_tagging(bucket_name: str) -> Dict[str, Any]:
            return unpaginated(
                "s3", "get_bucket_tagging", param={"Bucket": bucket_name}
            )["TagSet"]

        buckets = unpaginated("s3", "list_buckets")["Buckets"]
        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                # TODO: Use key "ServerSideEncryptionConfiguration"
                bucket["Encryption"] = get_encryption(bucket_name)
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    != "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    raise
            try:
                # TODO: Use key "PolicyStatus" and don't use "IsPublic"
                bucket["Public"] = get_policy_status(bucket_name)["IsPublic"]
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    raise
                bucket["Public"] = False
            try:
                bucket["Policy"] = get_policy(bucket_name)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    raise
            try:
                # TODO: Use key "TagSet"
                bucket["Tags"] = get_tagging(bucket_name)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchTagSet":
                    raise
        # TODO: Change to ["s3", "Buckets"]
        return ["s3buckets"], buckets

    tasks.append(s3api_list_buckets)

    global_data = utils.execute_tasks(tasks, threads)
    if global_data is None:
        raise RuntimeError("utils.execute_tasks returned None")
    return global_data
