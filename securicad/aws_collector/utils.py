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

import concurrent.futures
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from boto3.session import Session  # type: ignore
from botocore.client import BaseClient  # type: ignore
from botocore.config import Config  # type: ignore
from botocore.exceptions import ClientError  # type: ignore

from securicad.aws_collector.exceptions import AwsCollectorIOError

if TYPE_CHECKING:
    from typing_extensions import Protocol

    class ClientCallable(Protocol):
        def __call__(self, service_name: str) -> BaseClient:
            ...

    class UnpaginatedCallable(Protocol):
        def __call__(
            self,
            service_name: str,
            operation_name: str,
            param: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
            ...

    class PaginateCallable(Protocol):
        def __call__(
            self,
            service_name: str,
            operation_name: str,
            key: str,
            param: Optional[Dict[str, Any]] = None,
        ) -> List[Any]:
            ...

    class FakePaginateCallable(Protocol):
        def __call__(
            self,
            service_name: str,
            operation_name: str,
            request_key: str,
            response_key: str,
            n: int,
            items: List[Any],
            param: Optional[Dict[str, Any]] = None,
        ) -> List[Any]:
            ...


CLIENT_CONFIG = Config(
    retries={
        "max_attempts": 10,
        "mode": "standard",
    }
)

log = logging.getLogger("securicad-aws-collector")


def get_credentials(account: Dict[str, Any]) -> Optional[Dict[str, str]]:
    credentials: Dict[str, str] = {
        "aws_access_key_id": account["access_key"],
        "aws_secret_access_key": account["secret_key"],
    }
    if "session_token" in account:
        credentials["aws_session_token"] = account["session_token"]
    if "role" in account:
        session = Session(**credentials)
        client = session.client("sts")
        try:
            role = client.assume_role(
                RoleArn=account["role"], RoleSessionName="securicad"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"]["Message"]
            if code in {
                "InvalidClientTokenId",
                "SignatureDoesNotMatch",
                "AccessDenied",
            }:
                log.warning(message)
                return None
            raise
        credentials["aws_access_key_id"] = role["Credentials"]["AccessKeyId"]
        credentials["aws_secret_access_key"] = role["Credentials"]["SecretAccessKey"]
        credentials["aws_session_token"] = role["Credentials"]["SessionToken"]
    return credentials


def is_valid_region(session: Session, region: str) -> bool:
    return region in set(session.get_available_regions("ec2"))


def get_client(
    session: Session, client_lock: Lock, client_cache: Dict[str, BaseClient]
) -> "ClientCallable":
    def client(service_name: str) -> BaseClient:
        with client_lock:
            if service_name not in client_cache:
                client_cache[service_name] = session.client(
                    service_name, config=CLIENT_CONFIG
                )
            return client_cache[service_name]

    return client


def get_unpaginated(
    session: Session, client_lock: Lock, client_cache: Dict[str, BaseClient]
) -> "UnpaginatedCallable":
    _client = get_client(session, client_lock, client_cache)

    def unpaginated(
        service_name: str, operation_name: str, param: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if param is None:
            param = {}
        client = _client(service_name)
        operation = getattr(client, operation_name)
        result = operation(**param)
        if "ResponseMetadata" in result:
            del result["ResponseMetadata"]
        return result

    return unpaginated


def get_paginate(
    session: Session, client_lock: Lock, client_cache: Dict[str, BaseClient]
) -> "PaginateCallable":
    _client = get_client(session, client_lock, client_cache)

    def paginate(
        service_name: str,
        operation_name: str,
        key: str,
        param: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        if param is None:
            param = {}
        client = _client(service_name)
        paginator = client.get_paginator(operation_name)
        page_iterator = paginator.paginate(**param)
        result = []
        for page in page_iterator:
            result.extend(page[key])
        return result

    return paginate


def get_fake_paginate(
    session: Session, client_lock: Lock, client_cache: Dict[str, BaseClient]
) -> "FakePaginateCallable":
    _unpaginated = get_unpaginated(session, client_lock, client_cache)

    def fake_paginate(
        service_name: str,
        operation_name: str,
        request_key: str,
        response_key: str,
        n: int,
        items: List[Any],
        param: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        if param is None:
            param = {}
        head = None
        tail = items
        result = []
        while len(tail) > 0:
            head = tail[:n]
            tail = tail[n:]
            param[request_key] = head
            result.extend(
                _unpaginated(service_name, operation_name, param)[response_key]
            )
        return result

    return fake_paginate


def execute_tasks(
    tasks: List[Callable[[], Tuple[List[str], Any]]], threads: Optional[int]
) -> Optional[Dict[str, Any]]:
    output: Dict[str, Any] = {}
    threads = len(tasks) if threads is None else threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_name = {executor.submit(task): task.__name__ for task in tasks}
        for future in concurrent.futures.as_completed(future_to_name):
            try:
                names, result = future.result()

                if names:
                    obj = output
                    for name in names[:-1]:
                        if name not in obj:
                            obj[name] = {}
                        obj = obj[name]
                    obj[names[-1]] = result
            except ClientError as e:
                name = future_to_name[future]
                code = e.response["Error"]["Code"]
                message = e.response["Error"]["Message"]
                if code in {"InvalidClientTokenId", "SignatureDoesNotMatch"}:
                    log.warning(message)
                    return None
                if code in {
                    "AccessDenied",
                    "UnauthorizedOperation",
                    "AccessDeniedException",
                }:
                    log.warning(f"{name}: {message}")
                    continue
                raise
    return output


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            # TODO: Change to o.isoformat()
            return str(o)
        return super().default(o)


def parse_constant(string: str) -> None:
    raise ValueError(f'Invalid JSON constant "{string}"')


def read_json(path: Path) -> Any:
    try:
        if str(path) == "-":
            return json.load(sys.stdin, parse_constant=parse_constant)
        with path.open(mode="r", encoding="utf-8") as f:
            return json.load(f, parse_constant=parse_constant)
    except OSError as e:
        raise AwsCollectorIOError(str(e)) from e


def write_json(data: Any, path: Path) -> None:
    try:
        if str(path) == "-":
            json.dump(data, sys.stdout, allow_nan=False, indent=2)
            return
        with path.open(mode="w", encoding="utf-8") as f:
            json.dump(data, f, allow_nan=False, indent=2)
    except OSError as e:
        raise AwsCollectorIOError(str(e)) from e
