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
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import jsonschema  # type: ignore
import typer
from boto3.session import Session  # type: ignore
from botocore.exceptions import ProfileNotFound  # type: ignore
from jsonschema.exceptions import ValidationError  # type: ignore

from securicad.aws_collector import account_collector, schemas, utils
from securicad.aws_collector.exceptions import (
    AwsCollectorError,
    AwsCollectorInputError,
    AwsCredentialsError,
)

__version__ = "0.0.1"

PARSER_VERSION = 8
PARSER_VERSION_FIELD = "parser_version"

log = logging.getLogger("securicad-aws-collector")
app = typer.Typer()


def collect(
    config: Dict[str, Any],
    include_inspector: bool = False,
    threads: Optional[int] = None,
    delay: Optional[float] = None,
    raise_on_access_denied: bool = False,
) -> Dict[str, Any]:

    try:
        jsonschema.validate(instance=config, schema=schemas.get_config_schema())
    except ValidationError as e:
        raise AwsCollectorInputError(f"Invalid config file: {e.message}") from e

    data: Dict[str, Any] = {
        PARSER_VERSION_FIELD: PARSER_VERSION,
        "accounts": [],
    }
    account_ids = set()
    for account in config["accounts"]:
        account_data = account_collector.get_account_data(
            account, threads, delay, raise_on_access_denied
        )
        if account_data is None:
            continue
        if "account_aliases" not in account_data:
            account_data["account_aliases"] = []
        if account_data["account_id"] in account_ids:
            log.warning(
                f'Duplicate AWS Account "{account_data["account_id"]}", {account_data["account_aliases"]}'
            )
            continue
        log.info(
            f'Collecting AWS environment information of account "{account_data["account_id"]}", {account_data["account_aliases"]}'
        )
        account_collector.collect(
            account,
            account_data,
            include_inspector,
            threads,
            delay,
            raise_on_access_denied,
        )
        data["accounts"].append(account_data)
        account_ids.add(account_data["account_id"])
    if not data["accounts"]:
        raise AwsCredentialsError("No valid AWS credentials found")
    log.info("Finished collecting AWS environment information")

    try:
        jsonschema.validate(instance=data, schema=schemas.get_data_schema())
    except ValidationError as e:
        raise ValueError(f"Invalid output data: {e.message}") from e

    return json.loads(
        json.dumps(data, allow_nan=False, cls=utils.CustomJSONEncoder),
        parse_constant=utils.parse_constant,
    )


def init_logging(quiet: bool, verbose: bool) -> None:
    if verbose:
        log.setLevel(logging.DEBUG)
    elif quiet:
        log.setLevel(logging.WARNING)
    else:
        log.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(log.getEffectiveLevel())
    formatter = logging.Formatter(
        fmt="{asctime} - {name} - {levelname} - {message}",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        style="{",
    )
    formatter.converter = time.gmtime  # type: ignore
    handler.setFormatter(formatter)
    log.addHandler(handler)


def get_config_data(
    profile: Optional[str],
    access_key: Optional[str],
    secret_key: Optional[str],
    region: Optional[str],
    config: Optional[Path],
) -> Dict[str, Any]:
    def create_config(
        _access_key: Optional[str], _secret_key: Optional[str], _region: Optional[str]
    ) -> Dict[str, Any]:
        if not _access_key:
            raise AwsCollectorInputError("AWS Access Key has to be set")
        if not _secret_key:
            raise AwsCollectorInputError("AWS Secret Key has to be set")
        if not _region:
            raise AwsCollectorInputError("AWS Region has to be set")
        return {
            "accounts": [
                {
                    "access_key": _access_key,
                    "secret_key": _secret_key,
                    "regions": [_region],
                }
            ]
        }

    def create_config_from_session(session: Session) -> Dict[str, Any]:
        credentials = session.get_credentials()
        if credentials:
            _access_key = credentials.access_key
            _secret_key = credentials.secret_key
            _region = region or session.region_name
        else:
            raise AwsCollectorInputError("No AWS credentials found")
        return create_config(_access_key, _secret_key, _region)

    try:
        if access_key or secret_key:
            return create_config(access_key, secret_key, region)
        if profile:
            return create_config_from_session(Session(profile_name=profile))
        if config:
            return utils.read_json(config)
        return create_config_from_session(Session())
    except ProfileNotFound as e:
        raise AwsCollectorInputError(str(e)) from e


@app.command()
def main(
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p", metavar="PROFILE", help="AWS Profile"
    ),
    access_key: Optional[str] = typer.Option(
        None, "--access-key", "-a", metavar="KEY", help="AWS Access Key"
    ),
    secret_key: Optional[str] = typer.Option(
        None, "--secret-key", "-s", metavar="KEY", help="AWS Secret Key"
    ),
    region: Optional[str] = typer.Option(
        None, "--region", "-r", metavar="REGION", help="AWS Region"
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration File",
        exists=True,
        file_okay=True,
        dir_okay=False,
        writable=False,
        readable=True,
        allow_dash=True,
    ),
    inspector: bool = typer.Option(
        False,
        "--inspector",
        "-i",
        show_default=False,
        help="Include Amazon Inspector",
    ),
    threads: Optional[int] = typer.Option(
        None,
        "--threads",
        "-t",
        metavar="THREADS",
        help="Number of concurrent threads",
    ),
    delay: Optional[float] = typer.Option(
        None,
        "--delay",
        "-d",
        metavar="DELAY",
        help="Seconds of delay before a new API call",
    ),
    output: Path = typer.Option(
        Path("aws.json"),
        "--output",
        "-o",
        help="Output JSON file",
        file_okay=True,
        dir_okay=False,
        writable=True,
        readable=False,
        allow_dash=True,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        show_default=False,
        help="Only print warnings and errors",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        show_default=False,
        help="Print debug information",
    ),
) -> None:
    """
    \b
    Collects AWS environment information from the AWS APIs, and stores the
    result in a JSON file.

    \b
    There are three ways to specify AWS credentials and region:
    1. With the command-line arguments --access-key, --secret-key, and --region
    2. With a profile specified with the command-line argument --profile
    3. With a config file specified with the command-line argument --config

    \b
    If none of the above are specified, the default profile is used.
    The command-line argument --region can also be used with profiles to
    override their default region.
    """
    try:
        init_logging(quiet, verbose)
        config_data = get_config_data(profile, access_key, secret_key, region, config)
        output_data = collect(
            config=config_data,
            include_inspector=inspector,
            threads=threads,
            delay=delay,
        )
        utils.write_json(output_data, output)
        if str(output) != "-":
            log.info(f"Output written to {output}")
    except AwsCollectorError as e:
        sys.exit(f"Error: {e}")
