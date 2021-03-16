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

import copy
from typing import Any, Dict

CONFIG_SCHEMA: Dict[str, Any] = {
    "definitions": {
        "nonEmptyString": {
            "type": "string",
            "minLength": 1,
        },
        "nonEmptyStringArray": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/nonEmptyString",
            },
            "minItems": 1,
        },
        "account": {
            "type": "object",
            "properties": {
                "access_key": {
                    "$ref": "#/definitions/nonEmptyString",
                },
                "secret_key": {
                    "$ref": "#/definitions/nonEmptyString",
                },
                "session_token": {
                    "$ref": "#/definitions/nonEmptyString",
                },
                "role": {
                    "$ref": "#/definitions/nonEmptyString",
                },
                "regions": {
                    "$ref": "#/definitions/nonEmptyStringArray",
                },
            },
            "additionalProperties": False,
            "required": [
                "access_key",
                "secret_key",
                "regions",
            ],
        },
        "nonEmptyAccountArray": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/account",
            },
            "minItems": 1,
        },
    },
    "type": "object",
    "properties": {
        "accounts": {
            "$ref": "#/definitions/nonEmptyAccountArray",
        },
    },
    "additionalProperties": False,
    "required": [
        "accounts",
    ],
}

DATA_SCHEMA: Dict[str, Any] = {
    "definitions": {
        "nonEmptyString": {
            "type": "string",
            "minLength": 1,
        },
        "stringArray": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/nonEmptyString",
            },
        },
        "globalServices": {
            "type": "object",
            "properties": {},
            "additionalProperties": True,
            "required": [],
        },
        "regionServices": {
            "type": "object",
            "properties": {
                "region_name": {
                    "$ref": "#/definitions/nonEmptyString",
                },
            },
            "additionalProperties": True,
            "required": [
                "region_name",
            ],
        },
        "nonEmptyRegionServicesArray": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/regionServices",
            },
            "minItems": 1,
        },
        "account": {
            "type": "object",
            "properties": {
                "account_id": {
                    "$ref": "#/definitions/nonEmptyString",
                },
                "account_aliases": {
                    "$ref": "#/definitions/stringArray",
                },
                "global": {
                    "$ref": "#/definitions/globalServices",
                },
                "regions": {
                    "$ref": "#/definitions/nonEmptyRegionServicesArray",
                },
            },
            "additionalProperties": False,
            "required": [
                "account_id",
                "account_aliases",
                "global",
                "regions",
            ],
        },
        "nonEmptyAccountArray": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/account",
            },
            "minItems": 1,
        },
    },
    "type": "object",
    "properties": {
        "accounts": {
            "$ref": "#/definitions/nonEmptyAccountArray",
        },
    },
    "additionalProperties": False,
    "required": [
        "accounts",
    ],
}


def get_config_schema() -> Dict[str, Any]:
    config_schema = copy.deepcopy(CONFIG_SCHEMA)
    return config_schema


def get_data_schema() -> Dict[str, Any]:
    # pylint: disable=import-outside-toplevel, cyclic-import
    from securicad.aws_collector import PARSER_VERSION, PARSER_VERSION_FIELD

    data_schema = copy.deepcopy(DATA_SCHEMA)
    data_schema["properties"][PARSER_VERSION_FIELD] = {"const": PARSER_VERSION}
    data_schema["required"].append(PARSER_VERSION_FIELD)
    return data_schema
