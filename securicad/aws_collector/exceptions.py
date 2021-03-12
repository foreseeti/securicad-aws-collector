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


class AwsCollectorError(Exception):
    pass


class AwsCollectorIOError(AwsCollectorError):
    pass


class AwsCollectorInputError(AwsCollectorError):
    pass


class AwsCredentialsError(AwsCollectorError):
    pass


class AwsRegionError(AwsCollectorError):
    pass


class AwsRateLimitError(AwsCollectorError):
    pass
