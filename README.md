# securiCAD AWS Collector

A Python package for collecting AWS data for use in [foreseeti's securiCAD](https://foreseeti.com/securicad/) products

<!-- Generated with https://github.com/ekalinin/github-markdown-toc -->
## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Quick Start](#quick-start)
* [Collecting AWS Data](#collecting-aws-data)
* [Configuration](#configuration)
   * [Configuring an IAM User](#configuring-an-iam-user)
      * [1. Directly on the Command-Line](#1-directly-on-the-command-line)
      * [2. With a Profile Specified on the Command-Line](#2-with-a-profile-specified-on-the-command-line)
      * [3. With a Configuration File Specified on the Command-Line](#3-with-a-configuration-file-specified-on-the-command-line)
      * [4. From the Environment](#4-from-the-environment)
   * [Configuring an IAM Role](#configuring-an-iam-role)
      * [1. Directly on the Command-Line](#1-directly-on-the-command-line-1)
         * [Assume the Role Yourself](#assume-the-role-yourself)
         * [Let the securiCAD AWS Collector Assume the Role for You](#let-the-securicad-aws-collector-assume-the-role-for-you)
      * [2. With a Profile Specified on the Command-Line](#2-with-a-profile-specified-on-the-command-line-1)
         * [Assume the Role Yourself](#assume-the-role-yourself-1)
         * [Let the securiCAD AWS Collector Assume the Role for You](#let-the-securicad-aws-collector-assume-the-role-for-you-1)
      * [3. With a Configuration File Specified on the Command-Line](#3-with-a-configuration-file-specified-on-the-command-line-1)
         * [Assume the Role Yourself](#assume-the-role-yourself-2)
         * [Let the securiCAD AWS Collector Assume the Role for You](#let-the-securicad-aws-collector-assume-the-role-for-you-2)
      * [4. From the Environment](#4-from-the-environment-1)
         * [Assume the Role Yourself](#assume-the-role-yourself-3)
         * [Let the securiCAD AWS Collector Assume the Role for You](#let-the-securicad-aws-collector-assume-the-role-for-you-3)
* [License](#license)

## Installation

Install `securicad-aws-collector` with pip:

```shell
pip install securicad-aws-collector
```

## Usage

The securiCAD AWS Collector collects environment information from the AWS APIs, and stores the result in a JSON file.
To gain access to the AWS APIs, the securiCAD AWS Collector needs to be configured with the credentials of an IAM user or an IAM role with this [IAM policy](iam_policy.json).
It also needs to be configured with an AWS region to know where to collect environment information from.

## Quick Start

Below are a few examples of how to run the securiCAD AWS Collector.
The script stores the collected data in a file named `aws.json`.
This can be overridden with the command-line argument `--output`.
See the full list of configuration options under [Configuration](#configuration).

* Use credentials of an IAM user and a region:

```shell
securicad-aws-collector --access-key 'ACCESS_KEY' --secret-key 'SECRET_KEY' --region 'REGION'
```

* Use a pre-configured profile from `~/.aws/credentials` or `~/.aws/config`:

```shell
securicad-aws-collector --profile securicad
```

* Use a [configuration file](#configuration):

```shell
securicad-aws-collector --config config.json
```

* Use the default profile to assume an IAM role:

```shell
securicad-aws-collector --role arn:aws:iam::123456789012:role/securicadaccess
```

* Use a specific profile to assume an IAM role:

```shell
securicad-aws-collector --profile securicad --role arn:aws:iam::123456789012:role/securicadaccess
```

## Collecting AWS Data

The securiCAD AWS Collector stores the collected data in a file named `aws.json` by default.
This can be overridden with the command-line argument `--output`:

```shell
securicad-aws-collector --profile securicad --output securicad.json
```

By default, Amazon Inspector findings are not included in the collected data.
Use the command-line argument `--inspector` to include Amazon Inspector findings:

```shell
securicad-aws-collector --profile securicad --inspector
```

Information about other available command-line arguments can be found with the command-line argument `--help`:

```shell
securicad-aws-collector --help
```

## Configuration

The securiCAD AWS Collector can be configured with credentials and region in four ways:

1. Directly on the command-line
2. With a profile specified on the command-line
3. With a configuration file specified on the command-line
4. From the environment

The process is slightly different for IAM users and IAM roles.

### Configuring an IAM User

[Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html) with this [IAM policy](iam_policy.json) and [generate an access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) for the IAM user.

#### 1. Directly on the Command-Line

Configuring credentials directly on the command-line is not recommended, since the keys will be leaked into the process table and the shell's history file.

Pass the credentials of the user directly on the command-line:

```shell
securicad-aws-collector \
  --access-key 'AKIAIOSFODNN7EXAMPLE' \
  --secret-key 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY' \
  --region 'us-east-1'
```

#### 2. With a Profile Specified on the Command-Line

You can configure a profile in `~/.aws/credentials` or `~/.aws/config`.

Example for `~/.aws/credentials`:

```ini
[securicad]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1
```

Example for `~/.aws/config`:

```ini
[profile securicad]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1
```

Specify the profile on the command-line:

```shell
securicad-aws-collector --profile securicad
```

The region in the profile can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector --profile securicad --region us-east-2
```

#### 3. With a Configuration File Specified on the Command-Line

You can configure credentials and region in a JSON file:

```json
{
  "accounts": [
    {
      "access_key": "AKIAIOSFODNN7EXAMPLE",
      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
      "regions": ["us-east-1"]
    }
  ]
}
```

Specify the JSON file on the command-line:

```shell
securicad-aws-collector --config config.json
```

Using a JSON file for configuration allows you to specify multiple accounts and multiple regions per account.

#### 4. From the Environment

If none of the above command-line arguments are used, your environment is searched.

First, the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION` are checked.

If credentials were not found in your environment variables, the profile specified by the environment variable `AWS_PROFILE` is used.
If `AWS_PROFILE` is not set, the default profile is used.

Configure credentials and region in environment variables and run the securiCAD AWS Collector:

```shell
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

securicad-aws-collector
```

The region can be overridden with the command-line argument `--region`:

```shell
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

securicad-aws-collector --region us-east-2
```

Configure credentials and region in the default profile:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1
```

Run the securiCAD AWS Collector:

```shell
securicad-aws-collector
```

The region can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector --region us-east-2
```

### Configuring an IAM Role

[Create an IAM role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html) with this [IAM policy](iam_policy.json).

#### 1. Directly on the Command-Line

Configuring credentials directly on the command-line is not recommended, since the keys will be leaked into the process table and the shell's history file.

You can either assume the role yourself, or let the securiCAD AWS Collector assume the role for you.

##### Assume the Role Yourself

Assume the role:

```shell
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/securicadaccess --role-session-name securicad
```

This will output temporary credentials:

```json
{
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3XFRBF535PLBIFPI4:securicad",
        "Arn": "arn:aws:sts::123456789012:assumed-role/securicadaccess/securicad"
    },
    "Credentials": {
        "SecretAccessKey": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
        "SessionToken": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
        "Expiration": "2016-03-15T00:05:07Z",
        "AccessKeyId": "ASIAJEXAMPLEXEG2JICEA"
    }
}
```

Pass `.Credentials.AccessKeyId`, `.Credentials.SecretAccessKey`, and `.Credentials.SessionToken` directly on the command-line:

```shell
securicad-aws-collector \
  --access-key 'ASIAJEXAMPLEXEG2JICEA' \
  --secret-key '9drTJvcXLB89EXAMPLELB8923FB892xMFI' \
  --session-token 'AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=' \
  --region 'us-east-1'
```

##### Let the securiCAD AWS Collector Assume the Role for You

You need the access key and secret key of an IAM user that can assume the role.

Pass the credentials of the IAM user and the ARN of the role directly on the command-line:

```shell
securicad-aws-collector \
  --access-key 'AKIAIOSFODNN7EXAMPLE' \
  --secret-key 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY' \
  --role 'arn:aws:iam::123456789012:role/securicadaccess' \
  --region 'us-east-1'
```

#### 2. With a Profile Specified on the Command-Line

You can configure a profile in `~/.aws/credentials` or `~/.aws/config`.

Example for `~/.aws/credentials`:

```ini
[securicad-user]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1

[securicad-role1]
aws_access_key_id = ASIAJEXAMPLEXEG2JICEA
aws_secret_access_key = 9drTJvcXLB89EXAMPLELB8923FB892xMFI
aws_session_token = AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=
region = us-east-1
```

Example for `~/.aws/config`:

```ini
[profile securicad-user]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1

[profile securicad-role1]
aws_access_key_id = ASIAJEXAMPLEXEG2JICEA
aws_secret_access_key = 9drTJvcXLB89EXAMPLELB8923FB892xMFI
aws_session_token = AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=
region = us-east-1

[profile securicad-role2]
role_arn = arn:aws:iam::123456789012:role/securicadaccess
source_profile = securicad-user
role_session_name = securicad
region = us-east-1
```

You can either assume the role yourself, or let the securiCAD AWS Collector assume the role for you.

##### Assume the Role Yourself

Assume the role:

```shell
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/securicadaccess --role-session-name securicad
```

This will output temporary credentials:

```json
{
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3XFRBF535PLBIFPI4:securicad",
        "Arn": "arn:aws:sts::123456789012:assumed-role/securicadaccess/securicad"
    },
    "Credentials": {
        "SecretAccessKey": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
        "SessionToken": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
        "Expiration": "2016-03-15T00:05:07Z",
        "AccessKeyId": "ASIAJEXAMPLEXEG2JICEA"
    }
}
```

Store `.Credentials.AccessKeyId`, `.Credentials.SecretAccessKey`, and `.Credentials.SessionToken` in a profile like `securicad-role1` above, and pass the profile on the command-line:

```shell
securicad-aws-collector --profile securicad-role1
```

The region in the profile can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector --profile securicad-role1 --region us-east-2
```

##### Let the securiCAD AWS Collector Assume the Role for You

You need the access key and secret key of an IAM user that can assume the role.

Store the credentials of the IAM user in a profile like `securicad-user` above, and pass the profile and ARN of the role on the command-line:

```shell
securicad-aws-collector \
  --profile securicad-user \
  --role arn:aws:iam::123456789012:role/securicadaccess
```

The region in the profile can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector \
  --profile securicad-user \
  --role arn:aws:iam::123456789012:role/securicadaccess \
  --region us-east-2
```

You can also store the ARN of the role in a profile like `securicad-role2` above, and pass the profile on the command-line:

```shell
securicad-aws-collector --profile securicad-role2
```

The region in the profile can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector --profile securicad-role2 --region us-east-2
```

#### 3. With a Configuration File Specified on the Command-Line

You can configure credentials and region in a JSON file.
Using a JSON file for configuration allows you to specify multiple accounts and multiple regions per account.

You can either assume the role yourself, or let the securiCAD AWS Collector assume the role for you.

##### Assume the Role Yourself

Assume the role:

```shell
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/securicadaccess --role-session-name securicad
```

This will output temporary credentials:

```json
{
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3XFRBF535PLBIFPI4:securicad",
        "Arn": "arn:aws:sts::123456789012:assumed-role/securicadaccess/securicad"
    },
    "Credentials": {
        "SecretAccessKey": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
        "SessionToken": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
        "Expiration": "2016-03-15T00:05:07Z",
        "AccessKeyId": "ASIAJEXAMPLEXEG2JICEA"
    }
}
```

Store `.Credentials.AccessKeyId`, `.Credentials.SecretAccessKey`, and `.Credentials.SessionToken` in a JSON file:

```json
{
  "accounts": [
    {
      "access_key": "ASIAJEXAMPLEXEG2JICEA",
      "secret_key": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
      "session_token": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
      "regions": ["us-east-1"]
    }
  ]
}
```

Specify the JSON file on the command-line:

```shell
securicad-aws-collector --config config.json
```

##### Let the securiCAD AWS Collector Assume the Role for You

You need the access key and secret key of an IAM user that can assume the role.

Store the credentials of the IAM user and the ARN of the role in a JSON file:

```json
{
  "accounts": [
    {
      "access_key": "AKIAIOSFODNN7EXAMPLE",
      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
      "role": "arn:aws:iam::123456789012:role/securicadaccess",
      "regions": ["us-east-1"]
    }
  ]
}
```

Specify the JSON file on the command-line:

```shell
securicad-aws-collector --config config.json
```

#### 4. From the Environment

If none of the above command-line arguments are used, your environment is searched.

First, the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_DEFAULT_REGION` are checked.

If credentials were not found in your environment variables, the profile specified by the environment variable `AWS_PROFILE` is used.
If `AWS_PROFILE` is not set, the default profile is used.

You can either assume the role yourself, or let the securiCAD AWS Collector assume the role for you.

##### Assume the Role Yourself

Assume the role:

```shell
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/securicadaccess --role-session-name securicad
```

This will output temporary credentials:

```json
{
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3XFRBF535PLBIFPI4:securicad",
        "Arn": "arn:aws:sts::123456789012:assumed-role/securicadaccess/securicad"
    },
    "Credentials": {
        "SecretAccessKey": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
        "SessionToken": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
        "Expiration": "2016-03-15T00:05:07Z",
        "AccessKeyId": "ASIAJEXAMPLEXEG2JICEA"
    }
}
```

Store `.Credentials.AccessKeyId`, `.Credentials.SecretAccessKey`, and `.Credentials.SessionToken` in environment variables and run the securiCAD AWS Collector:

```shell
export AWS_ACCESS_KEY_ID="ASIAJEXAMPLEXEG2JICEA"
export AWS_SECRET_ACCESS_KEY="9drTJvcXLB89EXAMPLELB8923FB892xMFI"
export AWS_SESSION_TOKEN="AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
export AWS_DEFAULT_REGION="us-east-1"

securicad-aws-collector
```

The region can be overridden with the command-line argument `--region`:

```shell
export AWS_ACCESS_KEY_ID="ASIAJEXAMPLEXEG2JICEA"
export AWS_SECRET_ACCESS_KEY="9drTJvcXLB89EXAMPLELB8923FB892xMFI"
export AWS_SESSION_TOKEN="AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
export AWS_DEFAULT_REGION="us-east-1"

securicad-aws-collector --region us-east-2
```

Store `.Credentials.AccessKeyId`, `.Credentials.SecretAccessKey`, and `.Credentials.SessionToken` in the default profile:

```ini
[default]
aws_access_key_id = ASIAJEXAMPLEXEG2JICEA
aws_secret_access_key = 9drTJvcXLB89EXAMPLELB8923FB892xMFI
aws_session_token = AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=
region = us-east-1
```

Run the securiCAD AWS Collector:

```shell
securicad-aws-collector
```

The region can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector --region us-east-2
```

##### Let the securiCAD AWS Collector Assume the Role for You

You need the access key and secret key of an IAM user that can assume the role.

Store the credentials of the IAM user in environment variables and pass the ARN of the role on the command-line:

```shell
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

securicad-aws-collector --role arn:aws:iam::123456789012:role/securicadaccess
```

The region can be overridden with the command-line argument `--region`:

```shell
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

securicad-aws-collector --role arn:aws:iam::123456789012:role/securicadaccess --region us-east-2
```

Store the credentials of the IAM user in the default profile:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1
```

Pass the ARN of the role on the command-line:

```shell
securicad-aws-collector --role arn:aws:iam::123456789012:role/securicadaccess
```

The region can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector --role arn:aws:iam::123456789012:role/securicadaccess --region us-east-2
```

## License

Copyright © 2019-2021 [Foreseeti AB](https://foreseeti.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
