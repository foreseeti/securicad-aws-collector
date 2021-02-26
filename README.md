# securiCAD AWS Collector

A Python package for collecting AWS data for use in [foreseeti's securiCAD](https://foreseeti.com/securicad/) products

## Getting started

### Installation

Install `securicad-aws-collector` with pip:

```shell
pip install securicad-aws-collector
```

### Get the required AWS credentials

The securiCAD AWS Collector requires AWS credentials to be able to fetch data from AWS.
The easiest way is to create an IAM User with the required permissions and generate access keys for that IAM User:

* [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html) with this [IAM policy](iam_policy.json)
* [Generate access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) for the IAM user

### Configuration

The securiCAD AWS Collector needs to be configured with credentials and region to be able to fetch data from AWS.
You can configure these in a few different ways:

#### 1. With the command-line arguments `--access-key`, `--secret-key`, and `--region`

Credentials and region can be passed directly on the command-line:

```shell
securicad-aws-collector \
  --access-key 'AKIAIOSFODNN7EXAMPLE' \
  --secret-key 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  --region 'us-east-1'
```

This is not recommended, since the keys will be leaked into the process table and the shell's history file.

#### 2. With a profile specified with the command-line argument `--profile`

You can configure a profile in `~/.aws/credentials` or `~/.aws/config`.

Example for `~/.aws/credentials`:

```
[securicad]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
```

Example for `~/.aws/config`:

```
[profile securicad]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
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

#### 3. With a config file specified with the command-line argument `--config`

You can also configure credentials and region with a JSON file, e.g.

```json
{
  "accounts": [
    {
      "access_key": "AKIAIOSFODNN7EXAMPLE",
      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
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

#### 4. From the environment

If none of the above command-line arguments are used, your environment is searched.

First, the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_DEFAULT_REGION` are checked.
`AWS_SESSION_TOKEN` is only needed when you are using temporary credentials, and `AWS_DEFAULT_REGION` can be overridden with the command-line argument `--region`.

If credentials were not found in your environment variables, the default profile in `~/.aws/credentials` or `~/.aws/config` is used.

### Collecting AWS data

The securiCAD AWS Collector stores the collected data in a file `aws.json` by default.
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

## License

Copyright © 2019-2021 [Foreseeti AB](https://foreseeti.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
