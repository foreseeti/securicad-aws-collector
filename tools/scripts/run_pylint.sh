#!/bin/sh

set -eu

cd "$(dirname "$0")/../.."

repo_dir="$PWD"
venv_dir="$repo_dir/venv"

create_venv() {
  if [ ! -d "$venv_dir" ]; then
    ./tools/scripts/create_venv.sh
  fi
  # shellcheck disable=SC1090
  . "$venv_dir/bin/activate"
}

# Pylint does not support implicit namespace packages.
#
# This workaround creates an __init__.py file in the securicad/ directory,
# making it a regular package.

create_fake_namespace() {
  touch securicad/__init__.py
}

delete_fake_namespace() {
  rm -f securicad/__init__.py
}

run_pylint() {
  delete_fake_namespace
  create_fake_namespace
  set +e
  pylint securicad.aws_collector
  status=$?
  set -e
  delete_fake_namespace
  return $status
}

main() {
  create_venv
  run_pylint
}

main
