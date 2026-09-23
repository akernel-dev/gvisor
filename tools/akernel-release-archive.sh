#!/usr/bin/env bash

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

usage() {
  echo "usage: $0 build <amd64|arm64> <destination> | verify <amd64|arm64> <archive> [--run]" >&2
  exit 2
}

[[ $# -ge 3 ]] || usage
command=$1
arch=$2
target=$3

case "${arch}" in
  amd64)
    bazel_config=x86_64
    machine='Advanced Micro Devices X86-64'
    host_arch=x86_64
    ;;
  arm64)
    bazel_config=aarch64
    machine=AArch64
    host_arch=aarch64
    ;;
  *) usage ;;
esac

verify_archive() {
  local archive=$1
  local run_binary=$2
  local contents expected verify_dir binary

  [[ -f "${archive}" ]]
  contents="$(tar -tjf "${archive}" | sort)"
  expected=$'containerd-shim-runsc-v1\ngvisor-bin/\ngvisor-bin/checkpointgofer\ngvisor-bin/gvisor-sentry-prewarmer\ngvisor-bin/gvisor_sentry\ngvisor-bin/runsc-metric-server\nrunsc'
  if [[ "${contents}" != "${expected}" ]]; then
    echo "unexpected release archive contents: ${archive}" >&2
    diff -u <(printf '%s\n' "${expected}") <(printf '%s\n' "${contents}") >&2 || true
    exit 1
  fi

  verify_dir="$(mktemp -d)"
  trap 'rm -rf "${verify_dir}"' EXIT
  tar -xjf "${archive}" -C "${verify_dir}"
  for binary in runsc containerd-shim-runsc-v1 \
    gvisor-bin/checkpointgofer gvisor-bin/gvisor-sentry-prewarmer \
    gvisor-bin/gvisor_sentry gvisor-bin/runsc-metric-server; do
    if ! readelf -h "${verify_dir}/${binary}" \
      | grep -Eq "Machine:[[:space:]]+${machine}$"; then
      echo "unexpected ELF architecture: ${arch} ${binary}" >&2
      exit 1
    fi
  done
  if [[ "${run_binary}" == true ]]; then
    "${verify_dir}/runsc" --version
  fi
  rm -rf "${verify_dir}"
  trap - EXIT
}

case "${command}" in
  build)
    [[ $# == 3 ]] || usage
    case "$(uname -m)" in
      arm64) actual_arch=aarch64 ;;
      *) actual_arch="$(uname -m)" ;;
    esac
    if [[ "${actual_arch}" != "${host_arch}" ]]; then
      echo "native ${arch} build requires ${host_arch}, got ${actual_arch}" >&2
      exit 1
    fi
    mkdir -p "${target}"
    make release-tarball DESTINATION="${target}" \
      BAZEL_OPTIONS="--config=${bazel_config}"
    archive="${target}/gvisor-${arch}.tar.bz2"
    mv "${target}/gvisor.tar.bz2" "${archive}"
    (cd "${target}" && sha512sum "gvisor-${arch}.tar.bz2" \
      >"gvisor-${arch}.tar.bz2.sha512")
    verify_archive "${archive}" true
    ;;
  verify)
    [[ $# == 3 || ($# == 4 && $4 == --run) ]] || usage
    verify_archive "${target}" "${4:-false}"
    ;;
  *) usage ;;
esac
