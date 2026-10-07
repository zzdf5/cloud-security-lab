#!/usr/bin/env bash
# setup_lab.sh
#
# usage:
#   chmod +x setup_lab.sh
#   ./setup_lab.sh
#
# safe to run repeatedly. Images that already exist are only checked for a newer version, and nothing is deleted

set -euo pipefail

WAZUH_VERSION="4.14.8"
WAZUH_DIR="${HOME}/wazuh-docker"

# images pulled with 'docker pull'
IMAGES=(
  "hello-world:latest" # test image: Docker can run a container
  "quay.io/minio/minio:latest" # S3-compatible object storage
  "quay.io/keycloak/keycloak:latest" # identity provider
  "hashicorp/vault:latest" # secrets management and encryption
  "aquasec/trivy:latest" # image, IaC, and secret scanner
  "kindest/node:v1.33.12" # local Kubernetes node for kind
  "aquasec/kube-bench:latest" # Kubernetes hardening audit
  "toniblyx/prowler:latest" # CSPM
)

MIN_DISK_GB=20
MAX_RETRY=3

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }

# make sure Docker is installed and reachable
if ! command -v docker >/dev/null 2>&1; then
  err "Docker is not installed. Install Docker first, then run this script again."
  exit 1
fi

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif sudo -n docker info >/dev/null 2>&1; then
  warn "Docker is only reachable through sudo, so docker commands will use sudo."
  DOCKER=(sudo docker)
else
  err "Docker is not reachable. Make sure Docker Desktop is running (stable whale icon) and WSL Integration for Ubuntu is enabled."
  exit 1
fi
ok "Docker is ready."

# check disk space
DOCKER_DIR="/var/lib/docker"
[[ -d ${DOCKER_DIR} ]] || DOCKER_DIR="/var"
AVAIL_GB=$(df -BG --output=avail "${DOCKER_DIR}" 2>/dev/null | tail -n 1 | tr -dc '0-9' || true)
if [[ -n ${AVAIL_GB} && ${AVAIL_GB} -lt ${MIN_DISK_GB} ]]; then
  warn "Only about ${AVAIL_GB} GB free in ${DOCKER_DIR}, at least ${MIN_DISK_GB} GB is recommended."
elif [[ -n ${AVAIL_GB} ]]; then
  ok "Enough disk space (${AVAIL_GB} GB available)."
fi

# a local copy counts as present if the name matches exactly
has_local() {
  local img="$1"
  if "${DOCKER[@]}" image inspect "${img}" >/dev/null 2>&1; then
    LOCAL_NAME="${img}"
    return 0
  fi
  case "${img%%/*}" in
    *.*)
      if "${DOCKER[@]}" image inspect "${img#*/}" >/dev/null 2>&1; then
        LOCAL_NAME="${img#*/}"
        return 0
      fi
      ;;
  esac
  return 1
}

# pull the regular images, retrying if the connection drops
FAILED=()
LOCAL=()
LOCAL_NAME=""
for image in "${IMAGES[@]}"; do
  success=false
  for ((attempt = 1; attempt <= MAX_RETRY; attempt++)); do
    info "Pulling ${image} (attempt ${attempt}/${MAX_RETRY})..."
    if "${DOCKER[@]}" pull "${image}"; then
      success=true
      break
    fi
    warn "Failed to pull ${image}."
  done
  if [[ ${success} == false ]]; then
    if has_local "${image}"; then
      warn "Could not pull ${image}, but a local copy (${LOCAL_NAME}) already exists. Using the local copy."
      LOCAL+=("${LOCAL_NAME}")
    else
      FAILED+=("${image}")
    fi
  fi
done

# wazuh through the wazuh-docker repository and 'docker compose pull'
pull_wazuh() {
  local tag="v${WAZUH_VERSION}"

  if ! command -v git >/dev/null 2>&1; then
    err "git is not installed, but it is required to download the wazuh-docker repository."
    return 1
  fi
  if ! "${DOCKER[@]}" compose version >/dev/null 2>&1; then
    err "The 'docker compose' command is not available. Install the Docker Compose plugin first."
    return 1
  fi

  if [[ -d ${WAZUH_DIR}/.git ]]; then
    local current
    current=$(git -C "${WAZUH_DIR}" describe --tags --exact-match 2>/dev/null || true)
    if [[ ${current} == "${tag}" ]]; then
      ok "The wazuh-docker repository in ${WAZUH_DIR} is already at ${tag}."
    else
      err "Folder ${WAZUH_DIR} already exists but is not at ${tag} (currently ${current:-not a tag}). Move it first, for example 'mv ${WAZUH_DIR} ${WAZUH_DIR}-old', then run this script again."
      return 1
    fi
  elif [[ -e ${WAZUH_DIR} ]]; then
    err "${WAZUH_DIR} already exists but is not a git repository. Move it first, then run this script again."
    return 1
  else
    info "Downloading the wazuh-docker repository (${tag})..."
    git clone -c advice.detachedHead=false https://github.com/wazuh/wazuh-docker.git -b "${tag}" --single-branch "${WAZUH_DIR}" || return 1
  fi

  for ((attempt = 1; attempt <= MAX_RETRY; attempt++)); do
    info "Pulling the Wazuh images with docker compose (attempt ${attempt}/${MAX_RETRY})..."
    if (cd "${WAZUH_DIR}/single-node" && "${DOCKER[@]}" compose pull); then
      return 0
    fi
    warn "Failed to pull the Wazuh images."
  done
  return 1
}

if ! pull_wazuh; then
  FAILED+=("wazuh (wazuh-docker repository ${WAZUH_VERSION})")
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
  err "These parts did not succeed: ${FAILED[*]}"
  err "Check the messages above, fix the problem, then run this script again."
  exit 1
fi

# verification
echo
info "Docker version:"
"${DOCKER[@]}" --version

echo
info "Available images:"
"${DOCKER[@]}" images

if [[ ${#LOCAL[@]} -gt 0 ]]; then
  echo
  warn "These images use a local copy because they could not be pulled from the registry: ${LOCAL[*]}"
  warn "Do not delete these copies, they may not be possible to pull again."
fi

ok "All images are available. Do not start every tool at once, start them one at a time as each topic needs."
