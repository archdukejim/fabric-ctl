# fabric's own images (decision 2.1.1.21, manual 3.14.1): nine images, each for amd64 and arm64 (2.1.1.11).
#
# The contexts are the build folders a host has (packaging/images/stage-contexts.sh); the pinned bases and
# Kea's pinned package come from config/images.lock.yaml (packaging/images/bake_env.py). Nothing has a
# default that could build an unpinned image: an empty BASE_* fails the build at its FROM.
# The service account ids are the Dockerfiles' defaults (600–649, 2.1.2.4): a host with other ids builds that
# image itself (P1, 2.1.14.5).
#
#   docker buildx bake -f packaging/docker-bake.hcl                         # every image, this machine's platform
#   docker buildx bake -f packaging/docker-bake.hcl --set '*.platform=linux/arm64' bind9

variable "CONTEXTS" { default = "build/contexts" }
variable "REGISTRY" { default = "ghcr.io/archdukejim/open-fabric" }
variable "TAG" { default = "dev" }
variable "REVISION" { default = "" }
variable "BASE_DEBIAN" { default = "" }
variable "BASE_STEPCA" { default = "" }
variable "BASE_KEYCLOAK" { default = "" }
variable "KEA_VERSION" { default = "" }
variable "KEA_REPO" { default = "" }
variable "KEA_SUITE" { default = "" }
variable "KEA_KEY_URL" { default = "" }
variable "KEA_KEY_FINGERPRINT" { default = "" }

group "default" {
  targets = ["bind9", "freeradius", "kea", "keycloak", "samba", "stepca", "webui"]
}

target "_fabric" {
  labels = {
    "org.opencontainers.image.source"   = "https://github.com/archdukejim/fabric-ctl"
    "org.opencontainers.image.revision" = REVISION
    "org.opencontainers.image.version"  = TAG
    "org.opencontainers.image.licenses" = "MIT"
  }
}

target "bind9" {
  inherits = ["_fabric"]
  context  = "${CONTEXTS}/bind9"
  args     = { BASE_IMAGE = BASE_DEBIAN }
  tags     = ["${REGISTRY}/bind9:${TAG}"]
}

target "freeradius" {
  inherits = ["_fabric"]
  context  = "${CONTEXTS}/freeradius"
  args     = { BASE_IMAGE = BASE_DEBIAN }
  tags     = ["${REGISTRY}/freeradius:${TAG}"]
}

target "kea" {
  inherits = ["_fabric"]
  context  = "${CONTEXTS}/kea"
  args = {
    BASE_IMAGE          = BASE_DEBIAN
    KEA_VERSION         = KEA_VERSION
    KEA_REPO            = KEA_REPO
    KEA_SUITE           = KEA_SUITE
    KEA_KEY_URL         = KEA_KEY_URL
    KEA_KEY_FINGERPRINT = KEA_KEY_FINGERPRINT
  }
  tags = ["${REGISTRY}/kea:${TAG}"]
}

target "keycloak" {
  inherits = ["_fabric"]
  context  = "${CONTEXTS}/keycloak"
  args     = { BASE_IMAGE = BASE_KEYCLOAK }
  tags     = ["${REGISTRY}/keycloak:${TAG}"]
}

target "samba" {
  inherits = ["_fabric"]
  context  = "${CONTEXTS}/samba"
  args     = { BASE_IMAGE = BASE_DEBIAN }
  tags     = ["${REGISTRY}/samba:${TAG}"]
}

target "stepca" {
  inherits = ["_fabric"]
  context  = "${CONTEXTS}/stepca"
  args     = { BASE_IMAGE = BASE_STEPCA }
  tags     = ["${REGISTRY}/stepca:${TAG}"]
}

target "webui" {
  inherits = ["_fabric"]
  context  = "${CONTEXTS}/webui"
  args     = { BASE_IMAGE = BASE_DEBIAN }
  tags     = ["${REGISTRY}/webui:${TAG}"]
}
