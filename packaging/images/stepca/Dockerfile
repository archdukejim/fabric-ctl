# step-ca, hardened, with fabric's certificate reader.
#
# The upstream /usr/local/bin/step-ca carries a file capability (cap_net_bind_service) so it could bind low ports. A
# container with no-new-privileges and every capability dropped refuses to exec such a binary ("Operation not
# permitted"). step-ca listens on 9000 and does not need it: copying the file drops the security.capability xattr.
#
# fabric-certlist (reader/, decision 2.1.5.13) lists the certificates step-ca signed from a copy of its database. It is
# built here, static, for the image's own architecture (cross-compiled on the build machine's, so an arm64 image needs
# no emulation), on the smallstep/nosql versions this step-ca uses (go.sum checks every module's hash).
#
# Both bases are always given by the compose file or docker-bake.hcl: digest-pinned refs from config/images.lock.yaml
# (no default, so an unpinned build cannot happen).
ARG BASE_IMAGE
ARG GO_IMAGE
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS reader
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY reader/go.mod reader/go.sum ./
RUN go mod download && go mod verify
COPY reader/main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} GOFLAGS=-mod=readonly \
    go build -trimpath -ldflags="-s -w" -o /out/fabric-certlist .

FROM ${BASE_IMAGE}
ARG BASE_IMAGE
ARG GO_IMAGE
LABEL org.fabric.base="${BASE_IMAGE}" org.fabric.go="${GO_IMAGE}"

USER root
RUN cp /usr/local/bin/step-ca /tmp/step-ca \
 && mv -f /tmp/step-ca /usr/local/bin/step-ca \
 && chmod 0755 /usr/local/bin/step-ca
COPY --from=reader --chmod=0755 /out/fabric-certlist /usr/local/bin/fabric-certlist
USER step
