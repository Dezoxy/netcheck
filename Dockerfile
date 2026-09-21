# Build context is assembled by goreleaser (dockers_v2): the prebuilt static
# `netcheck` binary for each platform (CGO_ENABLED=0, web UI embedded via
# go:embed) sits at <os>/<arch>/netcheck, and buildx sets TARGETPLATFORM per
# image, so this Dockerfile only packages it: no Go toolchain, no build stage,
# no RUN step (so no QEMU is needed for arm64). Inspect locally with:
#   goreleaser release --snapshot --clean   (requires Docker with buildx)
FROM gcr.io/distroless/static:nonroot

# goreleaser also injects these via --label build flags; keep a few here so the
# image is still annotated when built outside goreleaser.
LABEL org.opencontainers.image.source="https://github.com/Dezoxy/netcheck" \
      org.opencontainers.image.description="netcheck — network diagnostic toolkit (web UI)" \
      org.opencontainers.image.licenses="MIT"

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/netcheck /netcheck

# The `app` server binds 127.0.0.1:8787 by default; inside a container it must
# listen on all interfaces to be reachable. Runs as the distroless `nonroot`
# user (uid 65532); 8787 is unprivileged so no extra capabilities are needed.
# The base image already defaults to nonroot, but state it explicitly so
# static scanners (Trivy DS-0002) can see it from the Dockerfile alone.
USER 65532:65532
EXPOSE 8787
ENTRYPOINT ["/netcheck"]
CMD ["app", "--listen", "0.0.0.0:8787"]
