# Build context is assembled by goreleaser: the prebuilt linux/amd64 `netcheck`
# binary (CGO_ENABLED=0, fully static, web UI embedded via go:embed) is copied
# into the context root, so this Dockerfile only packages it — no Go toolchain
# and no build stage. Inspect locally with:
#   goreleaser release --snapshot --clean   (requires a Docker daemon)
FROM gcr.io/distroless/static:nonroot

# goreleaser also injects these via --label build flags; keep a few here so the
# image is still annotated when built outside goreleaser.
LABEL org.opencontainers.image.source="https://github.com/Dezoxy/netcheck" \
      org.opencontainers.image.description="netcheck — network diagnostic toolkit (web UI)" \
      org.opencontainers.image.licenses="MIT"

COPY netcheck /netcheck

# The `app` server binds 127.0.0.1:8787 by default; inside a container it must
# listen on all interfaces to be reachable. Runs as the distroless `nonroot`
# user (uid 65532); 8787 is unprivileged so no extra capabilities are needed.
EXPOSE 8787
ENTRYPOINT ["/netcheck"]
CMD ["app", "--listen", "0.0.0.0:8787"]
