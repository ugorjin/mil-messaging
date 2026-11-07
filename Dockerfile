# syntax=docker/dockerfile:1
#
# Relay server image. Runs the TypeScript directly (Node strips the types),
# so there is no build step. Node 24 LTS: libsignal's dependencies require it. Debian (glibc) base: libsignal's prebuilt native
# binaries don't support Alpine (musl).
#
# For production, pin the base image by digest (node:24.22.2-bookworm-slim@sha256:...).
ARG NODE_IMAGE=node:24.22.2-bookworm-slim

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# Behind a TLS-inspecting proxy, pass its CA as a build secret (it is not kept in the image):
#   docker build --secret id=ca,src=/path/to/ca.crt --build-arg HTTPS_PROXY=... .
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca npm_config_cafile=/run/secrets/ca; fi; \
    npm ci --omit=dev && npm cache clean --force && \
    # keep only this platform's libsignal binary (the package ships all six)
    find node_modules/@signalapp/libsignal-client/prebuilds -mindepth 1 -maxdepth 1 \
      ! -name "linux-$(node -p process.arch)" -exec rm -rf {} +

FROM ${NODE_IMAGE}
ENV NODE_ENV=production \
    PORT=8080
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
# Run as the unprivileged "node" user; the app needs no writable files.
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "src/server/main.ts"]
