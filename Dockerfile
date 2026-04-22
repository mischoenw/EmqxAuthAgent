# Build stage
FROM amd64/debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build g++ python3 python3-pip git ca-certificates && \
    pip3 install --break-system-packages conan && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY conanfile.txt CMakeLists.txt ./
COPY src/ ./src/

RUN conan profile detect --force && \
    conan install . \
        --build=missing \
        -s build_type=Release \
        -s compiler.cppstd=17 && \
    cmake -B cmake-build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=Release/generators/conan_toolchain.cmake && \
    cmake --build cmake-build --target emqx-auth-agent

# Runtime stage
FROM amd64/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /bin/false appuser

COPY --from=builder /build/cmake-build/emqx-auth-agent /usr/local/bin/emqx-auth-agent
COPY config/ /app/config/

USER appuser
WORKDIR /app

EXPOSE 8000

ENV RULES_CONFIG=/app/config/rules.yaml \
    PORT=8000 \
    LOG_LEVEL=INFO

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["emqx-auth-agent"]
