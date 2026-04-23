# syntax=docker/dockerfile:1
# Build stage
FROM amd64/debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build g++ python3 python3-pip git ca-certificates \
        perl && \
    pip3 install --break-system-packages conan && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Layer 1: dependency manifest only — invalidated when conanfile.txt changes.
# conan install is expensive (compiles libwebsockets etc.) so keep it separate
# from the source COPY so source changes don't retrigger a full dep rebuild.
COPY conanfile.txt CMakeLists.txt ./
RUN conan profile detect --force && \
    conan install . \
        --build=missing \
        -s build_type=Release \
        -s compiler.cppstd=17 \
        --output-folder=cmake-build

# Layer 2: source — invalidated on every source change, cmake build only.
# BUILD_TESTING=OFF: tests/ is not present in this stage; the test-runner
# stage below re-configures cmake with testing enabled.
COPY src/ ./src/
RUN cmake -B cmake-build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=cmake-build/conan_toolchain.cmake \
        -DBUILD_TESTING=OFF && \
    cmake --build cmake-build --target emqx-auth-agent

# Test stage — inherits the Conan packages and cmake build from builder,
# then re-configures with testing enabled and runs the test suite.
FROM builder AS test-runner
COPY tests/ ./tests/
RUN cmake -B cmake-build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=cmake-build/conan_toolchain.cmake \
        -DBUILD_TESTING=ON && \
    cmake --build cmake-build --target run_tests && \
    ctest --test-dir cmake-build --output-on-failure

# Runtime stage — minimal image, no build tools
FROM amd64/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl && \
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
