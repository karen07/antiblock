FROM archlinux:latest

RUN pacman -Syu --noconfirm --needed \
        base-devel \
        ca-certificates \
        clang \
        cmake \
        curl \
        iproute2 \
        libpcap \
        python \
    && pacman -Scc --noconfirm

WORKDIR /src
COPY . .

RUN printf '\n=== GCC release ===\n' \
    && gcc --version \
    && cmake -S . -B build-gcc \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc \
        -DCMAKE_C_FLAGS="-DAB_DOMAIN_RETRY_SEC=2 -DAB_HTTP_CONNECT_TIMEOUT_SEC=1 -DAB_HTTP_TIMEOUT_SEC=2" \
    && cmake --build build-gcc -j2 \
    && printf '\n=== Clang release ===\n' \
    && clang --version \
    && cmake -S . -B build-clang \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS="-DAB_DOMAIN_RETRY_SEC=2 -DAB_HTTP_CONNECT_TIMEOUT_SEC=1 -DAB_HTTP_TIMEOUT_SEC=2" \
    && cmake --build build-clang -j2 \
    && printf '\n=== Clang ASan + UBSan ===\n' \
    && cmake -S . -B build-clang-sanitize \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS='-O1 -g -DAB_DOMAIN_RETRY_SEC=2 -DAB_HTTP_CONNECT_TIMEOUT_SEC=1 -DAB_HTTP_TIMEOUT_SEC=2 -fsanitize=address,undefined -fno-omit-frame-pointer' \
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' \
    && cmake --build build-clang-sanitize -j2

ENV ANTIBLOCK_BIN=/src/build-gcc/antiblock
CMD ["python", "-u", "tests/integration/test_antiblock.py"]
