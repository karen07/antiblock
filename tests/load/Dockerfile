FROM archlinux:latest

ARG DNS_CLIENT_REF=main
ARG DNS_SERVER_REF=main

RUN pacman -Syu --noconfirm --needed \
        base-devel \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        iproute2 \
        libpcap \
        python \
    && pacman -Scc --noconfirm

WORKDIR /src
COPY . .

RUN printf '\n=== AntiBlock GCC release ===\n' \
    && gcc --version \
    && cmake -S . -B build-load-gcc \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc \
    && cmake --build build-load-gcc -j2 \
    && printf '\n=== AntiBlock Clang ASan + UBSan ===\n' \
    && clang --version \
    && cmake -S . -B build-load-sanitize \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' \
    && cmake --build build-load-sanitize -j2

RUN git clone https://github.com/karen07/dns-client-test.git /opt/dns-client-test \
    && git -C /opt/dns-client-test checkout "$DNS_CLIENT_REF" \
    && cmake -S /opt/dns-client-test -B /opt/dns-client-test/build/release \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc \
    && cmake --build /opt/dns-client-test/build/release -j2 \
    && git clone --recurse-submodules https://github.com/karen07/dns-server-test.git /opt/dns-server-test \
    && git -C /opt/dns-server-test checkout "$DNS_SERVER_REF" \
    && git -C /opt/dns-server-test submodule update --init --recursive \
    && cmake -S /opt/dns-server-test -B /opt/dns-server-test/build/release \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc \
    && cmake --build /opt/dns-server-test/build/release -j2 \
    && { \
        printf 'dns-client-test %s\n' "$(git -C /opt/dns-client-test rev-parse HEAD)"; \
        printf 'dns-server-test %s\n' "$(git -C /opt/dns-server-test rev-parse HEAD)"; \
       } > /opt/dns-tools-versions.txt

ENV DNS_CLIENT_BIN=/opt/dns-client-test/build/release/dns-client-test
ENV DNS_SERVER_BIN=/opt/dns-server-test/build/release/dns-server-test
ENV ANTIBLOCK_RELEASE_BIN=/src/build-load-gcc/antiblock
ENV ANTIBLOCK_SANITIZE_BIN=/src/build-load-sanitize/antiblock

CMD ["python", "-u", "tests/load/load_test.py", "run", "all"]
