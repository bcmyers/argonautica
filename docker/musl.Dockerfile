FROM buildpack-deps:20.04 as builder

ARG MUSL_CROSS_MAKE_VERSION=0.9.9
ARG MUSL_CROSS_MAKE_HASH=ff3e2188626e4e55eddcefef4ee0aa5a8ffb490e3124850589bcaf4dd60f5f04
RUN set -eux ; \
    cd /tmp ; \
    curl -fLO "https://github.com/richfelker/musl-cross-make/archive/v$MUSL_CROSS_MAKE_VERSION.tar.gz" ; \
    hash=$(sha256sum "v$MUSL_CROSS_MAKE_VERSION.tar.gz" | awk '{ print $1 }') ; \
    [ "$hash" != "$MUSL_CROSS_MAKE_HASH" ] && exit 1 ; \
    tar xzf "v$MUSL_CROSS_MAKE_VERSION.tar.gz" ; \
    cd "musl-cross-make-$MUSL_CROSS_MAKE_VERSION" ; \
    echo "TARGET = x86_64-unknown-linux-musl" > config.mak ; \
    echo "OUTPUT = /usr/local" >> config.mak ; \
    make -j$(nproc) ; \
    make install ; \
    rm -r /tmp/*

ARG USERNAME=rust
ARG PASSWORD=password

ENV TZ=UTC

RUN set -eux ; \
    apt-get update -y ; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        clang \
        musl-dev \
        neovim \
        sudo \
        vim ; \
    apt-get clean ; \
    rm -rf /var/lib/apt/lists/* ; \
    echo "root:$PASSWORD" | chpasswd ; \
    useradd "$USERNAME" --create-home --groups sudo --shell /bin/bash --user-group ; \
    echo "$USERNAME:$PASSWORD" | chpasswd ; \
    echo "%sudo ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/nopasswd

USER $USERNAME

ENV AR=x86_64-unknown-linux-musl-ar \
    CC=x86_64-unknown-linux-musl-gcc \
    CXX=x86_64-unknown-linux-musl-g++ \
    LLVM_CONFIG_PATH=/usr/bin/llvm-config-10 \
    OBJCOPY=x86_64-unknown-linux-musl-objcopy \
    PATH=/home/$USERNAME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SYSROOT=/usr/local/x86_64-unknown-linux-musl \
    TARGET=musl \
    USER=$USERNAME

RUN mkdir -p "/home/$USERNAME/src"

WORKDIR /home/$USERNAME/src

ARG RUST_VERSION=1.44.1
RUN set -eux ; \
    curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain $RUST_VERSION ; \
    rustup target add x86_64-unknown-linux-musl ; \
    config="/home/$USER/.cargo/config" ; \
    echo "[build]"                              >  "$config" ; \
    echo 'target = "x86_64-unknown-linux-musl"' >> "$config"

RUN set -eux ; \
    cargo new --lib argonautica ; \
    cargo new --lib argonautica-sys ; \
    echo "fn main() {}" > ./argonautica/build.rs ; \
    echo "fn main() {}" > ./argonautica-sys/build.rs ; \
    echo '[workspace]\n\
members = [\n\
    "argonautica",\n\
    "argonautica-sys",\n\
]\n' > Cargo.toml

COPY --chown=$USERNAME ./argonautica/Cargo.toml ./argonautica/Cargo.toml
COPY --chown=$USERNAME ./argonautica-sys/Cargo.toml ./argonautica-sys/Cargo.toml

RUN cargo build --release

COPY --chown=$USERNAME ./argonautica ./argonautica
COPY --chown=$USERNAME ./argonautica-sys ./argonautica-sys

RUN cargo build --release

FROM alpine:3.12

COPY --from=builder \
    /home/rust/src/target/x86_64-unknown-linux-musl/release/argonautica \
    /usr/local/bin/

CMD /usr/local/bin/argonautica
