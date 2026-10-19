FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 curl openssl ca-certificates iproute2 passwd systemd systemd-sysv shellcheck nftables \
    && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src
CMD ["/sbin/init"]
