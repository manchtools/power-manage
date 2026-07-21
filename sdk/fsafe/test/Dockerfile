FROM golang:1.26

ENV CGO_ENABLED=0

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo \
    && mkdir -p /run/sshd /etc/ssh/sshd_config.d /etc/sudoers.d \
    && rm -f /etc/ssh/ssh_host_* \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY sdk /src/sdk
RUN chmod 0755 /src/sdk/fsafe/test/run.sh

ENTRYPOINT ["/src/sdk/fsafe/test/run.sh"]
