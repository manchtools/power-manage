ARG BASE=ubuntu:24.04
FROM golang:1.26 AS go
FROM ${BASE}

ARG BACKEND
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CGO_ENABLED=0

RUN set -eux; \
    case "$BACKEND" in \
      apt) \
        apt-get update; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates locales; \
        sed -i 's/^# *\(de_DE.UTF-8 UTF-8\)/\1/' /etc/locale.gen; \
        locale-gen; \
        rm -rf /var/lib/apt/lists/* ;; \
      dnf) \
        dnf -y install ca-certificates dnf5-plugins; \
        dnf clean all ;; \
      pacman) \
        pacman -Sy --needed --noconfirm archlinux-keyring; \
        pacman -Syu --noconfirm ca-certificates; \
        pacman -Scc --noconfirm ;; \
      zypper) \
        zypper --non-interactive install -y ca-certificates; \
        zypper clean --all ;; \
      flatpak) \
        apt-get update; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates flatpak; \
        rm -rf /var/lib/apt/lists/* ;; \
      *) exit 2 ;; \
    esac

WORKDIR /src
COPY sdk /src/sdk
RUN chmod 0755 /src/sdk/pkg/test/run.sh
ENTRYPOINT ["/src/sdk/pkg/test/run.sh"]
