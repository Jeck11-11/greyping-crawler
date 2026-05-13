FROM projectdiscovery/nuclei:latest

LABEL maintainer="GreyPing" \
      org.opencontainers.image.source="https://github.com/projectdiscovery/nuclei" \
      org.opencontainers.image.description="Nuclei passive scanner with opinionated defaults"

# Install a few helpful packages required for shell scripting and time zone handling.
RUN apk add --no-cache bash tzdata python3 py3-pip curl unzip

# Install ProjectDiscovery tools (httpx, katana, naabu) from GitHub releases.
# These are statically-linked Go binaries that work on Alpine/musl.
ARG PD_HTTPX_VERSION=1.6.9
ARG PD_KATANA_VERSION=1.1.2
ARG PD_NAABU_VERSION=2.3.3

RUN set -eux && \
    curl -sL "https://github.com/projectdiscovery/httpx/releases/download/v${PD_HTTPX_VERSION}/httpx_${PD_HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip && \
    unzip -q /tmp/httpx.zip -d /tmp/httpx && cp /tmp/httpx/httpx /usr/local/bin/httpx && chmod +x /usr/local/bin/httpx && \
    curl -sL "https://github.com/projectdiscovery/katana/releases/download/v${PD_KATANA_VERSION}/katana_${PD_KATANA_VERSION}_linux_amd64.zip" -o /tmp/katana.zip && \
    unzip -q /tmp/katana.zip -d /tmp/katana && cp /tmp/katana/katana /usr/local/bin/katana && chmod +x /usr/local/bin/katana && \
    curl -sL "https://github.com/projectdiscovery/naabu/releases/download/v${PD_NAABU_VERSION}/naabu_${PD_NAABU_VERSION}_linux_amd64.zip" -o /tmp/naabu.zip && \
    unzip -q /tmp/naabu.zip -d /tmp/naabu && cp /tmp/naabu/naabu /usr/local/bin/naabu && chmod +x /usr/local/bin/naabu && \
    rm -rf /tmp/httpx* /tmp/katana* /tmp/naabu*

# Install Python dependencies for the OSINT API
# NOTE: Playwright requires glibc and has no Alpine wheel, so JS rendering
# is unavailable in Docker. The crawler falls back to static httpx fetching
# automatically. For JS rendering, run the API outside Docker with
# requirements-dev.txt and `playwright install chromium`.
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

COPY config/nuclei-config.yaml /etc/nuclei/config.yaml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/api_server.py /usr/local/bin/nuclei_api.py
COPY src/ /usr/local/lib/osint_api/src/

RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["scan"]
