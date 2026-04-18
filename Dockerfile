FROM projectdiscovery/nuclei:latest

LABEL maintainer="GreyPing" \
      org.opencontainers.image.source="https://github.com/projectdiscovery/nuclei" \
      org.opencontainers.image.description="Nuclei passive scanner with opinionated defaults"

# Install a few helpful packages required for shell scripting and time zone handling.
# Chromium + deps for Playwright JS rendering.
RUN apk add --no-cache bash tzdata python3 py3-pip \
    chromium nss freetype harfbuzz ca-certificates ttf-freefont

# Install Python dependencies for the OSINT API
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt && \
    pip3 install --no-cache-dir --break-system-packages playwright && \
    PLAYWRIGHT_BROWSERS_PATH=/usr/lib playwright install chromium && \
    rm /tmp/requirements.txt

ENV PLAYWRIGHT_BROWSERS_PATH=/usr/lib

COPY config/nuclei-config.yaml /etc/nuclei/config.yaml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/api_server.py /usr/local/bin/nuclei_api.py
COPY src/ /usr/local/lib/osint_api/src/

RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["scan"]
