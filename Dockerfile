FROM projectdiscovery/nuclei:latest

LABEL maintainer="GreyPing" \
      org.opencontainers.image.source="https://github.com/projectdiscovery/nuclei" \
      org.opencontainers.image.description="Nuclei passive scanner with opinionated defaults"

# Install a few helpful packages required for shell scripting and time zone handling.
RUN apk add --no-cache bash tzdata

COPY config/nuclei-config.yaml /etc/nuclei/config.yaml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["scan"]
