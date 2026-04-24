FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      postfix \
      postfix-pcre \
      rsyslog \
      gettext-base \
      ca-certificates \
      curl \
      python3 \
      python3-pip \
      python3-dev \
      build-essential \
      libmilter-dev \
      iproute2 && \
    pip3 install --no-cache-dir python-logging-loki pymilter prometheus_client 'pyspf>=2.0,<3' 'dnspython>=2.7,<3' 'dkimpy>=1.1,<2' 'tldextract>=5.0,<6' 'boto3>=1.35,<2' && \
    rm -rf /var/lib/apt/lists/*

# Optional: Datadog APM tracing (enabled via DATADOG_TRACING_ENABLED=true at runtime)
ARG INSTALL_DDTRACE=false
RUN if [ "$INSTALL_DDTRACE" = "true" ]; then \
      pip3 install --no-cache-dir ddtrace; \
    fi

# Work dir for our scripts/config
RUN mkdir -p /opt/mx-box /mail/incoming && \
    chmod 750 /mail/incoming
WORKDIR /opt/mx-box

# Copy config + scripts
COPY postfix/postfix-main.cf.template /opt/mx-box/postfix-main.cf.template
COPY postfix/postfix-master.cf.append /opt/mx-box/postfix-master.cf.append
COPY postfix/relay_domains /opt/mx-box/relay_domains
COPY postfix/relay_recipients /opt/mx-box/relay_recipients
COPY postfix/command_filter.pcre /opt/mx-box/command_filter.pcre
COPY postfix/transport /opt/mx-box/transport
COPY postfix/aliases /opt/mx-box/aliases
COPY milter/entrypoint.sh /opt/mx-box/entrypoint.sh
COPY milter/store_mail.py /opt/mx-box/store_mail.py
COPY milter/email_validator.py /opt/mx-box/email_validator.py
COPY milter/primitivemail_milter.py /opt/mx-box/primitivemail_milter.py
COPY scripts/pipe-transport/store-mail-wrapper.sh /opt/mx-box/store-mail-wrapper.sh
COPY scripts/pipe-transport/store-mail-wrapper-debug.sh /opt/mx-box/store-mail-wrapper-debug.sh
COPY scripts/pipe-transport/store-mail.sh /opt/mx-box/store-mail.sh
COPY scripts/pipe-transport/store-mail-debug.sh /opt/mx-box/store-mail-debug.sh
COPY scripts/pipe-transport/test-pipe.sh /opt/mx-box/test-pipe.sh
COPY scripts/pipe-transport/debug-delivery.sh /opt/mx-box/debug-delivery.sh

RUN chmod +x /opt/mx-box/entrypoint.sh /opt/mx-box/store_mail.py /opt/mx-box/primitivemail_milter.py /opt/mx-box/store-mail-wrapper.sh /opt/mx-box/store-mail-wrapper-debug.sh /opt/mx-box/store-mail.sh /opt/mx-box/store-mail-debug.sh /opt/mx-box/test-pipe.sh /opt/mx-box/debug-delivery.sh

# Postfix spool dirs
RUN mkdir -p /var/spool/postfix /var/lib/postfix && \
    chown -R postfix:postfix /var/spool/postfix /var/lib/postfix

EXPOSE 25 9901

# Healthcheck: container is healthy once postfix is listening on :25 AND has
# written its log file. This gates postfix-exporter's start via compose's
# `depends_on: condition: service_healthy` — without it, the exporter races
# primitivemail and crashloops ~5× trying to open /var/log/postfix.log before
# postfix has created it. start-period tolerates the ~5s entrypoint (TLS cert
# generation, milter startup wait, postfix launch); retries give slower boxes
# more headroom.
HEALTHCHECK --interval=3s --timeout=3s --start-period=5s --retries=20 \
    CMD test -f /var/log/postfix.log && ss -tln 2>/dev/null | grep -q ":25 " || exit 1

CMD ["/opt/mx-box/entrypoint.sh"]
