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
    pip3 install --no-cache-dir python-logging-loki pymilter prometheus_client 'pyspf>=2.0,<3' 'dnspython>=2.7,<3' 'dkimpy>=1.1,<2' 'tldextract>=5.0,<6' && \
    rm -rf /var/lib/apt/lists/*

# Production Python dependencies (Primitive SDK, etc.). Installed as a separate
# layer so requirements.txt changes don't bust the cache above.
COPY requirements.txt /opt/mx-box/requirements.txt
RUN pip3 install --no-cache-dir -r /opt/mx-box/requirements.txt

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
COPY postfix-main.cf.template /opt/mx-box/postfix-main.cf.template
COPY postfix-master.cf.append /opt/mx-box/postfix-master.cf.append
COPY relay_domains /opt/mx-box/relay_domains
COPY relay_recipients /opt/mx-box/relay_recipients
COPY command_filter.pcre /opt/mx-box/command_filter.pcre
COPY transport /opt/mx-box/transport
COPY aliases /opt/mx-box/aliases
COPY entrypoint.sh /opt/mx-box/entrypoint.sh
COPY store_mail.py /opt/mx-box/store_mail.py
COPY email_validator.py /opt/mx-box/email_validator.py
COPY primitivemail_milter.py /opt/mx-box/primitivemail_milter.py
COPY store-mail-wrapper.sh /opt/mx-box/store-mail-wrapper.sh
COPY store-mail-wrapper-debug.sh /opt/mx-box/store-mail-wrapper-debug.sh
COPY store-mail.sh /opt/mx-box/store-mail.sh
COPY store-mail-debug.sh /opt/mx-box/store-mail-debug.sh
COPY test-pipe.sh /opt/mx-box/test-pipe.sh
COPY debug-delivery.sh /opt/mx-box/debug-delivery.sh

RUN chmod +x /opt/mx-box/entrypoint.sh /opt/mx-box/store_mail.py /opt/mx-box/primitivemail_milter.py /opt/mx-box/store-mail-wrapper.sh /opt/mx-box/store-mail-wrapper-debug.sh /opt/mx-box/store-mail.sh /opt/mx-box/store-mail-debug.sh /opt/mx-box/test-pipe.sh /opt/mx-box/debug-delivery.sh

# Postfix spool dirs
RUN mkdir -p /var/spool/postfix /var/lib/postfix && \
    chown -R postfix:postfix /var/spool/postfix /var/lib/postfix

EXPOSE 25 9901

CMD ["/opt/mx-box/entrypoint.sh"]
