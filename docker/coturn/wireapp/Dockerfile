# This image derives from another coturn image, and adds a script which
# polls the Prometheus metrics endpoint until there are no more active
# allocations. This is intended to be used as a pre-stop hook to allow graceful
# termination of the coturn process without disrupting active allocations.

ARG coturn_image=coturn/coturn
ARG coturn_tag=latest

FROM ${coturn_image}:${coturn_tag}

USER root

RUN apt-get update \
  && apt-get install -y --no-install-recommends --no-install-suggests \
    curl grep coreutils procps

COPY docker/coturn/wireapp/pre-stop-hook.sh /usr/local/bin/pre-stop-hook
RUN chmod +x /usr/local/bin/pre-stop-hook

# Limit access by switching to non-root user
USER nobody:nogroup
