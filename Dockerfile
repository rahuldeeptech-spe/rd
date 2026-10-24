# patchcheck in a container. Scans what you mount into it, not the host:
#   docker run --rm -v "$PWD":/scan:ro ghcr.io/rahuldeeptech-spe/rd --go-binaries /scan --no-processes
#   docker run --rm -v /opt/venv:/venv:ro ghcr.io/rahuldeeptech-spe/rd --python /venv/bin/python --no-processes
# The PHP/Node/Go it finds on PATH are the ones inside this image (none), so use the options above, or install.sh on the host.
FROM alpine:3.22

RUN apk add --no-cache bash python3 \
    && adduser -D -u 65532 patchcheck
COPY patchcheck.sh advisories.tsv /opt/patchcheck/
USER patchcheck
ENTRYPOINT ["bash", "/opt/patchcheck/patchcheck.sh"]
CMD ["--no-processes"]
