# Build stage: turn the source into a wheel. Nothing from here but the wheel
# reaches the final image.
FROM python:3.15.0-slim-bookworm AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# Runtime stage: no compiler, no source tree, no secrets. Config and the
# seed are created at first start inside the mounted /data volume.
FROM python:3.15.0-slim-bookworm
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data /handoff /app/scripts \
    && chown 10001:10001 /data /handoff \
    && chmod 700 /data /handoff
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels tr4p && rm -rf /wheels
COPY scripts/benchmark scripts/smoke /app/scripts/
COPY docker/entrypoint.sh /usr/local/bin/tr4p-entrypoint
ENV TR4P_HOME=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080 8787
ENTRYPOINT ["tr4p-entrypoint"]
CMD ["run"]
