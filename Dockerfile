FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock ./
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -f /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi; \
    pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-build-isolation --no-deps .
COPY configs ./configs
COPY rules/custom ./rules/custom
COPY rules/tests ./rules/tests
RUN useradd --uid 10001 --create-home minisiem && mkdir data && chown minisiem data && chmod -R a+rX configs rules
USER minisiem
CMD ["minisiem", "serve"]
