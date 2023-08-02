# Builder stage
FROM python:3.11.4-alpine3.18 AS builder

WORKDIR /app/certalert/

COPY requirements.txt certalert.py /app/certalert/

RUN apk add --no-cache --virtual .build-deps gcc musl-dev \
    && python -m venv /app/certalert/venv \
    && /app/certalert/venv/bin/pip install -U pip setuptools wheel \
    && /app/certalert/venv/bin/pip install -r /app/requirements.txt \
    && apk del .build-deps gcc musl-dev

# Final stage
FROM python:3.11.4-alpine3.18

WORKDIR /app/certalert/

COPY --from=builder /app/certalert/venv /app/certalert/venv

COPY certalert.py /app/

ENTRYPOINT ["/app/certalert/venv/bin/python", "/app/certalert/certalert.py"]
