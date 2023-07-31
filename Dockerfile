FROM python:3.11.4-alpine3.18

ADD requirements.txt certinator.py /app/

RUN apk add --no-cache --virtual .build-deps gcc musl-dev && \
    pip install -U pip setuptools wheel && \
    pip install -r /app/requirements.txt && \
    apk del .build-deps gcc musl-dev

FROM python:3.11.4-alpine3.18

COPY --from=builder /app /app

ENTRYPOINT ["python", "/app/certinator.py"]

