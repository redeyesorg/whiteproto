FROM alpine:edge

RUN apk add --update \
    protoc python3 python3-dev \
    py3-pip ninja gcc musl-dev \
    libffi-dev rust cargo openssl-dev

RUN pip install --upgrade pip
RUN pip install --upgrade --ignore-installed \
    poetry toml

WORKDIR /build
COPY docker/build-docker.sh /build

RUN chmod +x /build/build-docker.sh

ENTRYPOINT [ "/build/build-docker.sh" ]
