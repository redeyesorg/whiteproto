# WhiteProto reference implementation

## Build

### Docker (recommended)
Requires docker

```sh
# Build builder
docker build -f docker/Dockerfile -t whiteproto-builder .

# Build project with builder
docker run -v $PWD:/src whiteproto-builder
```

### Local
Requires ninja, poetry, and protoc 3.19.0+

```sh
scripts/makebuild.py
ninja -v protos
poetry build
```

## Install
Install from artifacts generated at [Build](#build) stage.

```sh
pip install dist/whiteproto-*-py3-none-any.whl
```

## Run examples

### Server
```sh
python examples/server.py
```

### Client
```sh
python examples/client.py
```

