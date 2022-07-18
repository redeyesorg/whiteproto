# WhiteProto reference implementation

## Run
Requires ninja and poetry to be installed.

```bash
scripts/makebuild.py
poetry install
ninja -v protos

# run server
poetry run examples/server.py

# run client
poetry run examples/client.py
```
