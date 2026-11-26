# For opencode / coding agents

This is a Flask pentest framework. Server: `cd backend && source venv/bin/activate && python app.py` → `http://localhost:5000`.

- Run any tool: `curl -X POST http://localhost:5000/api/targets/<target_id>/<endpoint>` - endpoint names are in README.md's API table.
- Read results: `backend/targets/<target_id>/*.txt` - plain text, one result per line.
- List targets: `curl http://localhost:5000/api/targets`
- Full route list + tool order: see README.md ("Tool order", API table).
