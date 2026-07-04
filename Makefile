.PHONY: backend frontend build validate demo

backend:
	./scripts/run_backend.sh

frontend:
	./scripts/run_frontend.sh

build:
	cd frontend && npm install && npm run build

validate:
	./scripts/validate.sh

demo:
	./scripts/demo_request.sh
