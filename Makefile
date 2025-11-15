.PHONY: help install dev test lint format clean docker-up docker-down db-init load-data demo report

# Default target
.DEFAULT_GOAL := help

# Help target
help:  ## Show this help message
	@echo "VMP (Vulnerability Management Pipeline) - Available Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Installation
install:  ## Install production dependencies
	pip install --upgrade pip
	pip install -r requirements.txt

dev:  ## Install development dependencies
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

# Docker
docker-up:  ## Start all Docker services
	docker-compose up -d
	@echo "✓ Services started. Access points:"
	@echo "  - API: http://localhost:8000"
	@echo "  - API Docs: http://localhost:8000/docs"
	@echo "  - Grafana: http://localhost:3000"
	@echo "  - Prometheus: http://localhost:9090"

docker-down:  ## Stop all Docker services
	docker-compose down

docker-logs:  ## View Docker logs
	docker-compose logs -f

docker-rebuild:  ## Rebuild and restart Docker services
	docker-compose down
	docker-compose build --no-cache
	docker-compose up -d

# Database
db-init:  ## Initialize database schema
	docker-compose exec api python -m src.database.engine

db-reset:  ## Reset database (WARNING: deletes all data)
	@echo "⚠️  This will delete ALL data. Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]
	docker-compose exec api python -c "from src.database.engine import DatabaseManager; DatabaseManager.reset_database()"
	@echo "✓ Database reset complete"

db-shell:  ## Open PostgreSQL shell
	docker-compose exec postgres psql -U vmp_admin -d vuln_management

# Data Management
load-data:  ## Load sample data for demo
	docker-compose exec api python scripts/load_sample_data.py

demo:  ## Run interactive demo
	docker-compose exec api python scripts/demo.py

# Reports
report:  ## Generate executive report
	docker-compose exec api python -c "from src.reporting.executive_report import ExecutiveReportGenerator; from src.database.engine import get_db_context; \
		with get_db_context() as db: print(ExecutiveReportGenerator(db).generate_report())"

# Testing
test:  ## Run all tests
	pytest tests/ -v

test-unit:  ## Run unit tests only
	pytest tests/unit/ -v

test-integration:  ## Run integration tests only
	pytest tests/integration/ -v

test-coverage:  ## Run tests with coverage report
	pytest --cov=src --cov-report=html --cov-report=term-missing
	@echo "✓ Coverage report: htmlcov/index.html"

test-fast:  ## Run fast tests (skip slow tests)
	pytest -v -m "not slow"

# Code Quality
lint:  ## Run linting checks
	flake8 src tests --max-line-length=100 --exclude=__pycache__
	mypy src --ignore-missing-imports

format:  ## Format code with black
	black src tests scripts
	isort src tests scripts

format-check:  ## Check code formatting
	black --check src tests scripts
	isort --check-only src tests scripts

# Celery
celery-worker:  ## Start Celery worker
	celery -A src.workflow.celery_app worker --loglevel=info

celery-beat:  ## Start Celery beat scheduler
	celery -A src.workflow.celery_app beat --loglevel=info

celery-flower:  ## Start Flower (Celery monitoring)
	celery -A src.workflow.celery_app flower

# API
api-run:  ## Run API server locally
	uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

api-test:  ## Test API endpoints
	curl http://localhost:8000/health
	@echo ""
	curl http://localhost:8000/api/metrics/summary | python -m json.tool

# Cleanup
clean:  ## Remove build artifacts and cache
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -rf htmlcov
	rm -rf .coverage
	@echo "✓ Cleaned build artifacts"

clean-all: clean docker-down  ## Remove everything including Docker volumes
	docker-compose down -v
	@echo "✓ Cleaned all data"

# Quick Start
quickstart: docker-up db-init load-data  ## Quick start: start services, init DB, load data
	@echo ""
	@echo "✓ VMP is ready!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. View API docs: http://localhost:8000/docs"
	@echo "  2. Run demo: make demo"
	@echo "  3. Generate report: make report"
	@echo "  4. View Grafana: http://localhost:3000 (admin/changeme_grafana_password)"

# Status
status:  ## Show service status
	@echo "Docker Services:"
	@docker-compose ps
	@echo ""
	@echo "Database Status:"
	@docker-compose exec api python -c "from src.database.engine import DatabaseManager; \
		print('✓ Database: Connected' if DatabaseManager.check_connection() else '✗ Database: Disconnected')"
	@echo ""
	@echo "Vulnerability Count:"
	@docker-compose exec api python -c "from src.database.engine import get_db_context; \
		from src.database.models import Vulnerability; \
		with get_db_context() as db: print(f'  Total: {db.query(Vulnerability).count()}')"

# Portfolio
portfolio:  ## Generate portfolio presentation materials
	@echo "Generating portfolio materials..."
	@echo "✓ README.md: Documentation"
	@echo "✓ docs/: Architecture, Risk Model, Setup guides"
	@echo "✓ tests/: Unit tests with coverage"
	@echo "✓ scripts/demo.py: Interactive demonstration"
	@echo ""
	@echo "Resume bullet points in README.md"
	@echo "Interview narrative in docs/RISK_MODEL.md"
