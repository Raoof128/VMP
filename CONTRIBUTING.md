# Contributing to Vulnerability Management Pipeline (VMP)

Thank you for your interest in contributing to VMP! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

---

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful** of differing viewpoints and experiences
- **Use welcoming and inclusive language**
- **Accept constructive criticism gracefully**
- **Focus on what is best for the community**
- **Show empathy towards other community members**

Unacceptable behavior includes harassment, trolling, insults, or other unprofessional conduct.

---

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose
- Git
- PostgreSQL 15+ (or use Docker)
- Redis 7+ (or use Docker)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/VMP.git
   cd VMP
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/Raoof128/VMP.git
   ```

---

## Development Setup

### 1. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### 3. Set Up Environment Variables

```bash
cp .env.example .env
# Edit .env with your local configuration
```

### 4. Initialize Database

```bash
# Using Docker
make docker-up
make db-init

# Or manually
python -c "from src.database.engine import init_db; init_db()"
```

### 5. Load Sample Data (Optional)

```bash
python scripts/load_sample_data.py
```

### 6. Run Tests

```bash
# Run all tests
make test

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_risk_scoring.py -v
```

---

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

When creating a bug report, include:

- **Clear title** describing the issue
- **Environment details** (OS, Python version, Docker version)
- **Steps to reproduce** the bug
- **Expected behavior** vs. **actual behavior**
- **Error messages** or logs (if applicable)
- **Screenshots** (if relevant)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide detailed description** of the proposed functionality
- **Explain why this enhancement would be useful**
- **List any similar features** in other tools
- **Include mockups or examples** if applicable

### Code Contributions

1. **Check existing issues** or create a new one to discuss your idea
2. **Create a feature branch** from `develop`:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** following our coding standards
4. **Write tests** for your changes
5. **Run the test suite** to ensure nothing breaks
6. **Update documentation** if needed
7. **Commit your changes** with clear commit messages
8. **Push to your fork** and create a pull request

---

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 127 characters maximum
- **Imports**: Organized using `isort`
- **Formatting**: Code formatted with `black`
- **Type hints**: Required for all public functions
- **Docstrings**: Google-style docstrings for all modules, classes, and public functions

### Example Function

```python
def calculate_business_risk(
    cvss_base_score: float,
    epss_score: float,
    asset_criticality: float,
    remediation_difficulty: int
) -> Dict[str, Any]:
    """
    Calculate business risk score for a vulnerability.

    Args:
        cvss_base_score: CVSS v3.x base score (0-10)
        epss_score: EPSS exploit probability (0-1)
        asset_criticality: Asset criticality rating (1-10)
        remediation_difficulty: Remediation complexity (1-5)

    Returns:
        Dictionary containing:
            - total_score: Business risk score (0-100)
            - components: Individual component contributions
            - explanation: Human-readable explanation

    Raises:
        ValueError: If any input is out of valid range
    """
    # Implementation here
    pass
```

### Code Quality Tools

We use the following tools (configured in `pyproject.toml`):

- **Black**: Code formatting
- **isort**: Import sorting
- **Flake8**: Linting
- **MyPy**: Type checking
- **Pylint**: Additional linting
- **Bandit**: Security linting

Run all checks:

```bash
# Format code
black src/ tests/
isort src/ tests/

# Lint
flake8 src/ tests/
mypy src/
pylint src/

# Security check
bandit -r src/
```

Or use pre-commit hooks:

```bash
pre-commit run --all-files
```

---

## Testing Guidelines

### Test Structure

```
tests/
├── unit/              # Unit tests (fast, isolated)
├── integration/       # Integration tests (with database)
└── performance/       # Performance benchmarks
```

### Writing Tests

- **Use pytest** for all tests
- **Follow AAA pattern**: Arrange, Act, Assert
- **Use fixtures** from `tests/conftest.py`
- **Mock external dependencies** (APIs, scanners)
- **Test edge cases** and error conditions
- **Aim for 80%+ code coverage**

### Example Test

```python
@pytest.mark.unit
def test_risk_calculation_critical(scorer):
    """Test that critical vulnerability produces high risk score"""
    # Arrange
    cvss = 10.0
    epss = 0.95
    criticality = 10
    difficulty = 3

    # Act
    result = scorer.calculate_business_risk(
        cvss_base_score=cvss,
        epss_score=epss,
        asset_criticality=criticality,
        remediation_difficulty=difficulty
    )

    # Assert
    assert result['total_score'] >= 80
    assert 'CRITICAL' in result['explanation']
```

### Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# With coverage
pytest --cov=src --cov-report=html

# Specific marker
pytest -m unit

# Verbose output
pytest -v -s
```

---

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks
- **perf**: Performance improvements
- **ci**: CI/CD changes

### Examples

```
feat(scoring): Add EPSS-based exploit probability weighting

Implement EPSS (Exploit Prediction Scoring System) integration to
improve risk prioritization accuracy by 35%.

Closes #123
```

```
fix(api): Handle 404 errors properly in vulnerability endpoint

Changed from tuple return to HTTPException for proper REST API
error responses.

Fixes #456
```

---

## Pull Request Process

### Before Submitting

1. ✅ Ensure all tests pass
2. ✅ Update documentation
3. ✅ Add/update tests for your changes
4. ✅ Run code quality tools
5. ✅ Rebase on latest `develop` branch
6. ✅ Write clear commit messages

### PR Template

When creating a PR, include:

- **Description**: What does this PR do?
- **Motivation**: Why is this change needed?
- **Type of change**: Bug fix, feature, documentation, etc.
- **Testing**: How was this tested?
- **Checklist**:
  - [ ] Tests pass locally
  - [ ] Code follows style guidelines
  - [ ] Documentation updated
  - [ ] No breaking changes (or clearly documented)

### Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **At least one reviewer** must approve
3. **Address feedback** from reviewers
4. **Squash commits** if requested
5. **Maintainer will merge** once approved

### After Merge

- Your PR will be merged to `develop`
- It will be included in the next release
- Update your local fork:
  ```bash
  git checkout develop
  git pull upstream develop
  ```

---

## Development Workflow

### Branching Strategy

- **main**: Production-ready code
- **develop**: Integration branch for features
- **feature/\***: New features
- **fix/\***: Bug fixes
- **docs/\***: Documentation updates
- **chore/\***: Maintenance tasks

### Release Process

1. Features are merged to `develop`
2. When ready for release, create `release/vX.Y.Z` branch
3. Test thoroughly on release branch
4. Merge to `main` and tag version
5. Deploy to production

---

## Project Structure

```
VMP/
├── src/                    # Source code
│   ├── api/               # FastAPI application
│   ├── database/          # Database models and engine
│   ├── prioritisation/    # Risk scoring logic
│   ├── scanner/           # Scanner integrations
│   ├── workflow/          # Celery tasks, Jira
│   └── reporting/         # Report generation
├── tests/                 # Test suite
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── conftest.py       # Shared fixtures
├── docs/                  # Documentation
├── scripts/               # Utility scripts
├── config/                # Configuration files
└── docker-compose.yml     # Docker orchestration
```

---

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and ideas
- **Documentation**: Check `docs/` directory
- **Examples**: See `scripts/demo.py`

---

## Recognition

Contributors will be recognized in:

- **CHANGELOG.md**: Listed for each release
- **README.md**: Contributors section
- **GitHub**: Contributor badge

Thank you for contributing to VMP! 🎉
