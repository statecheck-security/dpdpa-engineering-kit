# Contributing to the DPDPA Engineering Kit

Thank you for your interest in contributing to the **DPDPA Engineering Kit**! This repository provides open-source, tested, production-grade engineering implementations for India's **Digital Personal Data Protection Act, 2023 (DPDPA)** and the **DPDP Rules, 2025**.

Contributions from software engineers, privacy engineers, security researchers, and legal engineers are welcome.

---

## Code of Conduct

All contributors and participants are expected to adhere to the [Code of Conduct](CODE_OF_CONDUCT.md). Please treat everyone with respect, professionalism, and empathy.

---

## Core Guiding Principles

1. **Statutory Alignment**: Every module, schema, and API endpoint must trace to a specific statutory obligation in the DPDP Act, 2023 (e.g., Section 5, 6, 8, 9, 11, 12, 13, 14, 16) or the DPDP Rules, 2025.
2. **Minimalism & Simplicity**: Avoid over-engineering or unnecessary external dependencies. Prefer the standard library and well-established cryptographic primitives (`cryptography`, `pydantic`, `fastapi`).
3. **Burden of Proof & Non-Repudiation**: Consent and audit systems must produce cryptographically verifiable evidence (hash-chained logs, signed receipts) without logging cleartext personal data.
4. **Test-First Discipline**: Every change, feature, or bug fix must be accompanied by comprehensive unit tests.

---

## Development Setup

### Prerequisites
- Python 3.12+
- Git

### 1. Clone & Setup Environment

```bash
git clone https://github.com/ithis0623-png/dpdpa-engineering-kit.git
cd dpdpa-engineering-kit

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows

# Install development & test dependencies
pip install -r requirements-dev.txt
```

### 2. Running Quality Gates

Before opening a pull request or pushing changes, ensure all checks pass:

```bash
# 1. Lint and format checks
ruff check .

# 2. Run the unit test suite (excludes Docker and external network calls)
pytest -m "not docker and not network"

# 3. Run full test suite (if Docker is running locally)
pytest
```

---

## Areas We Welcome Contributions To

- **Bug Reports & Fixes**: Edge cases where real-world behavior diverges from legal obligations or causes runtime errors.
- **Statutory Extensions**:
  - Enhancing Verifiable Parental Consent (VPC) methods under Section 9.
  - Sectoral regulatory rules (e.g., RBI, SEBI, IRDAI data localization overrides) in `cross-border/`.
  - Data Protection Impact Assessment (DPIA) automated calculation templates for Significant Data Fiduciaries (SDF).
- **Integrations**: Adapting `ConsentStore` and `DataInventory` protocols for major databases (PostgreSQL with `asyncpg`, MongoDB, Redis, etc.).
- **Security Audits & Threat Models**: Enhancing LINDDUN privacy threat models and STRIDE mitigations.

---

## Pull Request Guidelines

1. **Fork and Branch**: Create a feature or fix branch from `main` (e.g., `git checkout -b feat/grievance-webhooks`).
2. **Atomic Commits**: Write clear, descriptive commit messages following Conventional Commits (e.g., `feat:`, `fix:`, `docs:`, `test:`).
3. **Include Tests**: Add unit tests in the appropriate module's `tests/` directory.
4. **Update Documentation**: If adding a new feature or fixing a behavior, update `README.md` and `CHANGES-FROM-ARTICLES.md`.
5. **Open PR**: Submit your pull request with a clear description referencing the relevant statutory sections.
