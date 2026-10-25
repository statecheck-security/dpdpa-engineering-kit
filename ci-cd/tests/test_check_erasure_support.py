import subprocess
import sys
from pathlib import Path

import pytest
from check_erasure_support import check_model_file, load_pii_fields

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_erasure_support.py"
CONFIG = ROOT / "config" / "pii-fields.yaml"


@pytest.fixture
def pii():
    return load_pii_fields(str(CONFIG))


def write(tmp_path, source):
    path = tmp_path / "models.py"
    path.write_text(source, encoding="utf-8")
    return path


def test_config_lists_core_identifiers(pii):
    assert {"aadhaar", "pan", "email", "phone", "ip_address"} <= pii


def test_django_model_without_erasure_is_flagged(tmp_path, pii):
    src = "class Customer(models.Model):\n    email = models.CharField()\n    order_ref = models.CharField()\n"
    (violation,) = check_model_file(write(tmp_path, src), pii)
    assert violation["model"] == "Customer"
    assert violation["pii_fields"] == ["email"]


def test_model_with_erase_method_passes(tmp_path, pii):
    src = (
        "class Customer(models.Model):\n"
        "    email = models.CharField()\n"
        "    def erase(self):\n"
        "        self.email = None\n"
    )
    assert check_model_file(write(tmp_path, src), pii) == []


@pytest.mark.parametrize(
    "field",
    [
        "    phone: str",                                    # dataclass / Pydantic
        "    phone: Mapped[str] = mapped_column()",          # SQLAlchemy 2.0
    ],
)
def test_annotated_fields_are_checked(field, tmp_path, pii):
    src = f"class Customer(Base):\n{field}\n"
    (violation,) = check_model_file(write(tmp_path, src), pii)
    assert violation["pii_fields"] == ["phone"]


def test_class_without_pii_is_ignored(tmp_path, pii):
    assert check_model_file(write(tmp_path, "class Order:\n    total = 0\n"), pii) == []


def test_cli_exit_codes(tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    (models / "customer.py").write_text("class Customer:\n    aadhaar = None\n", encoding="utf-8")
    cmd = [sys.executable, str(SCRIPT), "--models-dir", str(models), "--pii-fields-config", str(CONFIG)]

    failed = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    assert failed.returncode == 1
    assert "GATE 3 FAILED" in failed.stdout

    (models / "customer.py").write_text(
        "class Customer:\n    aadhaar = None\n    def anonymise(self):\n        pass\n", encoding="utf-8"
    )
    passed = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    assert passed.returncode == 0
    assert "PASSED" in passed.stdout
