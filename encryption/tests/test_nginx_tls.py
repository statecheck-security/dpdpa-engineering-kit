"""Loads tls/nginx-tls.conf into a real nginx and checks which TLS handshakes it accepts.

Needs Docker. Run with: pytest -m docker encryption/tests/test_nginx_tls.py
"""
import datetime
import shutil
import socket
import ssl
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytestmark = pytest.mark.docker

HERE = Path(__file__).resolve().parent
NGINX_IMAGE = "nginx:1.29-alpine"


def _self_signed(cert_dir: Path) -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    (cert_dir / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "key.pem").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )


def _docker_run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def nginx(tmp_path_factory):
    if shutil.which("docker") is None:
        pytest.fail("docker is required for this test")
    certs = tmp_path_factory.mktemp("certs")
    _self_signed(certs)
    mounts = [
        "-v", f"{HERE / 'nginx-harness.conf'}:/etc/nginx/nginx.conf:ro",
        "-v", f"{HERE.parent / 'tls' / 'nginx-tls.conf'}:/etc/nginx/dpdpa/nginx-tls.conf:ro",
        "-v", f"{certs}:/etc/nginx/test-certs:ro",
    ]

    check = _docker_run("run", "--rm", *mounts, NGINX_IMAGE, "nginx", "-t")
    assert check.returncode == 0, check.stderr

    name = f"kit-nginx-{uuid.uuid4().hex[:8]}"
    port = _free_port()
    started = _docker_run("run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:8443", *mounts, NGINX_IMAGE)
    assert started.returncode == 0, started.stderr
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.3)
        yield port, check.stderr
    finally:
        _docker_run("rm", "-f", name)


def _handshake(port, *, min_v=None, max_v=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # self-signed test certificate
    ctx.minimum_version = min_v or ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.maximum_version = max_v or ssl.TLSVersion.MAXIMUM_SUPPORTED
    if ciphers:
        ctx.set_ciphers(ciphers)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as tls:
        return tls.version(), tls.cipher()[0]


def test_config_passes_nginx_t(nginx):
    _, stderr = nginx
    assert "syntax is ok" in stderr
    assert "test is successful" in stderr


def test_tls13_is_negotiated_by_default(nginx):
    port, _ = nginx
    version, _cipher = _handshake(port)
    assert version == "TLSv1.3"


def test_tls12_aead_cipher_is_accepted(nginx):
    port, _ = nginx
    version, cipher = _handshake(port, max_v=ssl.TLSVersion.TLSv1_2, ciphers="ECDHE-ECDSA-AES256-GCM-SHA384")
    assert (version, cipher) == ("TLSv1.2", "ECDHE-ECDSA-AES256-GCM-SHA384")


def test_tls12_cbc_cipher_is_refused(nginx):
    port, _ = nginx
    with pytest.raises(ssl.SSLError):
        _handshake(port, max_v=ssl.TLSVersion.TLSv1_2, ciphers="ECDHE-ECDSA-AES256-SHA384")


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1_1 is deprecated:DeprecationWarning")  # offered on purpose
def test_tls11_is_refused(nginx):
    port, _ = nginx
    try:
        ctx_ok = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_ok.minimum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, ssl.SSLError):
        pytest.skip("this Python's OpenSSL cannot offer TLS 1.1 at all")
    with pytest.raises(ssl.SSLError):
        _handshake(port, min_v=ssl.TLSVersion.TLSv1_1, max_v=ssl.TLSVersion.TLSv1_1, ciphers="DEFAULT:@SECLEVEL=0")
