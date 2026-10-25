import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from field_encryption import DPDPAFieldEncryptor


class FakeKMS:
    """Wraps DEKs with a local AES-GCM key and, like AWS KMS, refuses a mismatched encryption context."""

    def __init__(self):
        self._kek = AESGCM.generate_key(bit_length=256)
        self.calls = []

    @staticmethod
    def _aad(key_id, context):
        return (key_id + "|" + "|".join(f"{k}={context[k]}" for k in sorted(context))).encode()

    def encrypt(self, key_id, plaintext, encryption_context):
        self.calls.append(("encrypt", key_id, dict(encryption_context)))
        nonce = os.urandom(12)
        return nonce + AESGCM(self._kek).encrypt(nonce, plaintext, self._aad(key_id, encryption_context))

    def decrypt(self, key_id, ciphertext, encryption_context):
        self.calls.append(("decrypt", key_id, dict(encryption_context)))
        return AESGCM(self._kek).decrypt(ciphertext[:12], ciphertext[12:], self._aad(key_id, encryption_context))


class RecordingAudit:
    def __init__(self):
        self.events = []

    def log(self, **event):
        self.events.append(event)


@pytest.fixture
def enc():
    kms, audit = FakeKMS(), RecordingAudit()
    return DPDPAFieldEncryptor(kms, audit, kek_id="alias/dpdpa-personal-data-test"), kms, audit


def test_round_trip(enc):
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    assert b"asha" not in field.ciphertext
    assert len(field.nonce) == 12
    assert encryptor.decrypt_field(field, "email", "dp-1", requester="support-agent-7") == "asha@example.in"


def test_each_record_gets_its_own_dek_and_nonce(enc):
    encryptor, _, _ = enc
    a = encryptor.encrypt_field("same value", "email", "dp-1")
    b = encryptor.encrypt_field("same value", "email", "dp-1")
    assert a.wrapped_dek != b.wrapped_dek
    assert a.nonce != b.nonce
    assert a.ciphertext != b.ciphertext


def test_ciphertext_cannot_be_moved_to_another_principal(enc):
    """AAD and the KMS encryption context bind the ciphertext to its field and Data Principal."""
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    with pytest.raises(InvalidTag):
        encryptor.decrypt_field(field, "email", "dp-2", requester="attacker")


def test_ciphertext_cannot_be_moved_to_another_field(enc):
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("9876543210", "phone", "dp-1")
    with pytest.raises(InvalidTag):
        encryptor.decrypt_field(field, "email", "dp-1", requester="attacker")


def test_tampered_ciphertext_is_rejected(enc):
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    field.ciphertext = bytes([field.ciphertext[0] ^ 1]) + field.ciphertext[1:]
    with pytest.raises(InvalidTag):
        encryptor.decrypt_field(field, "email", "dp-1", requester="support-agent-7")


def test_both_operations_are_audited_without_the_plaintext(enc):
    encryptor, kms, audit = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    encryptor.decrypt_field(field, "email", "dp-1", requester="support-agent-7")
    assert [e["event"] for e in audit.events] == ["field_encrypted", "field_decrypted"]
    assert audit.events[1]["requester"] == "support-agent-7"
    assert "asha@example.in" not in repr(audit.events)
    assert all(call[2]["purpose"] == "dpdpa_field_encryption" for call in kms.calls)
