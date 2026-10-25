import boto3
import pytest
from botocore.stub import ANY, Stubber
from crypto_shred import CryptoShredder
from fastapi.testclient import TestClient
from signup import create_app

KEY_ARN = "arn:aws:kms:ap-south-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"


class TestSignup:
    @pytest.fixture
    def client_and_queue(self):
        queue = []
        app = create_app(lambda **task: queue.append(task), lambda name: "test-hmac-key")
        return TestClient(app), queue

    def test_response_never_reveals_whether_the_account_exists(self, client_and_queue):
        client, _ = client_and_queue
        body = {"email": "asha@example.in", "phone": "+91 98765 43210"}
        first, second = client.post("/signup", json=body), client.post("/signup", json=body)
        assert first.status_code == second.status_code == 202
        assert first.json().keys() == second.json().keys() == {"correlation_id", "status"}
        assert first.json()["correlation_id"] != second.json()["correlation_id"]

    def test_only_hmacs_reach_the_queue(self, client_and_queue):
        client, queue = client_and_queue
        client.post("/signup", json={"email": "asha@example.in", "phone": "9876543210"})
        (task,) = queue
        assert "asha" not in str(task) and "9876543210" not in str(task)
        assert len(task["email_hmac"]) == 64

    def test_same_person_gets_the_same_hmac(self, client_and_queue):
        client, queue = client_and_queue
        client.post("/signup", json={"email": "Asha@Example.in", "phone": "+91 98765-43210"})
        client.post("/signup", json={"email": "asha@example.in", "phone": "09876543210"})
        assert queue[0]["email_hmac"] == queue[1]["email_hmac"]
        assert queue[0]["phone_hmac"] == queue[1]["phone_hmac"]

    def test_invalid_email_is_rejected(self, client_and_queue):
        client, queue = client_and_queue
        assert client.post("/signup", json={"email": "not-an-email", "phone": "1"}).status_code == 422
        assert queue == []


class TestCryptoShred:
    @pytest.fixture
    def stubs(self):
        kms = boto3.client("kms", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="x")
        table = boto3.resource(
            "dynamodb", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="x"
        ).Table("consent_events")
        with Stubber(kms) as kms_stub, Stubber(table.meta.client) as ddb_stub:
            yield kms, table, kms_stub, ddb_stub

    def test_erasure_schedules_key_deletion_and_strips_the_ledger(self, stubs):
        kms, table, kms_stub, ddb_stub = stubs
        shredder = CryptoShredder(kms, table, lambda pid: KEY_ARN, pseudonym_key=b"k")
        pseudonym = shredder._pseudonym("dp-1")

        kms_stub.add_response(
            "schedule_key_deletion",
            {"KeyId": KEY_ARN, "KeyState": "PendingDeletion", "PendingWindowInDays": 7},
            {"KeyId": KEY_ARN, "PendingWindowInDays": 7},
        )
        ddb_stub.add_response(
            "update_item",
            {},
            {
                "TableName": "consent_events",
                # The Table resource passes plain values; it adds DynamoDB types after the stub.
                "Key": {"data_principal_id": pseudonym},
                "UpdateExpression": "SET erasure_reason = :r, erased_at = :t REMOVE email, phone",
                "ExpressionAttributeValues": {":r": "consent_withdrawal", ":t": ANY},
            },
        )

        result = shredder.erase_data_principal("dp-1", "consent_withdrawal")

        kms_stub.assert_no_pending_responses()
        ddb_stub.assert_no_pending_responses()
        assert result.deleted_key_arn == KEY_ARN
        assert result.data_principal_id == pseudonym != "dp-1"
        assert result.consent_record_retained

    def test_kms_failure_leaves_the_ledger_untouched(self, stubs):
        kms, table, kms_stub, ddb_stub = stubs
        kms_stub.add_client_error("schedule_key_deletion", service_error_code="KMSInvalidStateException")
        shredder = CryptoShredder(kms, table, lambda pid: KEY_ARN, pseudonym_key=b"k")
        with pytest.raises(kms.exceptions.KMSInvalidStateException):
            shredder.erase_data_principal("dp-1", "consent_withdrawal")
        ddb_stub.assert_no_pending_responses()  # update_item was never called
