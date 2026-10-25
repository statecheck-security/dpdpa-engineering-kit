# Semgrep test fixture for dpdpa-rules.yml (run: semgrep --test ci-cd/semgrep/).
# "ruleid:" marks a line the rule must flag, "ok:" a line it must not.
import logging

from django.db import models
from rest_framework import serializers

logger = logging.getLogger(__name__)


def notify(user, order_id):
    # ruleid: dpdpa-pii-in-logs
    logger.info("welcome %s", user.email)
    # ruleid: dpdpa-pii-in-logs
    logging.warning("otp sent to %s", user.phone)
    # ok: dpdpa-pii-in-logs
    logger.info("order %s shipped", order_id)


class Customer(models.Model):
    # ruleid: dpdpa-unencrypted-pii-storage
    email = models.CharField(max_length=254)
    # ruleid: dpdpa-unencrypted-pii-storage
    aadhaar = models.CharField(max_length=12)
    # ok: dpdpa-unencrypted-pii-storage
    order_ref = models.CharField(max_length=20)


# ruleid: dpdpa-excessive-data-collection
class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'


# ok: dpdpa-excessive-data-collection
class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ["order_ref"]
