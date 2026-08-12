"""Reference SigV4 values produced by botocore (AWS's own SDK signer) for the
same inputs used in our SigV4 unit test. Botocore is part of the AWS SDK
ecosystem, so its output is authoritative for API acceptance."""
import datetime

# Freeze time for botocore's _datetime_now.
class FrozenDT(datetime.datetime):
    @classmethod
    def utcnow(cls):
        return cls(2015, 8, 30, 12, 36, 0)
    @classmethod
    def now(cls, tz=None):
        return cls(2015, 8, 30, 12, 36, 0, tzinfo=tz)

datetime.datetime = FrozenDT

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

creds = Credentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
req = AWSRequest(
    method="GET",
    url="https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
    headers={},
)
auth = SigV4Auth(creds, "iam", "us-east-1")
# Fix date for reproducibility (botocore uses its own clock otherwise).
class FixedAuth(SigV4Auth):
    def _timestamp(self, request):
        return self._datetime_now(request)
    def _datetime_now(self, request=None):
        return datetime.datetime(2015, 8, 30, 12, 36, 0)

FixedAuth(creds, "iam", "us-east-1").add_auth(req)
print("x-amz-date :", req.headers.get("X-Amz-Date"))
print("authorization:", req.headers.get("Authorization"))
print("x-amz-content-sha256:", req.headers.get("x-amz-content-sha256"))
