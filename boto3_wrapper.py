from datetime import datetime
from functools import wraps
from typing import List, Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel


def log_client_error(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


class CallerIdentity(BaseModel):
    UserId: str
    Account: str
    Arn: str


class TrailEvents(BaseModel):
    class Event(BaseModel):
        class Resource(BaseModel):
            ResourceType: str
            ResourceName: str

        EventId: str
        EventName: str
        ReadOnly: str
        AccessKeyId: str
        EventTime: datetime
        EventSource: str
        Username: str
        Resources: List[Resource]
        CloudTrailEvent: str

    Events: List[Event]
    NextToken: Optional[str]


class IamClient:
    def __init__(self, *, session):
        self.session = session
        self.client = session.client("iam")

    @log_client_error
    def create_user(self, *, name: str):
        self.client.create_user(
            UserName=name
        )

    @log_client_error
    def delete_user(self, *, name):
        self.client.delete_user(
            UserName=name
        )

    @log_client_error
    def attach_user_policy(self, *, name: str, policy_arn: str):
        self.client.attach_user_policy(
            UserName=name,
            PolicyArn=policy_arn
        )

    @log_client_error
    def detach_user_policy(self, *, name: str, policy_arn: str):
        self.client.detach_user_policy(
            UserName=name,
            PolicyArn=policy_arn
        )

    @log_client_error
    def create_login_profile(self, *, username: str, password: str, password_reset_required=False):
        self.client.create_login_profile(
            UserName=username,
            Password=password,
            PasswordResetRequired=password_reset_required
        )

    @log_client_error
    def delete_login_profile(self, *, username: str):
        self.client.delete_login_profile(
            UserName=username,
        )


class StsClient:
    def __init__(self, *, session):
        self.session = session
        self.client = session.client("sts")

    @log_client_error
    def get_caller_identity(self) -> CallerIdentity:
        return CallerIdentity(**self.client.get_caller_identity())


class CloudTrailClient:
    def __init__(self, *, session):
        self.session = session
        self.client = session.client("cloudtrail")

    @log_client_error
    def create_trail(self, *, name: str, bucket_name: str):
        self.client.create_trail(Name=name, S3BucketName=bucket_name)

    @log_client_error
    def delete_trail(self, *, name):
        self.client.delete_trail(Name=name)

    def lookup_events(self, lookup_attributes: List[dict]) -> TrailEvents:
        return TrailEvents(**self.client.lookup_events(LookupAttributes=lookup_attributes))


class S3Client:
    def __init__(self, *, session):
        self.session = session
        self.client = session.client("s3")

    def bucket_exists(self, *, name: str):
        try:
            self.head_bucket(name=name)
            exists = True
        except ClientError:
            exists = False

        return exists

    @log_client_error
    def head_bucket(self, *, name: str):
        return self.client.head_bucket(Bucket=name)

    @log_client_error
    def create_bucket(self, *, name: str):
        self.client.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={
                'LocationConstraint': self.session.region_name
            },
        )

    @log_client_error
    def put_bucket_policy(self, *, name: str, policy: str):
        self.client.put_bucket_policy(Bucket=name, Policy=policy)

    @log_client_error
    def delete_bucket(self,  *,  name: str):
        self.client.delete_bucket(Bucket=name)
