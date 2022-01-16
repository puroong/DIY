import json
import logging
import uuid
from pprint import pprint
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from boto3_wrapper import IamClient, StsClient, CloudTrailClient, S3Client, TrailEvents

session = boto3.Session()


class AwsPassword:
    def __init__(self):
        uuid4 = str(uuid.uuid4()).replace("-", "")
        uuid4_length = len(uuid4)

        upper_half = uuid4[:uuid4_length//2]
        lower_half = uuid4[uuid4_length//2:]

        self._value = upper_half.upper() + lower_half.lower()

    @property
    def value(self):
        return self._value


ADMIN_ACCESS_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"


class AwsUser:
    def __init__(self, *, name: str, policy_arn=None):
        self.name = name
        self.password = AwsPassword().value
        self.policy_arns = policy_arn or [ADMIN_ACCESS_POLICY]


class Trail:
    def __init__(self, *, name: str, bucket_name: str):
        self.name = name
        self.bucket_name = bucket_name


class AwsUserRepository:
    def __init__(self, *, iam_client: IamClient, sts_client: StsClient):
        self._iam_client = iam_client
        self._sts_client = sts_client

    def create_user(self, *, user: AwsUser):
        self._iam_client.create_user(name=user.name)

        for policy_arn in user.policy_arns:
            self._iam_client.attach_user_policy(name=user.name, policy_arn=policy_arn)

        self._iam_client.create_login_profile(username=user.name, password=user.password)

    def print_login_info(self, *, user: AwsUser):
        account_id = self._sts_client.get_caller_identity().Account

        print(f"""
        https://{account_id}.signin.aws.amazon.com/console

        username: {user.name}
        password: {user.password}
        """)

    def delete_user(self, *, user: AwsUser):
        self._iam_client.delete_login_profile(username=user.name)

        for policy_arn in user.policy_arns:
            self._iam_client.detach_user_policy(name=user.name, policy_arn=policy_arn)

        self._iam_client.delete_user(name=user.name)


class CloudTrailRepository:
    @classmethod
    def get_bucket_policy(cls, *, account_id: str, region_name: str, trail: Trail):
        return f"""{{
            "Version": "2012-10-17",
            "Statement": [
                {{
                    "Sid": "AWSCloudTrailAclCheck20150319",
                    "Effect": "Allow",
                    "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
                    "Action": "s3:GetBucketAcl",
                    "Resource": "arn:aws:s3:::{trail.bucket_name}"
                }},
                {{
                    "Sid": "AWSCloudTrailWrite20150319",
                    "Effect": "Allow",
                    "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::{trail.bucket_name}/AWSLogs/{account_id}/*",
                    "Condition": {{
                        "StringEquals": {{
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            "aws:SourceArn": "arn:aws:cloudtrail:{region_name}:{account_id}:trail/{trail.name}"
                        }}
                    }}
                }}
            ]
        }}"""

    def __init__(self, *, cloud_trail_client: CloudTrailClient, s3_client: S3Client, sts_client: StsClient):
        self._cloud_trail_client = cloud_trail_client
        self._s3_client = s3_client
        self._sts_client = sts_client

    def create_trail(self, *, trail: Trail):
        if not self._s3_client.bucket_exists(name=trail.bucket_name):
            account_id = self._sts_client.get_caller_identity().Account

            policy = self.get_bucket_policy(account_id=account_id, region_name=self._cloud_trail_client.session.region_name, trail=trail)
            self._s3_client.create_bucket(name=trail.bucket_name)
            self._s3_client.put_bucket_policy(name=trail.bucket_name, policy=policy)

        self._cloud_trail_client.create_trail(name=trail.name, bucket_name=trail.bucket_name)

    def delete_trail(self, *, trail: Trail):
        # TODO: boto3 client / resource 둘 중 하나로 통일하는게 좋을 듯
        bucket = session.resource('s3').Bucket(trail.bucket_name)
        bucket.objects.all().delete()
        self._s3_client.delete_bucket(name=trail.bucket_name)
        self._cloud_trail_client.delete_trail(name=trail.name)

    def get_events_by_username(self, *, username: str) -> TrailEvents:
        return self._cloud_trail_client.lookup_events(lookup_attributes=[{
            "AttributeKey": "Username",
            "AttributeValue": username
        }])


class CloudTrailService:
    def __init__(self, *, cloud_trail_repository: CloudTrailRepository):
        self._cloud_trail_repository = cloud_trail_repository

    def create_trail(self, *, trail: Trail):
        self._cloud_trail_repository.create_trail(trail=trail)

    def delete_trail(self, *, trail: Trail):
        self._cloud_trail_repository.delete_trail(trail=trail)

    def list_permisssions(self, *, username: str) -> List[str]:
        events = self._cloud_trail_repository.get_events_by_username(username=username).Events

        required_permissions = set()
        for event in events:
            cloud_trail_event = json.loads(event.CloudTrailEvent)
            if not cloud_trail_event.get("errorCode"):
                required_permissions.add((f"{event.EventName}, {event.Resources}"))

        return list(required_permissions)

class UserContainer:
    def __init__(self, *, user_repository: AwsUserRepository):
        self._user_repository = user_repository
        self._users: List[AwsUser] = []

    def print_login_info(self, *, user: AwsUser):
        self._user_repository.print_login_info(user=user)

    def add_user(self, *, user: AwsUser):
        try:
            self._user_repository.create_user(user=user)
            self._users.append(user)
        except ClientError as e:
            logging.error(e)

    def remove_user(self, *, user: AwsUser):
        try:
            self._user_repository.delete_user(user=user)
            self._users.remove(user)
        except ClientError as e:
            logging.error(e)

    def remove_all_user(self):
        try:
            for user in self._users:
                self._user_repository.delete_user(user=user)
                self._users.remove(user)
        except ClientError as e:
            logging.error(e)

    def find(self, *, name: str) -> Optional[AwsUser]:
        for user in self._users:
            if user.name == name:
                return user


class PermissionChecker:
    def __init__(self, *, user_container: UserContainer, cloud_trail_service: CloudTrailService, trail: Trail):
        self._user_container = user_container
        self._cloud_trail_service = cloud_trail_service

        self._trail = trail

    def initialize(self):
        self._cloud_trail_service.create_trail(trail=self._trail)

    def destroy(self):
        self._cloud_trail_service.delete_trail(trail=self._trail)
        self._user_container.remove_all_user()

    def run(self):
        username = input("username:").strip()
        new_user = AwsUser(name=username)
        self._user_container.add_user(user=new_user)

        self._user_container.print_login_info(user=new_user)
        print(f"""
        ACCESS WEB CONSOLE AND 
        
        PRESS ENTER TO LIST REQUIRED PERMISSIONS
        """)

        input()

        permissions = self._cloud_trail_service.list_permisssions(username=new_user.name)
        print(permissions)


if __name__ == "__main__":
    trail_name = input("TRAIL NAME:")
    bucket_name = input("BUCKET NAME(PRESS ENTER TO SKIP):") or f"{trail_name}-bucket-{uuid.uuid4()}"
    trail = Trail(name=trail_name, bucket_name=bucket_name)

    permchk = PermissionChecker(
        user_container=UserContainer(
            user_repository=AwsUserRepository(
                iam_client=IamClient(session=session),
                sts_client=StsClient(session=session)
            )
        ),
        cloud_trail_service=CloudTrailService(
            cloud_trail_repository=CloudTrailRepository(
                cloud_trail_client=CloudTrailClient(session=session),
                s3_client=S3Client(session=session),
                sts_client=StsClient(session=session)
            )
        ),
        trail=trail
    )

    permchk.initialize()
    permchk.run()
    permchk.destroy()
