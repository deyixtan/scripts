#!/bin/python3
# Prerequisite: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION environment variables
import boto3
import botocore
import os


def get_aws_env_vars():
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region = os.getenv("AWS_DEFAULT_REGION")
    
    if not access_key or not secret_key or not region:
        print("[!] AWS credentials are missing in environment variables!")
        print("[!] Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_DEFAULT_REGION.")
        return None
    
    env_vars = {
        "AWS_ACCESS_KEY_ID": access_key,
        "AWS_SECRET_ACCESS_KEY": secret_key,
        "AWS_DEFAULT_REGION": region
    }
    return env_vars


def check_services_available():
    env_vars = get_aws_env_vars()
    if not env_vars:
        return
 
    services_dict = {
        "STS": ("sts", "get_caller_identity", {}),
        "S3": ("s3", "list_buckets", {}),
        "EC2": ("ec2", "describe_instances", {}),
        "Lambda": ("lambda", "list_functions", {}),
        "Athena": ("athena", "list_databases", {}),
        "DynamoDB": ("dynamodb", "list_tables", {}),
        "Secrets Manager": ("secretsmanager", "list_secrets", {}),
        "CloudWatch Logs": ("logs", "describe_log_groups", {}),
        "IAM": ("iam", "list_users", {}),
        "RDS": ("rds", "describe_db_instances", {}),
        "ECS": ("ecs", "list_clusters", {}),
        "EKS": ("eks", "list_clusters", {}),
        "SQS": ("sqs", "list_queues", {}),
        "SNS": ("sns", "list_topics", {}),
        "EFS": ("efs", "describe_file_systems", {}),
        "EBS": ("ec2", "describe_volumes", {}),
        "CloudFormation": ("cloudformation", "list_stacks", {}),
        "KMS": ("kms", "list_keys", {}),
        "Glue": ("glue", "get_databases", {}),
        "ElastiCache": ("elasticache", "describe_cache_clusters", {}),
        "Route 53": ("route53", "list_hosted_zones", {}),
        "CloudFront": ("cloudfront", "list_distributions", {}),
        "Step Functions": ("stepfunctions", "list_state_machines", {}),
        "CodeBuild": ("codebuild", "list_projects", {}),
        "CodeDeploy": ("codedeploy", "list_applications", {}),
        "CodePipeline": ("codepipeline", "list_pipelines", {}),
        "VPC": ("ec2", "describe_vpcs", {}),
        "Subnets": ("ec2", "describe_subnets", {}),
        "Security Groups": ("ec2", "describe_security_groups", {}),
        "Elastic Beanstalk": ("elasticbeanstalk", "describe_applications", {}),
        "Backup": ("backup", "list_backup_jobs", {}),
        "GuardDuty": ("guardduty", "list_detectors", {}),
        "Organizations": ("organizations", "list_accounts", {}),
        "Macie": ("macie2", "list_classification_jobs", {}),
        "Service Quotas": ("service-quotas", "list_service_quotas", {}),
        "SageMaker": ("sagemaker", "list_notebook_instances", {}),
    }

    for service_name in services_dict:
        client_name = services_dict[service_name][0]
        operation = services_dict[service_name][1]
        params = services_dict[service_name][2]

        try:
            client = boto3.client(
                client_name,
                aws_access_key_id=env_vars["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=env_vars["AWS_SECRET_ACCESS_KEY"],
                region_name=env_vars["AWS_DEFAULT_REGION"]
            )
            getattr(client, operation)(**params)
            print(f"  - [+] {service_name} ({operation}) ")
        except Exception as e:
            print(f"  - [-] {service_name} ({operation}), Error: {str(e)}")


def validate_creds():
    env_vars = get_aws_env_vars()
    if not env_vars:
        return

    try:
        sts_client = boto3.client(
            "sts",
            aws_access_key_id=env_vars["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=env_vars["AWS_SECRET_ACCESS_KEY"]
        )
        identity = sts_client.get_caller_identity()

        print(f"[+] Account: {identity['Account']}")
        print(f"[+] User ARN: {identity['Arn']}")
    except botocore.exceptions.ClientError as e:
        print(f"[!] AWS credentials are invalid or have expired: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def list_user_info():
    env_vars = get_aws_env_vars()
    if not env_vars:
        return

    try:
        iam_client = boto3.client(
            "iam",
            aws_access_key_id=env_vars["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=env_vars["AWS_SECRET_ACCESS_KEY"],
            region_name=env_vars["AWS_DEFAULT_REGION"]
        )

        # Get the current IAM user
        user_info = iam_client.get_user()
        user_name = user_info["User"]["UserName"]
        print(f"[+] IAM User: {user_name}")

        # List attached policies
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
        if attached_policies["AttachedPolicies"]:
            print("[+] Attached Policies:")
            for policy in attached_policies["AttachedPolicies"]:
                print(f"  - {policy['PolicyName']} (ARN: {policy['PolicyArn']})")
        else:
            print("[-] No attached policies found.")

        # List inline policies
        inline_policies = iam_client.list_user_policies(UserName=user_name)
        if inline_policies["PolicyNames"]:
            print("[+] Inline Policies:")
            for policy_name in inline_policies["PolicyNames"]:
                print(f"  - {policy_name}")
        else:
            print("[-] No inline policies found.")

        # Get IAM groups for the user
        user_groups = iam_client.list_groups_for_user(UserName=user_name)
        if user_groups["Groups"]:
            print("[+] IAM Groups:")
            for group in user_groups["Groups"]:
                print(f"  - {group['GroupName']} (ARN: {group['Arn']})")
        else:
            print("[-] No IAM groups found.")
    except botocore.exceptions.ClientError as e:
        print(f"[!] AWS IAM error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def list_s3_buckets_metadata():
    env_vars = get_aws_env_vars()
    if not env_vars:
        return

    try:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=env_vars["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=env_vars["AWS_SECRET_ACCESS_KEY"],
            region_name=env_vars["AWS_DEFAULT_REGION"]
        )

        response = s3_client.list_buckets()
        if response.get("Buckets"):
            print("[+] S3 buckets:")
            
            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]
                print(f"  - Bucket Name: {bucket_name}")

                creation_date = bucket["CreationDate"]
                print(f"    - Creation Date: {creation_date}")

                location = s3_client.get_bucket_location(Bucket=bucket_name)
                region = location.get("LocationConstraint", env_vars["AWS_DEFAULT_REGION"])
                print(f"    - Region: {region}")
                
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                version_status = versioning.get("Status", "Disabled")
                print(f"    - Versioning: {version_status}")

                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    enc_rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    encryption_status = enc_rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] if enc_rules else "None"
                except botocore.exceptions.ClientError:
                    encryption_status = "None"
                print(f"    - Encryption: {encryption_status}")

                try:
                    public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                    restrictions = public_access["PublicAccessBlockConfiguration"]
                    block_public_acls = restrictions["BlockPublicAcls"]
                    block_public_policy = restrictions["BlockPublicPolicy"]
                    restrict_public_buckets = restrictions["RestrictPublicBuckets"]
                    print(f"    - Public Access: {'Restricted' if block_public_acls and block_public_policy and restrict_public_buckets else 'Public'}")
                except botocore.exceptions.ClientError:
                    print("    - Public Access: Not Configured")
        else:
            print("[-] No S3 buckets found.")
    except botocore.exceptions.ClientError as e:
        print(f"Error listing buckets: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def list_s3_files_metadata():
    env_vars = get_aws_env_vars()
    if not env_vars:
        return

    try:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=env_vars["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=env_vars["AWS_SECRET_ACCESS_KEY"],
            region_name=env_vars["AWS_DEFAULT_REGION"]
        )

        response = s3_client.list_buckets()
        if response.get("Buckets"):
            print("[+] S3 buckets:")

            for bucket in response["Buckets"]:
                bucket_name = bucket['Name']
                print(f"  - Bucket Name: {bucket_name}")

                try:
                    objects = s3_client.list_objects_v2(Bucket=bucket_name)    
                    if "Contents" in objects:
                        for obj in objects["Contents"]:
                            file_key = obj["Key"]
                            file_name = obj['Key']
                            file_size = obj['Size']
                            last_modified = obj['LastModified']
                            try:
                                metadata = s3_client.head_object(Bucket=bucket_name, Key=file_key)
                                content_type = metadata.get("ContentType", "Unknown")
                            except botocore.exceptions.ClientError:
                                content_type = "Unknown"
                            print(f"  - {file_name} ({content_type}, {file_size} bytes, Last Modified @ {last_modified})")
                    else:
                        print("  - No files found in this bucket.")
                except Exception as e:
                    print(f"  - Error accessing bucket {bucket_name}: {e}")
        else:
            print("[-] No S3 buckets found.")
    except botocore.exceptions.ClientError as e:
        print(f"Error listing buckets: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def list_s3_file_url(bucket_name, file_path):
    env_vars = get_aws_env_vars()
    if not env_vars:
        return

    try:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=env_vars["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=env_vars["AWS_SECRET_ACCESS_KEY"],
            region_name=env_vars["AWS_DEFAULT_REGION"]
        )

        # Check if file exists
        try:
            s3_client.head_object(Bucket=bucket_name, Key=file_path)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                print(f"[!] File '{file_path}' not found in bucket '{bucket_name}'.")
                return
            else:
                print(f"[!] Error checking file: {e}")
                return

        # Public URL
        public_url = f"https://{bucket_name}.s3.amazonaws.com/{file_path}"

        # Check ACL to determine if the file is public
        try:
            acl = s3_client.get_object_acl(Bucket=bucket_name, Key=file_path)
            is_public = any(grant["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers"
                            for grant in acl["Grants"])
        except botocore.exceptions.ClientError:
            is_public = False  # If we cannot retrieve ACL, assume it's private

        # If file is private, generate Pre-Signed URL
        presigned_url = None
        if not is_public:
            print('private')
            try:
                presigned_url = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": bucket_name, "Key": file_path},
                    ExpiresIn=3600  # 1 hour expiration
                )
            except botocore.exceptions.ClientError:
                presigned_url = "Unavailable"

        # Print the results
        print(f"[+] S3 File: {file_path}")
        if not is_public:
            print(f"  - Pre-Signed URL: {presigned_url}")
        else:
            print(f"  - Public URL: {public_url}")

    except botocore.exceptions.ClientError as e:
        print(f"Error generating file URLs: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def list_lambda_functions():
    env_vars = get_aws_env_vars()
    if not env_vars:
        return

    try:
        lambda_client = boto3.client(
            "lambda",
            aws_access_key_id=env_vars["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=env_vars["AWS_SECRET_ACCESS_KEY"],
            region_name=env_vars["AWS_DEFAULT_REGION"]
        )
        response = lambda_client.list_functions()
        
        if response.get("Functions"):
            print("[+] Lambda Functions:")
            
            for function in response.get("Functions", []):
                function_name = function['FunctionName']
                print(f"  - Function Name: {function_name}")
                print(f"  - Runtime: {function['Runtime']}")
                print(f"  - Memory Size: {function['MemorySize']} MB")
                print(f"  - Timeout: {function['Timeout']} seconds")
                print(f"  - Last Modified: {function['LastModified']}")
                print(f"  - ARN: {function['FunctionArn']}")

                code_info = lambda_client.get_function(FunctionName=function_name)
                code_location = code_info["Code"]["Location"]
                print(f"  - Code Location: {code_location}\n")
        else:
            print("[-] No Lambda functions found.")
    except botocore.exceptions.ClientError as e:
        print(f"[!] AWS lambda error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def display_menu():
    while True:
        print("\n[Custom AWS CLI]")
        print("(1) Check services available for AWS credential")
        print("(2) Validate AWS Credentials [Require STS role]")
        print("(3) List User Information [Require IAM role]")
        print("(4) List S3 buckets metadata [Require S3 role]")
        print("(5) List S3 files metadata [Require S3 role]")
        print("(6) Get S3 file URL [Require S3 role]")
        print("(7) List Lambda Functions [Require LAMBDA role]")
        print("(8) Exit")

        choice = input("Select an option: ")
        if choice == "1":
            check_services_available()
        elif choice == "2":
            validate_creds()
        elif choice == "3":
            list_user_info()
        elif choice == "4":
            list_s3_buckets_metadata()
        elif choice == "5":
            list_s3_files_metadata()           
        elif choice == "6":
            bucket_name = input("Please specify the bucket name: ")
            file_path = input("Please specify the file path: ")
            list_s3_file_url(bucket_name, file_path)
        elif choice == "7":
            list_lambda_functions()            
        elif choice == "8":
            break
        else:
            print("[!] Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    display_menu()
