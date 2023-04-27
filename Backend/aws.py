import boto3
import datetime

# Set up AWS credentials and client
session = boto3.Session(
    aws_access_key_id='<access_key>',
    aws_secret_access_key='<secret_key>',
    region_name='<region>'
)
ec2_client = session.client('ec2')
iam_client = session.client('iam')
cloudtrail_client = session.client('cloudtrail')



def check_vm_encryption():
    # Get a list of EC2 instances
    instances = ec2_client.describe_instances()

    # Check each instance for encryption settings
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            # Check if the instance has an encrypted root volume
            encrypted = False
            for block_device_mapping in instance['BlockDeviceMappings']:
                if block_device_mapping['DeviceName'] == instance['RootDeviceName']:
                    if 'Ebs' in block_device_mapping:
                        if 'Encrypted' in block_device_mapping['Ebs']:
                            encrypted = block_device_mapping['Ebs']['Encrypted']
                            break
            
            if not encrypted:
                print(f"EC2 instance '{instance['InstanceId']}' does not have an encrypted root volume.")

def check_vm_access():
    # Get a list of EC2 instances
    instances = ec2_client.describe_instances()

    # Check each instance for security group settings
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            # Get the instance's security group IDs
            security_groups = instance['SecurityGroups']

            # Check each security group for unrestricted access
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_rules = ec2_client.describe_security_group_rules(
                    Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
                )

                # Check if any rule allows unrestricted access
                for rule in sg_rules['SecurityGroupRules']:
                    if rule['IpProtocol'] == '-1' and rule['PrefixListIds'] == [] and rule['UserIdGroupPairs'] == []:
                        print(f"EC2 instance '{instance['InstanceId']}' has unrestricted access in security group '{sg_id}'.")

def check_mfa_enabled():
    # Get a list of IAM users
    users = iam_client.list_users()

    # Check each user for MFA authentication
    for user in users['Users']:
        mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])
        if not mfa_devices['MFADevices']:
            print(f"IAM user '{user['UserName']}' does not have MFA authentication enabled.")

def check_logging():
    # Get a list of CloudTrail trails
    trails = cloudtrail_client.describe_trails()['trailList']

    # Check each trail for logging settings
    for trail in trails:
        trail_status = cloudtrail_client.get_trail_status(Name=trail['Name'])
        if not trail_status['IsLogging']:
            print(f"CloudTrail trail '{trail['Name']}' is not logging API activity.")

def check_patches():
    # Get a list of EC2 instances
    instances = ec2_client.describe_instances()

    # Check each instance for pending updates
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            patch_data = ec2_client.describe_instance_patches(InstanceId=instance['InstanceId'])
            if patch_data['PendingCount'] > 0:
                print(f"EC2 instance '{instance['InstanceId']}' has {patch_data['PendingCount']} pending updates.")

def check_unused_resources():
    # Get a list of EC2 instances
    instances = ec2_client.describe_instances()

    # Set the time range for identifying unused resources
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=30)

    # Check each instance for activity within the past 30 days
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'ResourceName', 'AttributeValue': instance['InstanceId']},
                ],
                StartTime=start_time,
                EndTime=end_time
            )
            if not response['Events']:
                print(f"EC2 instance '{instance['InstanceId']}' has not been used within the past 30 days.")
