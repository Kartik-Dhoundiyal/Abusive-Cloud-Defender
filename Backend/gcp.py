from google.cloud import compute_v1
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
# Set up GCP credentials and client
client = compute_v1.InstancesClient.from_service_account_json('<path_to_service_account_key>')
creds = Credentials.from_authorized_user_file('<path_to_credentials_file>')
iam = build('iam', 'v1', credentials=creds)
logging = build('logging', 'v2', credentials=creds)
compute = build('compute', 'v1', credentials=creds)
resource_manager = build('cloudresourcemanager', 'v1', credentials=creds)

def check_vm_encryption():
    # Get a list of VM instances
    instances = client.aggregated_list_instances(requested_project='<project_id>')

    # Check each instance for encryption settings
    for _, instances_scoped_list in instances.items():
        for instance in instances_scoped_list.instances:
            # Check if the instance has an encrypted boot disk
            for disk in instance.disks:
                if disk.boot:
                    if not disk.initialize_params.disk_encryption_key:
                        print(f"VM instance '{instance.name}' does not have an encrypted boot disk.")

def check_vm_access():
    # Get a list of VM instances
    instances = client.aggregated_list_instances(requested_project='<project_id>')

    # Check each instance for firewall settings
    for _, instances_scoped_list in instances.items():
        for instance in instances_scoped_list.instances:
            # Get the instance's network interface configuration
            for nic in instance.network_interfaces:
                # Check if the NIC has a firewall rule that allows unrestricted access
                for access_config in nic.access_configs:
                    firewall_rules = client.list_firewall_policies(
                        request={
                            "parent": f"projects/{'<project_id>'}/locations/{access_config.nat_ip_address.region}/firewallPolicies/{'<firewall_policy_name>'}"
                        }
                    )
                    for rule in firewall_rules:
                        if rule.action == "allow" and rule.source_ranges == ["0.0.0.0/0"] and rule.direction == "INGRESS":
                            print(f"VM instance '{instance.name}' has unrestricted access in firewall policy '{rule.name}'.")

def check_mfa_enabled():
    # Get a list of all IAM users in the GCP project
    users = iam.projects().serviceAccounts().list(name=f'projects/<project_id>').execute()

    # Check if each user has MFA enabled
    for user in users['accounts']:
        if 'name' in user:
            mfa_enabled = False
            # Check if MFA is enabled for the user's account
            mfa = iam.projects().serviceAccounts().getIamPolicy(resource=user['name'], body={}).execute()
            for binding in mfa['bindings']:
                if binding['role'] == 'roles/iam.securityAdmin':
                    if 'condition' in binding and 'expression' in binding['condition']:
                        if 'title' in binding['condition']['expression']:
                            if 'multiFactorAuthMethodsRequireAll' in binding['condition']['expression']['title']:
                                mfa_enabled = True
                                break
            # Print a message if MFA is not enabled for the user's account
            if not mfa_enabled:
                print(f"Multi-factor authentication is not enabled for IAM user '{user['email']}'")

def check_logging():
    # Define the list of necessary logs
    necessary_logs = [
        'activity',
        'admin',
        'system_event',
        'data_access'
    ]

    # Get a list of all available logs in the GCP project
    logs = logging.projects().logs().list(projectId='<project_id>').execute()

    # Check if each necessary log is enabled
    for log in logs['logs']:
        if log['name'] in necessary_logs:
            if not log['enabled']:
                print(f"Logging is not enabled for the '{log['name']}' log.")

def check_patches():
    # Define the list of necessary patches
    necessary_patches = [
        'CVE-2021-3156',
        'CVE-2020-1967',
        'CVE-2019-14615'
    ]

    # Get a list of all VM instances in the GCP project
    instances = compute.instances().list(project='<project_id>', zone='<zone>').execute()

    # Check if each necessary patch is installed on each VM instance
    for instance in instances['items']:
        for patch in necessary_patches:
            # Check if the patch is installed on the instance
            output = compute.instances().getSerialPortOutput(project='<project_id>', zone='<zone>', instance=instance['name'], port=1, start=0).execute()
            if patch not in output['contents']:
                print(f"Patch '{patch}' is not installed on VM instance '{instance['name']}'.")

def check_unused_resources():
    # Get a list of all resources in the GCP project
    resources = resource_manager.projects().getAncestry(resource='<project_id>').execute()

    # Check if each resource is in use
    for resource in resources['ancestor']:
        if 'resourceId' in resource:
            if 'status' in resource and resource['status'] == 'DELETE_REQUESTED':
                print(f"Resource '{resource['resourceId']}' is marked for deletion.")
            else:
                usage = resource_manager.projects().getIamPolicy(resource='<project_id>', body={'options': {'requestedPolicyVersion': 3}}).execute()
                if not usage['bindings']:
                    print(f"Resource '{resource['resourceId']}' is not in use.")
                
