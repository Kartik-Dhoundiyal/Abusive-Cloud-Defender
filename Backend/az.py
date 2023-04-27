# import the dependencies
import os
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.storage.blob import BlobServiceClient
from azure.graphrbac import GraphRbacManagementClient
from datetime import timedelta,datetime

def check_vm_encryption(vm):
    # Check if the VM is encrypted and if the encryption is properly configured
    compute_credentials = ClientSecretCredential(
        tenant_id=os.environ['AZURE_TENANT_ID'],
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET']
    )
    compute_client = ComputeManagementClient(
        credentials=compute_credentials,
        subscription_id=os.environ['AZURE_SUBSCRIPTION_ID']
    )
    vm_encryption = compute_client.virtual_machines.get(
        os.environ['AZURE_RESOURCE_GROUP_NAME'],
        vm.name,
        expand='instanceView'
    ).instance_view.vm_agent.extension_handler_instance_view_list[0].status.split(';')
    if vm_encryption[0] != 'Provisioning succeeded' or vm_encryption[1] != 'Ready':
        print(f'{vm.name}: VM encryption is not properly configured.')
    elif 'Encrypted' not in vm_encryption[2]:
        print(f'{vm.name}: VM is not encrypted.')

def check_vm_access(vm):
    # Check if access to the VM is restricted and if the access policies are properly configured
    compute_credentials = ClientSecretCredential(
        tenant_id=os.environ['AZURE_TENANT_ID'],
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET']
    )
    compute_client = ComputeManagementClient(
        credentials=compute_credentials,
        subscription_id=os.environ['AZURE_SUBSCRIPTION_ID']
    )
    vm_id = vm.id.split('/')[-1]
    network_interfaces = compute_client.network_interfaces.list_virtual_machine_scale_set_vm_network_interfaces(
        os.environ['AZURE_RESOURCE_GROUP_NAME'],
        os.environ['AZURE_SCALE_SET_NAME'],
        vm_id
    )
    public_ips = []
    for nic in network_interfaces:
        if nic.ip_configurations[0].public_ip_address is not None:
            public_ips.append(nic.ip_configurations[0].public_ip_address.id.split('/')[-1])
    if len(public_ips) > 0:
        print(f'{vm.name}: VM access is not properly restricted. Public IP addresses: {", ".join(public_ips)}')


def check_mfa_enabled():
    # Check if multi-factor authentication (MFA) is enabled for the account and if it is properly configured
    graph_credentials = ClientSecretCredential(
        tenant_id=os.environ['AZURE_TENANT_ID'],
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET']
    )
    graph_client = GraphRbacManagementClient(
        credentials=graph_credentials,
        tenant_id=os.environ['AZURE_TENANT_ID']
    )
    user = graph_client.users.get(os.environ['AZURE_USER_OBJECT_ID'])
    if user.strong_authentication_methods is None:
        print('MFA is not enabled for the user account.')
    else:
        for auth_method in user.strong_authentication_methods:
            if auth_method.method_type == 'Microsoft.Azure.ActiveDirectory.PhoneAppNotification':
                print('MFA is properly configured with Phone App Notification.')
                break

def check_logging():
    # Check if logging and monitoring are properly configured for the resources
    credentials = ClientSecretCredential(
        tenant_id=os.environ['AZURE_TENANT_ID'],
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET']
    )
    monitor_client = MonitorManagementClient(
        credentials=credentials,
        subscription_id=os.environ['AZURE_SUBSCRIPTION_ID']
    )

    # Set the time range to check for log data
    duration = timedelta(minutes=10)
    end_time = datetime.utcnow()
    start_time = end_time - duration

    # Query for log data in Azure Monitor
    query = "AzureActivity | where TimeGenerated > datetime({}) and TimeGenerated < datetime({})".format(start_time.isoformat(), end_time.isoformat())
    result = monitor_client.query_resources(query)

    # Check if any log data was returned
    if len(result.tables[0].rows) > 0:
        print("Logging is properly configured.")
    else:
        print("No log data was found. Logging may not be properly configured.")

def check_patches():
    # Check if the latest security patches are applied to the resources
    credentials = ClientSecretCredential(
        tenant_id=os.environ['AZURE_TENANT_ID'],
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET']
    )
    compute_client = ComputeManagementClient(
        credentials=credentials,
        subscription_id=os.environ['AZURE_SUBSCRIPTION_ID']
    )

    # Get a list of all virtual machines in the subscription
    vm_list = compute_client.virtual_machines.list_all()

    # Set the time range for checking updates
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)

    # Check each virtual machine for installed security patches
    for vm in vm_list:
        # Get the status of security patches on the virtual machine
        patch_status = compute_client.virtual_machines.list_patches(vm.resource_group, vm.name, start_time=start_time, end_time=end_time)

        # Check if any security patches are missing
        if any(patch.installation_state != "Installed" for patch in patch_status):
            print(f"Security patches are missing on VM '{vm.name}' in resource group '{vm.resource_group}'.")
        else:
            print(f"All security patches are installed on VM '{vm.name}' in resource group '{vm.resource_group}'.")

def check_unused_resources():
    # Check
    # Set up Azure credentials and client
    credentials = ClientSecretCredential(
        tenant_id=os.environ['AZURE_TENANT_ID'],
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET']
    )
    resource_client = ResourceManagementClient(
        credentials=credentials,
        subscription_id=os.environ['AZURE_SUBSCRIPTION_ID']
    )

    # Set the time range for identifying unused resources
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=30)

    # Get a list of all resources in the subscription
    resource_list = resource_client.resources.list()

    # Check each resource for activity within the past 30 days
    for resource in resource_list:
        activity = resource_client.activity_logs.list(
            filter=f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}' and resourceId eq '{resource.id}'"
        )
        if len(list(activity)) == 0:
            print(f"Resource '{resource.id}' has not been used within the past 30 days.")
            
            
            