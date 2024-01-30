# Open Telekom Cloud Provider for DevPod

The Open Telekom Cloud provider for [Loft Labs' DevPod](https://github.com/loft-sh/devpod).

_That is a community project, not an officially supported one by T-Systems International GmbH._

## Overview

Open Telekom Cloud is an **OpenStack-based** public cloud offering from German leading IT services provider 
T-Systems International GmbH, a subsidiary company of the Deutsche Telekom Group. Open Telekom Cloud offers 
Infrastructure as a Service (IaaS) from the public cloud. Companies of all sizes and in all industries can 
obtain computing resources flexibly at the push of a button and benefit from all the advantages of a 
public cloud environment with the highest security and the strictest data protection according to the 
GDPR and extreme flexible and competitive price models.

## Installation

### Using the CLI

The provider is available for auto-installation using the following commands:

```sh
devpod provider add github.com/akyriako/devpod-provider-opentelekomcloud
devpod provider use github.com/akyriako/devpod-provider-opentelekomcloud
```

### Pre-requisites

You will need to provision to your tenant the following resources before being able to use the DevPod provider:

- A VPC `Network` & a `Subnet` with internet access
- A `Security Group` allowing port 22 (If **not** provided it will be created automatically)
- A `NAT Gateway` and its associated `Elastic IP` address (**only if** NAT Gateway is going to be used otherwise VMs can be accessed
  directly using an `Elastic IP` address that will be automatically allocated or released)
- An `AK/SK` pair in the region and project that the VMs are going to be provisioned

### Configuration

| NAME                 | REQUIRED | DESCRIPTION                                       | DEFAULT                      |
|----------------------|----------|---------------------------------------------------|------------------------------|
| OTC_ACCESS_KEY       | true     | Open Telekom Cloud Access Key                     |                              |
| OTC_SECRET_KEY       | true     | Open Telekom Cloud Secret Key                     |                              |
| OTC_TENANT_NAME      | true     | Tenant's Name                                     |                              |
| OTC_REGION           | true     | Region (e.g. eu-de or eu-nl or eu-ch)             |                              |
| OTC_FLAVOR_ID        | true     | Flavor to use for sizing                          | s3.large.2                   |
| OTC_DISK_IMAGE       | true     | Virtual Machine's Disk Image                      | Standard_Ubuntu_22.04_latest |
| OTC_DISK_SIZE        | true     | Virtual Machine's Disk Size (in GB)               | 40                           |
| OTC_NETWORK_ID       | true     | **Subnet** ID to place the VM into                |                              |
| OTC_SECURITYGROUP_ID | false    | Security Group ID to use with this VM             |                              |
| OTC_NATGATEWAY_ID    | false    | NAT Gateway ID (to use instead of individual EIP) |                              |
| OTC_FLOATINGIP_ID    | false    | EIP ID to associate with NAT Gateway DNAT Rules   |                              |
| PROXY_HOST           | false    | SOCKS Host                                        |                              |
| SOCKS_PORT           | false    | SOCKS v5 Port                                     | 1080                         |

**Note**: If you intend to use a NAT Gateway you should have already created an EIP and insert its ID in `OTC_FLOATINGIP_ID`
          If not, the provider will take care creating and destroying the necessary EIP needed to access your VM.

