package opentelekomcloud

import "github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/secgroups"

func (o *OpenTelekomCloudProvider) addSecurityGroup(serverId string) error {
	err := secgroups.AddServer(o.ecsv2ServiceClient, serverId, o.Config.SecurityGroupId).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}
