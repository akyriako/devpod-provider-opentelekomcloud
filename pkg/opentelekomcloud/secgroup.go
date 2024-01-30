package opentelekomcloud

import (
	"fmt"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/secgroups"
)

func (o *OpenTelekomCloudProvider) addServerInSecurityGroup(serverId string, securityGroupId string) error {
	err := secgroups.AddServer(o.ecsv2ServiceClient, serverId, securityGroupId).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}

func (o *OpenTelekomCloudProvider) removeServerFromSecurityGroup(serverId string, securityGroupId string) error {
	err := secgroups.RemoveServer(o.ecsv2ServiceClient, serverId, securityGroupId).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}

func (o *OpenTelekomCloudProvider) createSecurityGroup() (string, error) {
	sg, err := secgroups.Create(o.ecsv2ServiceClient, secgroups.CreateOpts{
		Name:        fmt.Sprintf("sg-%s-allow-ssh", o.Config.MachineID),
		Description: "Used to remotely connect to DevPod instances via SSH",
	}).Extract()
	if err != nil {
		return "", err
	}

	_, err = secgroups.CreateRule(o.ecsv2ServiceClient, secgroups.CreateRuleOpts{
		ParentGroupID: sg.ID,
		FromPort:      22,
		ToPort:        22,
		IPProtocol:    "TCP",
		CIDR:          "0.0.0.0/0",
	}).Extract()
	if err != nil {
		return "", err
	}

	return sg.ID, nil
}

func (o *OpenTelekomCloudProvider) deleteSecurityGroup(securityGroupId string) error {
	err := secgroups.Delete(o.ecsv2ServiceClient, securityGroupId).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}

func (o *OpenTelekomCloudProvider) getSecurityGroup(serverId string, securityGroupName string) (*secgroups.SecurityGroup, error) {
	allPages, err := secgroups.ListByServer(o.ecsv2ServiceClient, serverId).AllPages()
	if err != nil {
		return nil, err
	}

	securityGroups, err := secgroups.ExtractSecurityGroups(allPages)
	if err != nil {
		return nil, err
	}

	for _, securityGroup := range securityGroups {
		if securityGroup.Name == securityGroupName {
			return &securityGroup, nil
		}
	}

	return nil, fmt.Errorf("devpod security group '%s' was not found", securityGroupName)
}
