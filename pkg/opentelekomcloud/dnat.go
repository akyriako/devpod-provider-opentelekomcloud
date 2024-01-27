package opentelekomcloud

import (
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/options"
	"github.com/loft-sh/devpod/pkg/random"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/networking/v2/extensions/dnatrules"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/networking/v2/extensions/portsecurity"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/networking/v2/ports"
)

func (o *OpenTelekomCloudProvider) getDnatRuleElasticIpAddress(dnatRuleId string) (string, int, error) {
	dnatRule, err := dnatrules.Get(o.natv2ServiceClient, dnatRuleId)
	if err != nil {
		return "", -1, err
	}

	return dnatRule.FloatingIpAddress, dnatRule.ExternalServicePort, nil
}

func (o *OpenTelekomCloudProvider) createDnatRule(serverId string) (string, error) {
	serverPortId, err := o.getServerPortId(serverId)
	if err != nil {
		return "", err
	}
	o.Config.ServerPortId = serverPortId

	dnatRules, err := o.getDnatRules(o.Config.NatGatewayId)
	if err != nil {
		return "", err
	}

	internalServicePort := options.DefaultSshPort
	var externalServicePort int

	for externalServicePort == 0 || o.isPortAlreadyUsedInDnatRules(dnatRules, externalServicePort) {
		externalServicePort = random.InRange(dnatRuleMinOutsidePort, dnatRuleMaxOutsidePort)
	}

	createOpts := dnatrules.CreateOpts{
		NatGatewayID:        o.Config.NatGatewayId,
		PortID:              o.Config.ServerPortId,
		InternalServicePort: &internalServicePort,
		FloatingIpID:        o.Config.FloatingIpId,
		ExternalServicePort: &externalServicePort,
		Protocol:            "TCP",
	}

	dnatRule, err := dnatrules.Create(o.natv2ServiceClient, createOpts)
	if err != nil {
		return "", err
	}

	return dnatRule.ID, nil
}

func (o *OpenTelekomCloudProvider) deleteDnatRule(dnatRuleId string) error {
	err := dnatrules.Delete(o.natv2ServiceClient, dnatRuleId)
	if err != nil {
		return err
	}

	return nil
}

func (o *OpenTelekomCloudProvider) getDnatRules(natGatewayId string) ([]dnatrules.DnatRule, error) {
	dnatRules, err := dnatrules.List(o.natv2ServiceClient, dnatrules.ListOpts{
		NatGatewayId: natGatewayId,
	})
	if err != nil {
		return nil, err
	}

	return dnatRules, nil
}

func (o *OpenTelekomCloudProvider) isPortAlreadyUsedInDnatRules(dnatRules []dnatrules.DnatRule, port int) bool {
	for _, dnatRule := range dnatRules {
		if dnatRule.ExternalServicePort == port {
			return true
		}
	}

	return false
}

func (o *OpenTelekomCloudProvider) getServerPortId(serverId string) (string, error) {
	type portWithExt struct {
		ports.Port
		portsecurity.PortSecurityExt
	}

	var allPorts []portWithExt
	allPages, err := ports.List(o.netv2ServiceClient, ports.ListOpts{
		DeviceID: serverId,
	}).AllPages()
	if err != nil {
		return "", err
	}

	err = ports.ExtractPortsInto(allPages, &allPorts)
	if err != nil {
		return "", err
	}

	return allPorts[0].ID, nil
}
