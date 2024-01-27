package opentelekomcloud

import (
	"fmt"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/options"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/common/tags"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/floatingips"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
)

func (o *OpenTelekomCloudProvider) createElasticIpAddress() (*floatingips.FloatingIP, error) {
	// Allocate a floating IP
	fip, err := floatingips.Create(o.ecsv2ServiceClient, floatingips.CreateOpts{
		Pool: "admin_external_net",
	}).Extract()
	if err != nil {
		return nil, err
	}

	return fip, err
}

func (o *OpenTelekomCloudProvider) getElasticIpAddress(floatingIpId string) (*floatingips.FloatingIP, error) {
	fip, err := floatingips.Get(o.ecsv2ServiceClient, floatingIpId).Extract()
	if err != nil {
		return nil, err
	}

	return fip, nil
}

func (o *OpenTelekomCloudProvider) associateElasticIpAddress(serverId string, fip *floatingips.FloatingIP) error {
	// Associate the floating IP with the server
	associateOpts := floatingips.AssociateOpts{
		FloatingIP: fip.IP,
	}

	err := floatingips.AssociateInstance(o.ecsv2ServiceClient, serverId, associateOpts).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}

func (o *OpenTelekomCloudProvider) deleteElasticIpAddress(floatingIpId string) error {
	// Deletes the floating IP
	err := floatingips.Delete(o.ecsv2ServiceClient, floatingIpId).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}

func (o *OpenTelekomCloudProvider) getExternalIpAndPort(server servers.Server) (string, int, error) {
	o.getServerIpAddresses(server)

	if o.Config.UseNatGateway() {
		resourceTags, err := tags.Get(o.ecsv1ServiceClient, "cloudservers", server.ID).Extract()
		if err != nil {
			return "", -1, err
		}

		rts := resourceTags[:]
		for _, tag := range rts {
			if tag.Key == dnatRuleIdTagKey {
				natPublicIp, outsidePort, err := o.getDnatRuleElasticIpAddress(tag.Value)
				if err != nil {
					return "", -1, err
				}

				o.Config.PublicIp = natPublicIp
				o.Config.Port = outsidePort
				break
			}
		}
	}

	if o.Config.Port == 0 {
		o.Config.Port = options.DefaultSshPort
	}

	if o.Config.PublicIp == "" {
		return "", -1, fmt.Errorf("no public ip was found for: %s", server.Name)
	}

	return o.Config.PublicIp, o.Config.Port, nil
}

func (o *OpenTelekomCloudProvider) getServerIpAddresses(server servers.Server) (string, string) {
	for _, v1 := range server.Addresses {
		addresses := v1.([]interface{})
		for _, v2 := range addresses {
			address := v2.(map[string]interface{})
			if address["OS-EXT-IPS:type"] == "floating" {
				o.Config.PublicIp = address["addr"].(string)
			} else if address["OS-EXT-IPS:type"] == "fixed" {
				o.Config.PrivateIp = address["addr"].(string)
			}
		}
	}

	return o.Config.PublicIp, o.Config.PrivateIp
}
