package opentelekomcloud

import (
	"encoding/base64"
	"fmt"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/options"
	"github.com/loft-sh/devpod/pkg/random"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/common/tags"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/floatingips"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/keypairs"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/secgroups"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/startstop"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/networking/v2/extensions/dnatrules"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/networking/v2/extensions/portsecurity"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/networking/v2/ports"
	"time"
)

const (
	devpodTagKey           = "devpod"
	devpodKeyPairName      = "KeyPair-DevPod"
	dnatRuleIdTagKey       = "dnat"
	floatingIpIdTagKey     = "fip"
	dnatRuleMinOutsidePort = 10000
	dnatRuleMaxOutsidePort = 19999
)

func (o *OpenTelekomCloudProvider) getAllServers() ([]servers.Server, error) {
	allPages, err := servers.List(o.ecsv2ServiceClient, servers.ListOpts{
		Limit: 1000,
	}).AllPages()
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("getting all server pages failed: %s", err.Error()))
	}

	allServers, err := servers.ExtractServers(allPages)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("extracting all server pages failed: %s", err.Error()))

	}

	return allServers, nil
}

func (o *OpenTelekomCloudProvider) getServer(serverId string) (*servers.Server, error) {
	allServers, err := o.getAllServers()
	if err != nil {
		return nil, err
	}

	for _, server := range allServers {
		resourceTags, err := tags.Get(o.ecsv1ServiceClient, "cloudservers", server.ID).Extract()
		if err != nil {
			return nil, err
		}

		rts := resourceTags[:]
		for _, tag := range rts {
			if tag.Key == devpodTagKey && tag.Value == serverId {
				return &server, nil
			}
		}
	}

	return nil, fmt.Errorf("found no devpod machine with id: %s", serverId)
}

func (o *OpenTelekomCloudProvider) startServer(serverId string) {
	startstop.Start(o.ecsv2ServiceClient, serverId)
}

func (o *OpenTelekomCloudProvider) deleteServer(server *servers.Server) error {
	resourceTags, err := tags.Get(o.ecsv1ServiceClient, "cloudservers", server.ID).Extract()
	if err != nil {
		return err
	}
	rts := resourceTags[:]

	if o.Config.UseNatGateway() {
		var dnatRuleId string
		for _, tag := range rts {
			if tag.Key == dnatRuleIdTagKey {
				dnatRuleId = tag.Value
				break
			}
		}

		err = o.deleteDnatRule(dnatRuleId)
		if err != nil {
			return err
		}
	} else {
		var floatingIpId string
		for _, tag := range rts {
			if tag.Key == floatingIpIdTagKey {
				floatingIpId = tag.Value
				break
			}
		}

		err = o.deleteElasticIpAddress(floatingIpId)
		if err != nil {
			return err
		}
	}

	return servers.Delete(o.ecsv2ServiceClient, server.ID).ExtractErr()
}

func (o *OpenTelekomCloudProvider) stopServer(serverId string) {
	startstop.Stop(o.ecsv2ServiceClient, serverId)
}

func (o *OpenTelekomCloudProvider) createServer() (*servers.Server, error) {
	// get public key
	publicKeyBase, err := ssh.GetPublicKeyBase(o.Config.MachineFolder)
	if err != nil {
		return nil, fmt.Errorf("loading public key failed: %w", err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase)
	if err != nil {
		return nil, err
	}

	// create a keypair
	keyPair, err := o.createKeyPair(publicKey)
	if err != nil {
		return nil, err
	}

	var fip *floatingips.FloatingIP
	var dnatRuleId string

	if !o.Config.UseNatGateway() {
		// create a floating ip
		fip, err = o.createElasticIpAddress()
		if err != nil {
			return nil, err
		}
	}

	// TODO: get ImageUUID by ImageRefName - at the moment suggested values are not working
	// define the details of the block device that will boot the server
	blockDevices := []bootfromvolume.BlockDevice{
		bootfromvolume.BlockDevice{
			DeleteOnTermination: true,
			DestinationType:     bootfromvolume.DestinationVolume,
			SourceType:          bootfromvolume.SourceImage,
			UUID:                o.Config.DiskImage,
			VolumeSize:          o.Config.DiskSizeGB,
		},
	}

	// define the server and network details
	serverCreateOpts := servers.CreateOpts{
		Name:      o.Config.MachineID,
		FlavorRef: o.Config.FlavorId,
		Networks:  []servers.Network{{UUID: o.Config.SubnetId}},
		UserData:  []byte(o.getInjectKeyPairScript(publicKey)),
	}

	keypairOpts := keypairs.CreateOptsExt{
		CreateOptsBuilder: serverCreateOpts,
		KeyName:           keyPair.Name,
	}

	createOpts := bootfromvolume.CreateOptsExt{
		CreateOptsBuilder: keypairOpts,
		BlockDevice:       blockDevices,
	}

	server, err := bootfromvolume.Create(o.ecsv2ServiceClient, createOpts).Extract()
	if err != nil {
		return nil, err
	}

	// Wait until the server is in the "ACTIVE" state
	server, err = o.waitForServerActive(server.ID)
	if err != nil {
		return nil, err
	}

	o.getServerIpAddresses(*server)

	// from here on return the instance create so it can be deleted in case of error

	if !o.Config.UseNatGateway() {
		// TODO: figure out why EIP is created with default bandwidth 1000Mbits/sec
		// associate the server with the floating ip
		err = o.assosiateElasticIpAddress(server.ID, fip)
		if err != nil {
			return server, err
		}
	} else {
		// create a DNAT Rule in the designated NAT Gateway
		dnatRuleId, err = o.createDnatRule(server.ID)
		if err != nil {
			return server, err
		}
	}

	// TODO: create a security group if it the env variable is empty
	// add an *existing* security group (allow 22, and preferrably ICMP as well)
	err = o.addSecurityGroup(server.ID)
	if err != nil {
		return server, err
	}

	// TODO: create a separate method to get the necessary resource tags
	// add tags to the server
	tagList := []tags.ResourceTag{
		{
			Key:   devpodTagKey,
			Value: o.Config.MachineID,
		},
	}

	if o.Config.UseNatGateway() {
		tagList = append(tagList, tags.ResourceTag{
			Key:   dnatRuleIdTagKey,
			Value: dnatRuleId,
		})
	} else {
		tagList = append(tagList, tags.ResourceTag{
			Key:   floatingIpIdTagKey,
			Value: fip.ID,
		})
	}

	if err := tags.Create(o.ecsv1ServiceClient, "cloudservers", server.ID, tagList).ExtractErr(); err != nil {
		return server, err
	}

	return server, nil
}

func (o *OpenTelekomCloudProvider) waitForServerActive(serverId string) (*servers.Server, error) {
	start := time.Now()
	var srv *servers.Server

	for {
		server, err := servers.Get(o.ecsv2ServiceClient, serverId).Extract()
		if err != nil {
			continue
		}

		if server.Status == "ACTIVE" {
			srv = server
			break
		}

		if time.Now().After(start.Add(5 * time.Minute)) {
			return nil, fmt.Errorf("timeout waiting for server: %s", o.Config.MachineID)
		}

		time.Sleep(2 * time.Second)
	}

	return srv, nil
}

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

func (o *OpenTelekomCloudProvider) assosiateElasticIpAddress(serverId string, fip *floatingips.FloatingIP) error {
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
	externalServicePort := random.InRange(dnatRuleMinOutsidePort, dnatRuleMaxOutsidePort)

	for o.isPortAlreadyUsedInDnatRule(dnatRules, externalServicePort) {
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

func (o *OpenTelekomCloudProvider) isPortAlreadyUsedInDnatRule(dnatRules []dnatrules.DnatRule, port int) bool {
	for _, dnatRule := range dnatRules {
		if dnatRule.ExternalServicePort == port {
			return true
		}
	}

	return false
}

func (o *OpenTelekomCloudProvider) addSecurityGroup(serverId string) error {
	err := secgroups.AddServer(o.ecsv2ServiceClient, serverId, o.Config.SecurityGroupId).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}

func (o *OpenTelekomCloudProvider) createKeyPair(publicKey []byte) (*keypairs.KeyPair, error) {
	keyPair, err := keypairs.Get(o.ecsv2ServiceClient, devpodKeyPairName).Extract()
	if err != nil {
		createOpts := keypairs.CreateOpts{
			Name:      devpodKeyPairName,
			PublicKey: string(publicKey),
		}

		keyPair, err = keypairs.Create(o.ecsv2ServiceClient, createOpts).Extract()
		if err != nil {
			return nil, err
		}
	}

	return keyPair, nil
}

// TODO: make this script generic (for docker installation), at the moment covers only ubuntu
func (o *OpenTelekomCloudProvider) getInjectKeyPairScript(publicKey []byte) string {
	resultScript := `#!/bin/sh
useradd devpod -s /bin/bash -d /home/devpod
mkdir -p /home/devpod
if grep -q sudo /etc/groups; then
	usermod -aG sudo devpod
elif grep -q wheel /etc/groups; then
	usermod -aG wheel devpod
fi
echo "devpod ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/91-devpod
mkdir -p /home/devpod/.ssh
echo "` + string(publicKey) + `" >> /home/devpod/.ssh/authorized_keys
chmod 0700 /home/devpod/.ssh
chmod 0600 /home/devpod/.ssh/authorized_keys
chown -R devpod:devpod /home/devpod
sudo snap install docker
sudo groupadd docker
sudo usermod -aG docker devpod`

	return base64.StdEncoding.EncodeToString([]byte(resultScript))
}
