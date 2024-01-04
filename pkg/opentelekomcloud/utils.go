package opentelekomcloud

import (
	"encoding/base64"
	"fmt"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/common/tags"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/floatingips"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/keypairs"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/secgroups"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/startstop"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
	"time"
)

const (
	devpodTagKey      = "devpod"
	devpodKeyPairName = "KeyPair-DevPod"
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

func (o *OpenTelekomCloudProvider) getServer(machineId string) (*servers.Server, error) {
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
			if tag.Key == devpodTagKey && tag.Value == o.Config.MachineID {
				return &server, nil
			}
		}
	}

	return nil, fmt.Errorf("found no devpod machine with id: %s", machineId)
}

func (o *OpenTelekomCloudProvider) startServer(serverId string) {
	startstop.Start(o.ecsv2ServiceClient, serverId)
}

func (o *OpenTelekomCloudProvider) deleteServer(serverId string) error {
	return servers.Delete(o.ecsv2ServiceClient, serverId).ExtractErr()
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

	// create a floating ip
	fip, err := o.createElasticIpAddress()
	if err != nil {
		return nil, err
	}

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
	err = o.waitForServerActive(server.ID)
	if err != nil {
		return nil, err
	}

	// associate the server with the floating ip
	err = o.assosiateElasticIpAddress(server, fip)
	if err != nil {
		return nil, err
	}

	// add an *existing* security group (allow 22, and preferrably ICMP as well)
	err = o.addSecurityGroup(server)
	if err != nil {
		return nil, err
	}

	// add tags to the server
	tagList := []tags.ResourceTag{
		{
			Key:   devpodTagKey,
			Value: o.Config.MachineID,
		},
	}
	if err := tags.Create(o.ecsv1ServiceClient, "cloudservers", server.ID, tagList).ExtractErr(); err != nil {
		return nil, err
	}

	return server, nil
}

func (o *OpenTelekomCloudProvider) waitForServerActive(serverId string) error {
	start := time.Now()

	for {
		server, err := servers.Get(o.ecsv2ServiceClient, serverId).Extract()
		if err != nil {
			continue
		}

		if server.Status == "ACTIVE" {
			break
		}

		if time.Now().After(start.Add(5 * time.Minute)) {
			return fmt.Errorf("timeout waiting for server: %s", o.Config.MachineID)
		}

		time.Sleep(2 * time.Second)
	}

	return nil
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

func (o *OpenTelekomCloudProvider) assosiateElasticIpAddress(server *servers.Server, fip *floatingips.FloatingIP) error {
	// Associate the floating IP with the server
	associateOpts := floatingips.AssociateOpts{
		FloatingIP: fip.IP,
	}

	err := floatingips.AssociateInstance(o.ecsv2ServiceClient, server.ID, associateOpts).ExtractErr()
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

func (o *OpenTelekomCloudProvider) extractElasticIpAddress(server servers.Server) (string, error) {
	for _, v1 := range server.Addresses {
		addresses := v1.([]interface{})
		for _, v2 := range addresses {
			address := v2.(map[string]interface{})
			if address["OS-EXT-IPS:type"] == "floating" {
				eip := address["addr"].(string)
				return eip, nil
			}
		}
	}

	return "", fmt.Errorf("no floating ip found for server: %s/%s", server.Name, server.ID)
}

func (o *OpenTelekomCloudProvider) addSecurityGroup(server *servers.Server) error {
	err := secgroups.AddServer(o.ecsv2ServiceClient, server.ID, o.Config.SecurityGroupId).ExtractErr()
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

func (o *OpenTelekomCloudProvider) getInjectKeyPairScript(publicKey []byte) string {
	resultScript := `#!/bin/sh
useradd devpod -d /home/devpod
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
chown -R devpod:devpod /home/devpod`

	return base64.StdEncoding.EncodeToString([]byte(resultScript))
}
