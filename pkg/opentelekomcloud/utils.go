package opentelekomcloud

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/options"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/common/tags"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/floatingips"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/keypairs"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/secgroups"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/startstop"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	machineIdKeyValue   = "machineID"
	devpodKeyValue      = "createdFrom"
	devpodTagValue      = "devpod"
	devpodPublicKeyName = "KeyPair-DevPod"
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
			if tag.Key == machineIdKeyValue && tag.Value == o.Config.MachineID {
				if slices.Contains(rts, tags.ResourceTag{
					Key:   devpodKeyValue,
					Value: devpodTagValue,
				}) {
					return &server, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("found no devpod machine with id: %s", machineId)
}

func (o *OpenTelekomCloudProvider) startServer() {
	startstop.Start(o.ecsv2ServiceClient, o.Config.ServerID)
}

func (o *OpenTelekomCloudProvider) deleteServer() error {
	return servers.Delete(o.ecsv2ServiceClient, o.Config.ServerID).ExtractErr()
}

func (o *OpenTelekomCloudProvider) stopServer() {
	startstop.Stop(o.ecsv2ServiceClient, o.Config.ServerID)
}

func (o *OpenTelekomCloudProvider) createServer() (*servers.Server, error) {
	publicKeyBase, err := ssh.GetPublicKeyBase(o.Config.MachineFolder)
	if err != nil {
		return nil, fmt.Errorf("loading public key failed: %w", err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase)
	if err != nil {
		return nil, err
	}

	keyPair, err := o.createKeyPair(string(publicKey))
	if err != nil {
		return nil, err
	}

	var fip *floatingips.FloatingIP
	if o.Config.FloatingIpID == "" {
		fip, err = o.createElasticIpAddress()
		if err != nil {
			return nil, err
		}
		//defer o.deleteElasticIpAddress(fip.ID)
	} else {
		fip, err = o.getElasticIpAddress(o.Config.FloatingIpID)
		if err != nil {
			return nil, err
		}
	}

	cloudConfigReader := strings.NewReader(
		fmt.Sprintf(`#cloud-config
								users:
								- name: devpod
								  shell: /bin/bash
								  groups: [ sudo, docker ]
								  ssh_authorized_keys:
								  - %s
								  sudo: [ "ALL=(ALL) NOPASSWD:ALL" ]`,
			string(publicKey)))

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(cloudConfigReader)
	if err != nil {
		return nil, err
	}

	blockDevices := []bootfromvolume.BlockDevice{
		bootfromvolume.BlockDevice{
			DeleteOnTermination: true,
			DestinationType:     bootfromvolume.DestinationVolume,
			SourceType:          bootfromvolume.SourceImage,
			UUID:                o.Config.DiskImage,
			VolumeSize:          o.Config.DiskSizeGB,
		},
	}

	serverCreateOpts := servers.CreateOpts{
		Name:      o.Config.MachineID,
		FlavorRef: o.Config.FlavorId,
		Networks:  []servers.Network{{UUID: o.Config.SubnetId}},
		UserData:  buf.Bytes(),
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

	o.Config.ServerID = server.ID

	// Wait until the server is in the "ACTIVE" state
	err = o.waitForServerActive()
	if err != nil {
		return nil, err
	}

	err = o.assosiateElasticIpAddress(server, fip)
	if err != nil {
		return nil, err
	}

	err = os.Setenv(options.OTC_FLOATINGIP_ID, fip.ID)
	if err != nil {
		return nil, err
	}

	err = o.addSecurityGroup(server)
	if err != nil {
		return nil, err
	}

	tagList := []tags.ResourceTag{
		{
			Key:   machineIdKeyValue,
			Value: o.Config.MachineID,
		},
		{
			Key:   devpodKeyValue,
			Value: devpodTagValue,
		},
	}
	if err := tags.Create(o.ecsv1ServiceClient, "cloudservers", server.ID, tagList).ExtractErr(); err != nil {
		return nil, err
	}

	return server, nil
}

func (o *OpenTelekomCloudProvider) waitForServerActive() error {
	start := time.Now()

	for {
		server, err := servers.Get(o.ecsv2ServiceClient, o.Config.ServerID).Extract()
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

func (o *OpenTelekomCloudProvider) createKeyPair(publicKey string) (*keypairs.KeyPair, error) {
	keyPair, err := keypairs.Get(o.ecsv2ServiceClient, devpodPublicKeyName).Extract()
	if err != nil {
		createOpts := keypairs.CreateOpts{
			Name:      devpodPublicKeyName,
			PublicKey: publicKey,
		}

		keyPair, err = keypairs.Create(o.ecsv2ServiceClient, createOpts).Extract()
		if err != nil {
			return nil, err
		}
	}

	return keyPair, nil
}
