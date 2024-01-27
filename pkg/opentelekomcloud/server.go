package opentelekomcloud

import (
	"encoding/base64"
	"fmt"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/common/tags"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/floatingips"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/keypairs"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/startstop"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/ims/v2/images"
	"time"
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

	imageId, err := o.getImageId(o.Config.DiskImage)
	if err != nil {
		return nil, err
	}

	// define the details of the block device that will boot the server
	blockDevices := []bootfromvolume.BlockDevice{
		bootfromvolume.BlockDevice{
			DeleteOnTermination: true,
			DestinationType:     bootfromvolume.DestinationVolume,
			SourceType:          bootfromvolume.SourceImage,
			UUID:                imageId,
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
		err = o.associateElasticIpAddress(server.ID, fip)
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
	// add an *existing* security group (allow 22, and preferably ICMP as well)
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

func (o *OpenTelekomCloudProvider) getImageId(imageName string) (string, error) {
	imagesInfo, err := images.ListImages(o.imsv2ServiceClient, images.ListImagesOpts{
		Name: imageName,
	})
	if err != nil {
		return "", err
	}

	for _, imageInfo := range imagesInfo {
		if imageInfo.Name == imageName {
			return imageInfo.Id, nil
		}
	}

	return "", nil
}