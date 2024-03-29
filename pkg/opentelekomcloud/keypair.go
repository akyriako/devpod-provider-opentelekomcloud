package opentelekomcloud

import (
	"encoding/base64"
	"fmt"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/keypairs"
	"os"
	"regexp"
)

func (o *OpenTelekomCloudProvider) createKeyPair(publicKey []byte) (*keypairs.KeyPair, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)
	hostname = nonAlphanumericRegex.ReplaceAllString(hostname, "")

	keyPairName := fmt.Sprintf("%s-%s", devpodKeyPairName, hostname)
	keyPair, err := keypairs.Get(o.ecsv2ServiceClient, keyPairName).Extract()
	if err != nil {
		createOpts := keypairs.CreateOpts{
			Name:      keyPairName,
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
