package opentelekomcloud

import (
	"fmt"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/options"
	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/log"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
	"github.com/pkg/errors"
	"net/http"
	"os"
)

const (
	identityEndpoint = "https://iam.%s.otc.t-systems.com/v3"
)

type OpenTelekomCloudProvider struct {
	Config             *options.Options
	authOptions        *golangsdk.AKSKAuthOptions
	Client             *golangsdk.ProviderClient
	ecsv1ServiceClient *golangsdk.ServiceClient
	ecsv2ServiceClient *golangsdk.ServiceClient
	Log                log.Logger
	WorkingDirectory   string
}

func NewProvider(log log.Logger, init bool) (*OpenTelekomCloudProvider, error) {
	accessKey := os.Getenv("OTC_ACCESS_KEY")
	if accessKey == "" {
		return nil, errors.Errorf("OTC_ACCESS_KEY is not set")
	}
	secretKey := os.Getenv("OTC_SECRET_KEY")
	if secretKey == "" {
		return nil, errors.Errorf("OTC_SECRET_KEY is not set")
	}

	config, err := options.FromEnv(init)
	if err != nil {
		return nil, err
	}

	authOptions := golangsdk.AKSKAuthOptions{
		IdentityEndpoint: fmt.Sprintf(identityEndpoint, config.Region),
		ProjectName:      config.Tenant,
		Region:           config.Region,
		//Domain:           config.Domain,
		AccessKey: accessKey,
		SecretKey: secretKey,
	}

	providerClient, err := openstack.AuthenticatedClient(authOptions)
	if err != nil {
		return nil, err
	}

	openTelekomCloudProvider := &OpenTelekomCloudProvider{
		Config:      config,
		authOptions: &authOptions,
		Client:      providerClient,
		Log:         log,
	}

	providerClient.HTTPClient = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if providerClient.AKSKAuthOptions.AccessKey != "" {
				golangsdk.ReSign(req, golangsdk.SignOptions{
					AccessKey: providerClient.AKSKAuthOptions.AccessKey,
					SecretKey: providerClient.AKSKAuthOptions.SecretKey,
				})
			}
			return nil
		},
	}

	ecsv1sc, err := openstack.NewComputeV1(providerClient, golangsdk.EndpointOpts{
		Region: openTelekomCloudProvider.Config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to acquire a NewComputeV1 service client: %s", err.Error())
	}

	openTelekomCloudProvider.ecsv1ServiceClient = ecsv1sc

	ecsv2sc, err := openstack.NewComputeV2(openTelekomCloudProvider.Client, golangsdk.EndpointOpts{
		Region: openTelekomCloudProvider.Config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to acquire a NewComputeV2 service client: %s", err.Error())
	}

	openTelekomCloudProvider.ecsv2ServiceClient = ecsv2sc

	return openTelekomCloudProvider, nil
}

func GetDevpodInstance(openTelekomCloudProvider *OpenTelekomCloudProvider) (*servers.Server, error) {
	server, err := openTelekomCloudProvider.getServer(openTelekomCloudProvider.Config.MachineID)
	if err != nil {
		return nil, err
	}

	openTelekomCloudProvider.Config.ServerID = server.ID
	return server, nil
}

func GetDevpodInstanceElasticIp(openTelekomCloudProvider *OpenTelekomCloudProvider, devPodInstance *servers.Server) (string, error) {
	if devPodInstance == nil {
		dpi, err := GetDevpodInstance(openTelekomCloudProvider)
		if err != nil {
			return "", err
		}

		devPodInstance = dpi
	}

	return openTelekomCloudProvider.extractElasticIpAddress(*devPodInstance)
}

func Create(opentelekomcloudProvider *OpenTelekomCloudProvider) error {
	_, err := opentelekomcloudProvider.createServer()
	if err != nil {
		return err
	}

	return nil
}

func Delete(openTelekomCloudProvider *OpenTelekomCloudProvider) error {
	_, err := GetDevpodInstance(openTelekomCloudProvider)
	if err != nil {
		return err
	}

	return openTelekomCloudProvider.deleteServer()
}

func Start(openTelekomCloudProvider *OpenTelekomCloudProvider) error {
	_, err := GetDevpodInstance(openTelekomCloudProvider)
	if err != nil {
		return err
	}

	openTelekomCloudProvider.startServer()
	return nil
}

func Status(openTelekomCloudProvider *OpenTelekomCloudProvider) (client.Status, error) {
	devPodInstance, err := GetDevpodInstance(openTelekomCloudProvider)
	if err != nil {
		return client.StatusNotFound, nil
	}

	switch {
	case devPodInstance.Status == "ACTIVE":

		return client.StatusRunning, nil
	case devPodInstance.Status == "SHUTOFF":
		return client.StatusStopped, nil
	default:
		return client.StatusBusy, nil
	}
}

func Stop(openTelekomCloudProvider *OpenTelekomCloudProvider) error {
	_, err := GetDevpodInstance(openTelekomCloudProvider)
	if err != nil {
		return err
	}

	openTelekomCloudProvider.stopServer()

	return nil
}

func Init(openTelekomCloudProvider *OpenTelekomCloudProvider) error {
	err := openstack.Authenticate(openTelekomCloudProvider.Client, *openTelekomCloudProvider.authOptions)
	if err != nil {
		return err
	}

	return nil
}
