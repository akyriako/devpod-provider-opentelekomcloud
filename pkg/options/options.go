package options

import (
	"fmt"
	"github.com/sethvargo/go-password/password"
	"os"
	"strconv"
	"strings"
)

var (
	OTC_TENANT_NAME = "OTC_TENANT_NAME"
	OTC_REGION      = "OTC_REGION"

	OTC_NETWORK_ID       = "OTC_NETWORK_ID"
	OTC_NATGATEWAY_ID    = "OTC_NATGATEWAY_ID"
	OTC_FLOATINGIP_ID    = "OTC_FLOATINGIP_ID"
	OTC_SECURITYGROUP_ID = "OTC_SECURITYGROUP_ID"

	OTC_FLAVOR_ID  = "OTC_FLAVOR_ID"
	OTC_DISK_IMAGE = "OTC_DISK_IMAGE"
	OTC_DISK_SIZE  = "OTC_DISK_SIZE"

	PROXY_HOST = "PROXY_HOST"
	SOCKS_PORT = "SOCKS_PORT"

	MACHINE_ID     = "MACHINE_ID"
	MACHINE_FOLDER = "MACHINE_FOLDER"
)

const (
	DefaultSshPort int = 22
)

type Options struct {
	FlavorId        string
	DiskImage       string
	DiskSizeGB      int
	SubnetId        string
	SecurityGroupId string
	NatGatewayId    string
	FloatingIpId    string

	ServerPortId string
	PublicIp     string
	PrivateIp    string
	Port         int

	Region string
	Tenant string

	ProxyHost string
	SocksPort *int

	MachineID     string
	MachineFolder string
}

func (o *Options) UseNatGateway() bool {
	return strings.TrimSpace(o.NatGatewayId) != ""
}

func (o *Options) UseProxy() bool {
	return strings.TrimSpace(o.ProxyHost) != "" && o.SocksPort != nil
}

func FromEnv(init bool) (*Options, error) {
	retOptions := &Options{}

	var err error

	retOptions.DiskImage, err = fromEnvOrError(OTC_DISK_IMAGE)
	if err != nil {
		return nil, err
	}

	retOptions.FlavorId, err = fromEnvOrError(OTC_FLAVOR_ID)
	if err != nil {
		return nil, err
	}

	retOptions.SubnetId, err = fromEnvOrError(OTC_NETWORK_ID)
	if err != nil {
		return nil, err
	}

	retOptions.NatGatewayId = os.Getenv(OTC_NATGATEWAY_ID)
	if !retOptions.UseNatGateway() {
		retOptions.Port = DefaultSshPort
	} else {
		retOptions.FloatingIpId, err = fromEnvOrError(OTC_FLOATINGIP_ID)
		if err != nil {
			return nil, err
		}
	}

	retOptions.ProxyHost = os.Getenv(PROXY_HOST)
	proxyPort, err := strconv.Atoi(os.Getenv(SOCKS_PORT))
	if err != nil {
		return nil, err
	}
	retOptions.SocksPort = &proxyPort

	retOptions.SecurityGroupId, err = fromEnvOrError(OTC_SECURITYGROUP_ID)
	if err != nil {
		return nil, err
	}

	diskSizeInGB, err := fromEnvOrError(OTC_DISK_SIZE)
	if err != nil {
		return nil, err
	}
	diskSizeInGBAsInt, err := strconv.Atoi(diskSizeInGB)
	if err != nil {
		return nil, err
	}
	retOptions.DiskSizeGB = diskSizeInGBAsInt

	retOptions.Region, err = fromEnvOrError(OTC_REGION)
	if err != nil {
		return nil, err
	}

	retOptions.Tenant, err = fromEnvOrError(OTC_TENANT_NAME)
	if err != nil {
		return nil, err
	}

	// Return early if we're just doing init
	if init {
		return retOptions, nil
	}

	retOptions.MachineID = os.Getenv(MACHINE_ID)
	if retOptions.MachineID == "" {
		// create a MACHINE_ID
		postfix, err := password.Generate(4, 2, 0, true, true)
		if err != nil {
			return nil, err
		}
		machineId := fmt.Sprintf("ecs-devpod-%s", postfix)
		retOptions.MachineID = machineId
		err = os.Setenv(MACHINE_ID, machineId)
		if err != nil {
			return nil, err
		}
	}

	retOptions.MachineFolder, err = fromEnvOrError(MACHINE_FOLDER)
	if err != nil {
		return nil, err
	}

	return retOptions, nil
}

func fromEnvOrError(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf(
			"couldn't find option %s in environment, please make sure %s is defined",
			name,
			name,
		)
	}

	return val, nil
}
