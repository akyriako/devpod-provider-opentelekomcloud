package options

import (
	"fmt"
	"github.com/sethvargo/go-password/password"
	"os"
	"strconv"
)

var (
	OTC_TENANT_NAME      = "OTC_TENANT_NAME"
	OTC_REGION           = "OTC_REGION"
	OTC_NETWORK_ID       = "OTC_NETWORK_ID"
	OTC_SECURITYGROUP_ID = "OTC_SECURITYGROUP_ID"
	OTC_FLAVOR_ID        = "OTC_FLAVOR_ID"
	OTC_DISK_IMAGE       = "OTC_DISK_IMAGE"
	OTC_DISK_SIZE        = "OTC_DISK_SIZE"
	OTC_FLOATINGIP_ID    = "OTC_FLOATINGIP_ID"
	MACHINE_ID           = "MACHINE_ID"
	MACHINE_FOLDER       = "MACHINE_FOLDER"
)

type Options struct {
	FlavorId        string
	DiskImage       string
	DiskSizeGB      int
	SubnetId        string
	SecurityGroupId string

	Region string
	Tenant string

	FloatingIpID string
	ServerID     string

	MachineID     string
	MachineFolder string
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
	//retOptions.Domain = os.Getenv(OTC_DOMAIN_NAME)

	retOptions.Tenant, err = fromEnvOrError(OTC_TENANT_NAME)
	if err != nil {
		return nil, err
	}

	// Return early if we're just doing init
	if init {
		return retOptions, nil
	}

	retOptions.MachineID = os.Getenv(MACHINE_ID)
	//if err != nil {
	//	return nil, err
	//}

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

	retOptions.FloatingIpID = os.Getenv(OTC_FLOATINGIP_ID)

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
