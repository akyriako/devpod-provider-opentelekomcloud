package cmd

import (
	"context"
	"fmt"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/opentelekomcloud"
	"os"

	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/loft-sh/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// CommandCmd holds the cmd flags
type CommandCmd struct{}

// NewCommandCmd defines a command
func NewCommandCmd() *cobra.Command {
	cmd := &CommandCmd{}
	commandCmd := &cobra.Command{
		Use:   "command",
		Short: "Command an instance",
		RunE: func(_ *cobra.Command, args []string) error {
			opentelekomcloudProvider, err := opentelekomcloud.NewProvider(log.Default, false)
			if err != nil {
				return err
			}

			return cmd.Run(
				context.Background(),
				opentelekomcloudProvider,
				provider.FromEnvironment(),
				log.Default,
			)
		},
	}

	return commandCmd
}

// Run runs the command logic
func (cmd *CommandCmd) Run(
	ctx context.Context,
	opentelekomcloudProvider *opentelekomcloud.OpenTelekomCloudProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	command := os.Getenv("COMMAND")

	if command == "" {
		return fmt.Errorf("command environment variable is missing")
	}

	privateKey, err := ssh.GetPrivateKeyRawBase(opentelekomcloudProvider.Config.MachineFolder)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	// get instance
	instance, err := opentelekomcloudProvider.GetDevpodInstance()
	if err != nil {
		return err
	}

	// get elastic ip
	floatingIp, err := opentelekomcloudProvider.GetDevpodInstanceElasticIp(instance)
	if err != nil {
		return err
	}

	sshClient, err := ssh.NewSSHClient("ubuntu", floatingIp+":22", privateKey)

	if err != nil {
		return errors.Wrap(err, "create ssh client")
	}

	defer sshClient.Close()

	// run command
	return ssh.Run(ctx, sshClient, command, os.Stdin, os.Stdout, os.Stderr)
}
