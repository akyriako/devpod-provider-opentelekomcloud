package cmd

import (
	"context"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/opentelekomcloud"

	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// StopCmd holds the cmd flags
type StopCmd struct{}

// NewStopCmd defines a command
func NewStopCmd() *cobra.Command {
	cmd := &StopCmd{}
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop an instance",
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

	return stopCmd
}

// Run runs the command logic
func (cmd *StopCmd) Run(
	ctx context.Context,
	opentelekomcloudProvider *opentelekomcloud.OpenTelekomCloudProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	return opentelekomcloudProvider.Stop()
}
