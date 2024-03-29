package cmd

import (
	"context"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/opentelekomcloud"

	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// StartCmd holds the cmd flags
type StartCmd struct{}

// NewStartCmd defines a command
func NewStartCmd() *cobra.Command {
	cmd := &StartCmd{}
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start an instance",
		RunE: func(_ *cobra.Command, args []string) error {
			opentelekomcloudProvider, err := opentelekomcloud.NewProvider(log.Default, false)
			if err != nil {
				return err
			}

			return cmd.Run(
				context.Background(),
				opentelekomcloudProvider,
				log.Default,
			)
		},
	}

	return startCmd
}

// Run runs the command logic
func (cmd *StartCmd) Run(
	ctx context.Context,
	opentelekomcloudProvider *opentelekomcloud.OpenTelekomCloudProvider,
	logs log.Logger,
) error {
	return opentelekomcloudProvider.Start()
}
