package cmd

import (
	"context"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/opentelekomcloud"
	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// InitCmd holds the cmd flags
type InitCmd struct{}

// NewInitCmd defines a init
func NewInitCmd() *cobra.Command {
	cmd := &InitCmd{}
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Init account",
		RunE: func(_ *cobra.Command, args []string) error {
			opentelekomcloudProvider, err := opentelekomcloud.NewProvider(log.Default, true)
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

	return initCmd
}

// Run runs the init logic
func (cmd *InitCmd) Run(
	ctx context.Context,
	opentelekomcloudProvider *opentelekomcloud.OpenTelekomCloudProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	return opentelekomcloudProvider.Init()
}
