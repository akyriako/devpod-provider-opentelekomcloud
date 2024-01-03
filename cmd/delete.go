package cmd

import (
	"context"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/opentelekomcloud"

	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// DeleteCmd holds the cmd flags
type DeleteCmd struct{}

// NewDeleteCmd defines a command
func NewDeleteCmd() *cobra.Command {
	cmd := &DeleteCmd{}
	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an instance",
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

	return deleteCmd
}

// Run runs the command logic
func (cmd *DeleteCmd) Run(
	ctx context.Context,
	opentelekomcloudProvider *opentelekomcloud.OpenTelekomCloudProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	return opentelekomcloud.Delete(opentelekomcloudProvider)
}
