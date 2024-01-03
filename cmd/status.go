package cmd

import (
	"context"
	"fmt"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/opentelekomcloud"
	"os"

	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// StatusCmd holds the cmd flags
type StatusCmd struct{}

// NewStatusCmd defines a command
func NewStatusCmd() *cobra.Command {
	cmd := &StatusCmd{}
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Status an instance",
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

	return statusCmd
}

// Run runs the command logic
func (cmd *StatusCmd) Run(
	ctx context.Context,
	opentelekomcloudProvider *opentelekomcloud.OpenTelekomCloudProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {

	status, err := opentelekomcloudProvider.Status()
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(os.Stdout, status)
	return err
}
