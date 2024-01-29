package cmd

import (
	"context"
	"fmt"
	"github.com/akyriako/devpod-provider-opentelekomcloud/pkg/opentelekomcloud"
	"os"

	"github.com/loft-sh/devpod/pkg/provider"
	devpodssh "github.com/loft-sh/devpod/pkg/ssh"
	"github.com/loft-sh/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
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

	privateKey, err := devpodssh.GetPrivateKeyRawBase(opentelekomcloudProvider.Config.MachineFolder)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	// get instance
	instance, err := opentelekomcloudProvider.GetDevPodRunningInstance()
	if err != nil {
		return err
	}

	// get public ip and port
	publicIp, port, err := opentelekomcloudProvider.GetDevPodRunningInstanceConnectionAddr(instance)
	if err != nil {
		return err
	}

	var sshClient *ssh.Client
	addr := fmt.Sprintf("%s:%d", publicIp, port)

	if opentelekomcloudProvider.Config.UseProxy() {
		proxyAddr := fmt.Sprintf(
			"%s:%d",
			opentelekomcloudProvider.Config.ProxyHost,
			*opentelekomcloudProvider.Config.SocksPort,
		)
		sshClient, err = NewSSHClient("devpod", addr, privateKey, proxyAddr)
		if err != nil {
			return errors.Wrap(err, "create ssh client")
		}
	} else {
		sshClient, err = devpodssh.NewSSHClient("devpod", addr, privateKey)
		if err != nil {
			return errors.Wrap(err, "create ssh client")
		}
	}

	defer sshClient.Close()

	// run command
	return devpodssh.Run(ctx, sshClient, command, os.Stdin, os.Stdout, os.Stderr)
}

func NewSSHClient(user, addr string, keyBytes []byte, proxyAddr string) (*ssh.Client, error) {
	sshConfig, err := devpodssh.ConfigFromKeyBytes(keyBytes)
	if err != nil {
		return nil, err
	}

	if user != "" {
		sshConfig.User = user
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy %v failed: %w", addr, err)
	}

	netConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	sshConn, channel, request, err := ssh.NewClientConn(netConn, addr, sshConfig)
	if err != nil {
		return nil, err
	}

	client := ssh.NewClient(sshConn, channel, request)
	if err != nil {
		return nil, fmt.Errorf("dial to %v failed: %w", addr, err)
	}

	return client, nil
}
