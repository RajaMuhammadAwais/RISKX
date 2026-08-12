package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
	"github.com/RajaMuhammadAwais/RISKX/internal/serve"
)

// newServeCmd implements `riskx serve`: a read-only HTTP JSON API over the
// evidence store (roadmap P0). Authentication is strictly user-supplied:
// the server refuses to start without an API key set via RISKX_API_KEY or
// serve.api_key. Nothing can be written through the API.
func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the read-only evidence API over HTTP",
		Long: `serve exposes the evidence store (assets, findings, risk scores,
evidence, relationships) as a read-only JSON API so dashboards, CI systems,
and AI agents can consume RISKX data without re-running scans.

Authentication: the server REQUIRES an API key supplied by the operator.
Set RISKX_API_KEY (recommended) or serve.api_key in the config file. The
server refuses to start without one (fail secure). Keys are compared in
constant time; unauthorized requests are logged and receive 401.

Endpoints:
  GET /health                     server health
  GET /api/v1/summary             counts headline
  GET /api/v1/assets              all stored assets
  GET /api/v1/findings?severity=  findings (optionally filtered by severity)
  GET /api/v1/scores              risk scores
  GET /api/v1/evidence?finding=&asset=  evidence rows (optionally filtered)
  GET /api/v1/relationships       graph relationships

Clients authenticate with the X-API-Key request header.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			listenFlag, _ := cmd.Flags().GetString("listen")
			dataFlag, _ := cmd.Flags().GetString("data")

			cfgPath, _ := cmd.Flags().GetString("config")
			cfgFile, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			// Resolution order: flag > env > config file > secure default port.
			listen := listenFlag
			if listen == "" {
				listen = cfgFile.Serve.Listen
			}
			if listen == "" {
				listen = ":8090"
			}

			key := serve.ResolveAPIKey(cfgFile.Serve.APIKey)

			path, ok := resolveDataPath(dataFlag)
			if !ok {
				return fmt.Errorf("serve: no evidence store configured; set --data or RISKX_DATA")
			}

			srv, err := serve.New(serve.ServerConfig{
				Listen:    listen,
				Key:       key,
				StorePath: path,
			})
			if err != nil {
				return err
			}
			defer srv.Close()

			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Printf("RISKX evidence API listening on %s (auth: X-API-Key header)\n", listen)
			fmt.Println("Stop with Ctrl+C. Nothing can be written through this API.")
			return srv.Serve(ctx)
		},
	}
	cmd.Flags().String("listen", "", "listen address (default :8090, may be set in config serve.listen)")
	cmd.Flags().String("data", os.Getenv("RISKX_DATA"), "evidence store path (env RISKX_DATA)")
	return cmd
}
