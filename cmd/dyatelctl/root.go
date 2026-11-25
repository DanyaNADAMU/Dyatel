package main

import (
	"fmt"
	"io"
	"os"

	"nadamu/dyatel/internal/client"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dyatelctl",
	Short: "Control the dyatel tunnel proxy daemon",
	Long: "dyatelctl drives a dyatel-core daemon through its /api/v1 HTTP API.\n\n" +
		"Credentials: a personal access token (--token, dyatel_*) or the\n" +
		"break-glass admin pair (--user/--password). Bearer wins when both set.\n" +
		"Every flag falls back to its DYATEL_* environment variable.",
	// SilenceErrors: main prints errors in one uniform "dyatelctl: ..." line;
	// SilenceUsage: usage noise does not help when the daemon rejected a call.
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.String("api", "", "daemon base URL (env DYATEL_API, default http://127.0.0.1:8100)")
	pf.String("token", "", "personal access token, dyatel_* (env DYATEL_TOKEN)")
	pf.String("user", "", "break-glass admin user for Basic auth (env DYATEL_USER)")
	pf.String("password", "", "break-glass admin password for Basic auth (env DYATEL_PASSWORD)")
	pf.Bool("json", false, "print the raw daemon response instead of human-readable output")

	carapace.Gen(rootCmd)

	rootCmd.AddCommand(meCmd, statusCmd, hostsCmd, forwardsCmd,
		tokensCmd, usersCmd, eventsCmd, reconcileCmd)
	tokensCmd.AddCommand(tokensCreateCmd, tokensListCmd, tokensRmCmd)
	tokensCreateCmd.Flags().String("label", "", "human label shown in `tokens list` (laptop, vps, ci)")
	usersCmd.AddCommand(usersListCmd)
	eventsCmd.Flags().Int("limit", 50, "max rows (1-500)")
}

// Execute runs the command tree; main owns the error formatting.
func Execute() error {
	return rootCmd.Execute()
}

// envOr resolves a setting: explicit flag beats env beats the fallback —
// the same precedence every operator tool should follow.
func envOr(cmd *cobra.Command, name, env, fallback string) string {
	if v, _ := cmd.Flags().GetString(name); v != "" {
		return v
	}
	if env := os.Getenv(env); env != "" {
		return env
	}
	return fallback
}

func jsonMode(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("json")
	return v
}

// clientFrom builds the API client once per command run. Failing here on
// missing credentials beats burning a round trip on a guaranteed 401.
func clientFrom(cmd *cobra.Command) (*client.Client, error) {
	token := envOr(cmd, "token", "DYATEL_TOKEN", "")
	user := envOr(cmd, "user", "DYATEL_USER", "")
	password := envOr(cmd, "password", "DYATEL_PASSWORD", "")
	if token == "" && (user == "" || password == "") {
		return nil, fmt.Errorf("no credentials: set --token (DYATEL_TOKEN) or --user/--password (DYATEL_USER/DYATEL_PASSWORD)")
	}
	base := envOr(cmd, "api", "DYATEL_API", "http://127.0.0.1:8100")
	return client.New(base, token, user, password), nil
}

// out resolves the destination for command output: stdout, or --out FILE
// (created with 0600 — some outputs, like client configs, carry secrets).
func out(cmd *cobra.Command) (*os.File, func() error, error) {
	path, _ := cmd.Flags().GetString("out")
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, f.Close, nil
}

// output handles the --json split: raw daemon bytes go through untouched
// (passthrough preserves field order and unknown fields), human rendering
// happens only for non-json invocations.
func output(cmd *cobra.Command, raw []byte, render func(io.Writer) error) error {
	w, closeFn, err := out(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	if jsonMode(cmd) {
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			raw = append(raw, '\n')
		}
		_, err := w.Write(raw)
		return err
	}
	return render(w)
}
