package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"nadamu/dyatel/internal/client"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"
)

var hostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "Manage hosts (tunnel endpoints)",
}

var transports = []string{"wireguard", "amneziawg"}

var hostsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List hosts you own or consume",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodGet, "/hosts/", nil)
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var hs []client.Host
			if err := json.Unmarshal(raw, &hs); err != nil {
				return err
			}
			rows := make([][]string, 0, len(hs))
			for _, h := range hs {
				rows = append(rows, []string{
					h.ID, h.Name, dash(h.State), h.Transport,
					fmt.Sprintf("%d", h.ListenPort), dash(h.TunnelIPv4), dash(h.Endpoint),
				})
			}
			printTable(w, []string{"ID", "NAME", "STATE", "TRANSPORT", "PORT", "TUNNEL_V4", "ENDPOINT"}, rows)
			return nil
		})
	},
}

var hostsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a host",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		transport, _ := cmd.Flags().GetString("transport")
		consumerID, _ := cmd.Flags().GetString("consumer-id")
		pubkey, _ := cmd.Flags().GetString("wg-pubkey")
		keepalive, _ := cmd.Flags().GetInt("keepalive")
		paramsRaw, _ := cmd.Flags().GetString("params")

		// Client-side validation mirrors the daemon's checks so obvious
		// mistakes fail before a network round trip.
		if pubkey != "" && len(pubkey) != 44 {
			return fmt.Errorf("bad --wg-pubkey (want 44-char wg public key, got %d chars)", len(pubkey))
		}
		var params json.RawMessage
		if paramsRaw != "" {
			if !json.Valid([]byte(paramsRaw)) {
				return fmt.Errorf("bad --params: not valid json")
			}
			params = json.RawMessage(paramsRaw)
		}
		if keepalive < 0 {
			return fmt.Errorf("bad --keepalive: must be >= 0")
		}

		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodPost, "/hosts/", client.CreateHostRequest{
			Name:        name,
			WGPublicKey: pubkey,
			Transport:   transport,
			ConsumerID:  consumerID,
			Keepalive:   keepalive,
			Params:      params,
		})
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var h client.Host
			if err := json.Unmarshal(raw, &h); err != nil {
				return err
			}
			hostKV(w, &h)
			return nil
		})
	},
}

var hostsShowCmd = &cobra.Command{
	Use:   "show HOSTID",
	Short: "Show one host",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodGet, "/hosts/"+args[0]+"/", nil)
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var h client.Host
			if err := json.Unmarshal(raw, &h); err != nil {
				return err
			}
			hostKV(w, &h)
			return nil
		})
	},
}

var hostsRmCmd = &cobra.Command{
	Use:     "rm HOSTID",
	Aliases: []string{"delete"},
	Short:   "Delete a host",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		// Deletion answers 204 with no body; success is silence.
		_, err = c.Do(http.MethodDelete, "/hosts/"+args[0]+"/", nil)
		return err
	},
}

var hostsStateCmd = &cobra.Command{
	Use:   "state HOSTID active|suspended",
	Short: "Set the desired host state",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		state := args[1]
		if state != "active" && state != "suspended" {
			return fmt.Errorf("bad state %q: want active or suspended", state)
		}
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		_, err = c.Do(http.MethodPost, "/hosts/"+args[0]+"/state", map[string]string{"state": state})
		return err
	},
}

var hostsRegisterKeyCmd = &cobra.Command{
	Use:   "register-consumer-key HOSTID",
	Short: "Register the consumer's wg public key for a host",
	Long: "Registers the consumer's 44-char wg public key (BYOK: keys are generated\n" +
		"locally, only public halves travel). Reads the key from --wg-pubkey or\n" +
		"from stdin when the flag is omitted.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, _ := cmd.Flags().GetString("wg-pubkey")
		if key == "" {
			// Stdin input keeps keys out of shell history.
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read key from stdin: %w", err)
			}
			key = strings.TrimSpace(string(b))
		}
		if len(key) != 44 {
			return fmt.Errorf("bad key (want 44-char wg public key, got %d chars)", len(key))
		}
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		// 204 on success.
		_, err = c.Do(http.MethodPost, "/hosts/"+args[0]+"/consumer-key",
			map[string]string{"wg_public_key": key})
		return err
	},
}

var hostsConfigCmd = &cobra.Command{
	Use:   "config HOSTID proxer|client",
	Short: "Print a generated wireguard config",
	Long: "Prints the rendered config for a host: 'proxer' is the gateway-side\n" +
		"config, 'client' is the consumer-side config (it contains the consumer\n" +
		"private key material and should be saved to a file with --out).",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		kind := args[1]
		if kind != "proxer" && kind != "client" {
			return fmt.Errorf("bad config kind %q: want proxer or client", kind)
		}
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		path := "/hosts/" + args[0] + "/config/" + kind
		raw, err := c.Do(http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			_, err := w.Write(raw)
			return err
		})
	},
}

// hostKV renders the full host detail view; nil pointer fields (consumer
// side before registration) show as '-'.
func hostKV(w io.Writer, h *client.Host) {
	params, _ := h.DecodedParams()
	printKV(w, []kv{
		{"id", h.ID},
		{"name", h.Name},
		{"state", dash(h.State)},
		{"transport", h.Transport},
		{"listen_port", fmt.Sprintf("%d", h.ListenPort)},
		{"keepalive", fmt.Sprintf("%d", h.Keepalive)},
		{"tunnel_ipv4", dash(h.TunnelIPv4)},
		{"tunnel_ipv6", dash(h.TunnelIPv6)},
		{"endpoint", dash(h.Endpoint)},
		{"owner_id", h.OwnerID},
		{"consumer_id", h.ConsumerID},
		{"wg_public_key", h.WGPublicKey},
		{"gw_public_key", h.GWPublicKey},
		{"consumer_wg_public_key", dash(h.ConsumerWGPublicKey)},
		{"consumer_tunnel_ipv4", dash(h.ConsumerTunnelIPv4)},
		{"consumer_tunnel_ipv6", dash(h.ConsumerTunnelIPv6)},
		{"params", string(params)},
	})
}

func init() {
	hostsCreateCmd.Flags().String("name", "", "host name (a-z0-9-)")
	_ = hostsCreateCmd.MarkFlagRequired("name")
	hostsCreateCmd.Flags().String("transport", "wireguard", "transport: wireguard or amneziawg")
	hostsCreateCmd.Flags().String("consumer-id", "", "consumer user id (uuid)")
	_ = hostsCreateCmd.MarkFlagRequired("consumer-id")
	hostsCreateCmd.Flags().String("wg-pubkey", "", "44-char wg public key (optional at creation)")
	hostsCreateCmd.Flags().Int("keepalive", 0, "persistent keepalive seconds (default: daemon applies 25)")
	hostsCreateCmd.Flags().String("params", "", "raw transport params (amneziawg junk header), valid json")

	hostsRegisterKeyCmd.Flags().String("wg-pubkey", "", "44-char wg public key; read from stdin when omitted")

	hostsConfigCmd.Flags().String("out", "", "write the config to FILE (mode 0600) instead of stdout")

	hostsCmd.AddCommand(hostsListCmd, hostsCreateCmd, hostsShowCmd, hostsRmCmd,
		hostsStateCmd, hostsRegisterKeyCmd, hostsConfigCmd)

	// Shell completion: choices for enum flags, nothing for opaque IDs.
	carapace.Gen(hostsCreateCmd).FlagCompletion(carapace.ActionMap{
		"transport": carapace.ActionValues(transports...),
	})
	carapace.Gen(hostsStateCmd).PositionalCompletion(
		carapace.ActionValues(),
		carapace.ActionValues("active", "suspended"),
	)
	carapace.Gen(hostsConfigCmd).PositionalCompletion(
		carapace.ActionValues(),
		carapace.ActionValues("proxer", "client"),
	)
}
