package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"nadamu/dyatel/internal/client"

	"github.com/carapace-sh/carapace"
	"github.com/spf13/cobra"
)

var forwardsCmd = &cobra.Command{
	Use:   "forwards",
	Short: "Manage forwards (public port -> target port on a host)",
}

var forwardsListCmd = &cobra.Command{
	Use:   "list HOSTID",
	Short: "List a host's forwards",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodGet, "/hosts/"+args[0]+"/forwards", nil)
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var fs []client.Forward
			if err := json.Unmarshal(raw, &fs); err != nil {
				return err
			}
			rows := make([][]string, 0, len(fs))
			for _, f := range fs {
				rows = append(rows, []string{
					f.ID, strconv.Itoa(f.PublicPort), strconv.Itoa(f.TargetPort),
					f.Proto, dash(f.Label),
				})
			}
			printTable(w, []string{"ID", "PUBLIC_PORT", "TARGET_PORT", "PROTO", "LABEL"}, rows)
			return nil
		})
	},
}

var forwardsCreateCmd = &cobra.Command{
	Use:   "create HOSTID",
	Short: "Add a forward to a host",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		publicPort, err := port(cmd, "public-port")
		if err != nil {
			return err
		}
		targetPort, err := port(cmd, "target-port")
		if err != nil {
			return err
		}
		proto, _ := cmd.Flags().GetString("proto")
		label, _ := cmd.Flags().GetString("label")

		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodPost, "/hosts/"+args[0]+"/forwards", client.CreateForwardRequest{
			PublicPort: publicPort,
			TargetPort: targetPort,
			Proto:      proto,
			Label:      label,
		})
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var f client.Forward
			if err := json.Unmarshal(raw, &f); err != nil {
				return err
			}
			printKV(w, []kv{
				{"id", f.ID},
				{"host_id", f.HostID},
				{"public_port", strconv.Itoa(f.PublicPort)},
				{"target_port", strconv.Itoa(f.TargetPort)},
				{"proto", f.Proto},
				{"label", dash(f.Label)},
			})
			return nil
		})
	},
}

var forwardsRmCmd = &cobra.Command{
	Use:     "rm HOSTID FORWARDID",
	Aliases: []string{"delete"},
	Short:   "Delete a forward",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		// 204 on success.
		_, err = c.Do(http.MethodDelete, "/hosts/"+args[0]+"/forwards/"+args[1], nil)
		return err
	},
}

// port parses and range-checks a port flag client-side: the daemon would
// reject it anyway, but the error should name the flag.
func port(cmd *cobra.Command, name string) (int, error) {
	v, _ := cmd.Flags().GetInt(name)
	if v < 1 || v > 65535 {
		return 0, fmt.Errorf("bad --%s %d: want 1-65535", name, v)
	}
	return v, nil
}

func init() {
	forwardsCreateCmd.Flags().Int("public-port", 0, "port exposed publicly (1-65535)")
	_ = forwardsCreateCmd.MarkFlagRequired("public-port")
	forwardsCreateCmd.Flags().Int("target-port", 0, "port on the target host (1-65535)")
	_ = forwardsCreateCmd.MarkFlagRequired("target-port")
	forwardsCreateCmd.Flags().String("proto", "tcp", "protocol: tcp or udp")
	forwardsCreateCmd.Flags().String("label", "", "optional label")

	forwardsCmd.AddCommand(forwardsListCmd, forwardsCreateCmd, forwardsRmCmd, forwardsDNSCmd)

	forwardsDNSSetCmd.Flags().String("name", "", "subdomain label (e.g. mc1) or FQDN under the daemon DNS zone")
	_ = forwardsDNSSetCmd.MarkFlagRequired("name")
	forwardsDNSCmd.AddCommand(forwardsDNSListCmd, forwardsDNSSetCmd, forwardsDNSRmCmd)

	carapace.Gen(forwardsCreateCmd).FlagCompletion(carapace.ActionMap{
		"proto": carapace.ActionValues("tcp", "udp"),
	})
	carapace.Gen(forwardsRmCmd).PositionalCompletion(
		carapace.ActionValues(),
		carapace.ActionValues(),
	)
}

var forwardsDNSCmd = &cobra.Command{
	Use:   "dns",
	Short: "Manage Cloudflare DNS records for forwards",
}

var forwardsDNSListCmd = &cobra.Command{
	Use:   "list HOSTID",
	Short: "List DNS records bound to a host's forwards",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodGet, "/hosts/"+args[0]+"/dns", nil)
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var ds []client.DNSRecord
			if err := json.Unmarshal(raw, &ds); err != nil {
				return err
			}
			rows := make([][]string, 0, len(ds))
			for _, d := range ds {
				rows = append(rows, []string{d.ForwardID, d.Name, dash(d.CloudflareID), d.CreatedAt})
			}
			printTable(w, []string{"FORWARD_ID", "NAME", "CF_ID", "CREATED_AT"}, rows)
			return nil
		})
	},
}

var forwardsDNSSetCmd = &cobra.Command{
	Use:   "set FORWARDID",
	Short: "Bind or rename a DNS record for a forward",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodPost, "/forwards/"+args[0]+"/dns", map[string]string{"name": name})
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var d client.DNSRecord
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			printKV(w, []kv{
				{"id", d.ID},
				{"forward_id", d.ForwardID},
				{"name", d.Name},
				{"cloudflare_id", dash(d.CloudflareID)},
			})
			return nil
		})
	},
}

var forwardsDNSRmCmd = &cobra.Command{
	Use:     "rm FORWARDID",
	Aliases: []string{"delete"},
	Short:   "Remove a forward's DNS record",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		_, err = c.Do(http.MethodDelete, "/forwards/"+args[0]+"/dns", nil)
		return err
	},
}
