package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"nadamu/dyatel/internal/client"

	"github.com/spf13/cobra"
)

var meCmd = &cobra.Command{
	Use:   "me",
	Short: "Show the identity the daemon sees for you",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodGet, "/me", nil)
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var me client.Me
			if err := json.Unmarshal(raw, &me); err != nil {
				return err
			}
			printKV(w, []kv{
				{"id", me.ID},
				{"sub", dash(me.Sub)},
				{"name", dash(me.Name)},
				{"is_admin", fmt.Sprintf("%t", me.IsAdmin)},
				{"auth", me.Auth},
			})
			return nil
		})
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon reconcile status (admin only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		raw, err := c.Do(http.MethodGet, "/status", nil)
		if err != nil {
			return err
		}
		return output(cmd, raw, func(w io.Writer) error {
			var data map[string]json.RawMessage
			if err := json.Unmarshal(raw, &data); err != nil {
				return err
			}
			if checkedRaw, ok := data["_checked_at"]; ok {
				var checked string
				if json.Unmarshal(checkedRaw, &checked) == nil && checked != "" {
					fmt.Fprintf(w, "checked_at: %s\n", checked)
				}
			}
			if dnsRaw, ok := data["_dns"]; ok {
				var d struct {
					Enabled   bool   `json:"enabled"`
					LastSync  string `json:"last_sync"`
					LastError string `json:"last_error"`
				}
				if json.Unmarshal(dnsRaw, &d) == nil {
					switch {
					case !d.Enabled:
						fmt.Fprintln(w, "dns: disabled (DYATEL_CLOUDFLARE_TOKEN is not set)")
					case d.LastError != "":
						fmt.Fprintf(w, "dns: error: %s\n", d.LastError)
					case d.LastSync != "":
						fmt.Fprintf(w, "dns: synced at %s\n", d.LastSync)
					default:
						fmt.Fprintln(w, "dns: awaiting first sync")
					}
				}
			}
			type peerStat struct {
				Endpoint      string `json:"endpoint"`
				LastHandshake string `json:"last_handshake"`
				TransferRx    int64  `json:"transfer_rx"`
				TransferTx    int64  `json:"transfer_tx"`
			}
			type hostStat struct {
				Name       string              `json:"name"`
				Interface  string              `json:"interface"`
				State      string              `json:"state"`
				ListenPort int                 `json:"listen_port"`
				Transport  string              `json:"transport"`
				Endpoints  map[string]peerStat `json:"endpoints"`
				LastError  string              `json:"last_error"`
			}
			keys := make([]string, 0, len(data))
			for k := range data {
				if k != "_checked_at" {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			rows := make([][]string, 0, len(keys))
			for _, k := range keys {
				var hs hostStat
				if err := json.Unmarshal(data[k], &hs); err != nil || hs.Name == "" {
					continue
				}
				fmtPeer := func(p peerStat) string {
					if p.Endpoint == "" && p.LastHandshake == "" && p.TransferRx == 0 && p.TransferTx == 0 {
						return "-"
					}
					ep := dash(p.Endpoint)
					hsStr := "never"
					if sec, err := strconv.ParseInt(p.LastHandshake, 10, 64); err == nil && sec > 0 {
						hsStr = time.Unix(sec, 0).UTC().Format("15:04:05Z")
					}
					return fmt.Sprintf("%s (hs=%s rx=%d tx=%d)", ep, hsStr, p.TransferRx, p.TransferTx)
				}
				rows = append(rows, []string{
					hs.Name, dash(hs.Interface), hs.Transport, hs.State,
					strconv.Itoa(hs.ListenPort),
					fmtPeer(hs.Endpoints["proxer"]),
					fmtPeer(hs.Endpoints["consumer"]),
					dash(hs.LastError),
				})
			}
			printTable(w, []string{"NAME", "IFACE", "TRANSPORT", "STATE", "PORT", "PROXER", "CONSUMER", "ERROR"}, rows)
			return nil
		})
	},
}
