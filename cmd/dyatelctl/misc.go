package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
			// Status is an open map[string]any from the reconcile loop;
			// pretty-printing beats inventing a schema the daemon may grow.
			var buf json.RawMessage = raw
			indented, err := json.MarshalIndent(&buf, "", "  ")
			if err != nil {
				return err
			}
			_, err = w.Write(append(indented, '\n'))
			return err
		})
	},
}
