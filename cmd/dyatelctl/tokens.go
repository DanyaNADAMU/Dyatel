package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// tokens implements the PAT lifecycle (RFC §3.2). A token is minted with a
// human label, printed exactly once, and revoked by id — never rotated in
// place, because a rotation window is indistinguishable from a leak.
var tokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Manage personal access tokens (dyatel_*)",
}

var tokensCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Mint a PAT and print it once",
	Long: "Mint a PAT for CLI and script use. The full secret is printed\n" +
		"exactly once and never stored in plaintext by the daemon.",
	RunE: func(cmd *cobra.Command, args []string) error {
		label, _ := cmd.Flags().GetString("label")
		if label == "" {
			return fmt.Errorf("--label is required (e.g. laptop, vps, ci)")
		}
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		t, err := c.CreateToken(label)
		if err != nil {
			return err
		}
		return output(cmd, mustJSON(t), func(w io.Writer) error {
			printKV(w, []kv{
				{"id", t.ID},
				{"label", t.Label},
				{"token", t.Secret},
			})
			_, err := fmt.Fprintln(w, "\nStore this token now: the daemon keeps only its hash.")
			return err
		})
	},
}

var tokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your tokens (metadata only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		ts, err := c.ListTokens()
		if err != nil {
			return err
		}
		return output(cmd, mustJSON(ts), func(w io.Writer) error {
			rows := make([][]string, 0, len(ts))
			for _, t := range ts {
				state := "active"
				if t.RevokedAt != "" {
					state = "revoked"
				}
				rows = append(rows, []string{
					t.ID, t.Label, state, dash(t.LastUsedAt), t.CreatedAt,
				})
			}
			printTable(w, []string{"ID", "LABEL", "STATE", "LAST_USED", "CREATED"}, rows)
			return nil
		})
	},
}

var tokensRmCmd = &cobra.Command{
	Use:   "rm TOKENID",
	Short: "Revoke a token by id",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		if err := c.RevokeToken(args[0]); err != nil {
			return err
		}
		fmt.Println("revoked", args[0])
		return nil
	},
}

// reconcileCmd forces a loop pass instead of waiting up to the tick interval.
var reconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Trigger a reconcile pass now",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		if err := c.TriggerReconcile(); err != nil {
			return err
		}
		fmt.Println("reconcile queued")
		return nil
	},
}

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Search the user directory (for consumer invitations)",
}

var usersListCmd = &cobra.Command{
	Use:   "list [QUERY]",
	Short: "List users, optionally filtered by display name",
	RunE: func(cmd *cobra.Command, args []string) error {
		q := ""
		if len(args) > 0 {
			q = args[0]
		}
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		us, err := c.ListUsers(q)
		if err != nil {
			return err
		}
		return output(cmd, mustJSON(us), func(w io.Writer) error {
			rows := make([][]string, 0, len(us))
			for _, u := range us {
				admin := ""
				if u.IsAdmin {
					admin = "admin"
				}
				rows = append(rows, []string{u.ID, u.DisplayName, admin})
			}
			printTable(w, []string{"ID", "NAME", "ROLE"}, rows)
			return nil
		})
	},
}

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Show the audit feed (own actions; admins see all)",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		c, err := clientFrom(cmd)
		if err != nil {
			return err
		}
		evs, err := c.ListEvents(limit)
		if err != nil {
			return err
		}
		return output(cmd, mustJSON(evs), func(w io.Writer) error {
			rows := make([][]string, 0, len(evs))
			for _, e := range evs {
				rows = append(rows, []string{
					e.At, e.AuthMethod, e.Action, e.ObjectType, e.ObjectID,
				})
			}
			printTable(w, []string{"AT", "AUTH", "ACTION", "OBJECT", "ID"}, rows)
			return nil
		})
	},
}

// mustJSON is the --json passthrough payload for locally built responses.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
