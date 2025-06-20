package main

import (
	"fmt"

	"github.com/perplext/zerodaybuddy/internal/version"
	"github.com/spf13/cobra"
)

func createVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Print version information including Git commit, build date, and Go version.`,
		Run: func(cmd *cobra.Command, args []string) {
			if short, _ := cmd.Flags().GetBool("short"); short {
				fmt.Println(version.GetVersion())
			} else {
				fmt.Println(version.BuildInfo())
			}
		},
	}
	
	cmd.Flags().BoolP("short", "s", false, "Print only the version number")
	return cmd
}