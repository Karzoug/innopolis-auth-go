package main

import (
	"context"
	"log"

	"github.com/Karzoug/innopolis-auth-go/cmd/commands"
)

func main() {
	ctx := context.Background()

	commands.RootCmd.AddCommand(commands.NewGenKeysCmd())
	commands.RootCmd.AddCommand(commands.NewServeCmd())

	if err := commands.RootCmd.ExecuteContext(ctx); err != nil {
		log.Fatalf("smth went wrong: %s", err)
	}
}
