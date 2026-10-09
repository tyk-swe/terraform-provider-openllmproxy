package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/tyk-swe/terraform-provider-openllmproxy/internal/provider"
)

var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "Enable protocol debugging")
	flag.Parse()
	if err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{Address: "registry.terraform.io/tyk-swe/openllmproxy", Debug: *debug}); err != nil {
		log.Fatal(err)
	}
}
