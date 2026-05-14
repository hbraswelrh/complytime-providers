// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/complytime/complyctl/pkg/provider"
	"github.com/complytime/complytime-providers/cmd/openscap-provider/server"
)

func main() {
	openSCAPProvider := server.New()
	provider.Serve(openSCAPProvider)
}
