package main

import (
	"flag"
	"fmt"

	"github.com/actiontech/sqle-pg-plugin/internal/inspector"
	"github.com/actiontech/sqle/sqle/driver"
)

var version string

var printVersion = flag.Bool("version", false, "Print version & exit")

func main() {
	flag.Parse()

	if *printVersion {
		fmt.Println(version)
		return
	}

	driver.ServePlugin(inspector.NewRegisterer(), inspector.NewDriver)
}
