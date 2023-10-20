package main

import (
	"chimney-go2/configure"
	"chimney-go2/utils"
	"chimney-go2/vpnkinds"
	"flag"
	"fmt"
	"os"
	"runtime"
)

var (
	isServer *bool
)

func main() {
	var configpath string
	cpu := runtime.NumCPU()
	runtime.GOMAXPROCS(cpu * 4)
	dir, _ := utils.RetrieveExePath()
	configpath = dir + "/config.json"
	if (len(configpath)) == 0 {
		fmt.Println("config file path is incorrect!!", configpath)
		os.Exit(1)
	}

	config, err := configure.Parse(configpath)
	if err != nil {
		fmt.Println("load config file failed!", err)
		os.Exit(1)
	}

	isServer = flag.Bool("s", false, "a bool")
	flag.Parse()

	vpnkinds.RunServer(*config, *isServer)
	//vpnkinds.RunServer(*config, true)
}
