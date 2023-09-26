package proxycore

import (
	"chimney-go2/configure"
	"io"
)

type MF func(configure.AppConfig) io.ReadWriteCloser

type ProxySetting struct {
	NetType        string
	NetworkMakeFun MF
	config         configure.AppConfig
	Exit           bool
}
