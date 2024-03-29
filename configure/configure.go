package configure

import (
	"encoding/json"
	"io"
	"log"
	"os"
)

// AppConfig ..
type AppConfig struct {
	ServerPort     uint16 `json:"server_port"`
	Server         string `json:"server"`
	QuicServerPort uint16 `json:"quic_server_port"`
	DnsPort        uint16 `json:"dns_port"`
	LocalPort      uint16 `json:"local_port"`
	LocalQuicPort  uint16 `json:"local_quic_port"`
	Local          string `json:"local"`
	Which          string `json:"which"`
	Method         string `json:"method"`
	Password       string `json:"password"`
	Timeout        uint32 `json:"timeout"`
}

// Parse ..
func Parse(path string) (config *AppConfig, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	config = &AppConfig{}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// DumpConfig ..
func DumpConfig(config *AppConfig) {
	log.Println("server :", config.Server)
	log.Println("server_port :", config.ServerPort)
	log.Println("quic_server_port :", config.QuicServerPort)
	log.Println("local_port :", config.LocalPort)
	log.Println("local_quic_port :", config.LocalQuicPort)
	log.Println("dns_port :", config.DnsPort)
	log.Println("local :", config.Local)
	log.Println("which :", config.Which)
	log.Println("method :", config.Method)
	log.Println("password :", config.Password)
	log.Println("timeout :", config.Timeout)
}
