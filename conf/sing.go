package conf

import (
	"github.com/sagernet/sing-box/option"
)

type SingConfig struct {
	LogConfig    SingLogConfig `json:"Log"`
	NtpConfig    SingNtpConfig `json:"NTP"`
	OriginalPath string        `json:"OriginalPath"`
}

type SingLogConfig struct {
	Disabled  bool   `json:"Disable"`
	Level     string `json:"Level"`
	Output    string `json:"Output"`
	Timestamp bool   `json:"Timestamp"`
}

func NewSingConfig() *SingConfig {
	return &SingConfig{
		LogConfig: SingLogConfig{
			Level:     "error",
			Timestamp: true,
		},
		NtpConfig: SingNtpConfig{
			Enable:     false,
			Server:     "time.apple.com",
			ServerPort: 0,
		},
	}
}

type SingOptions struct {
	TCPFastOpen              bool                   `json:"EnableTFO"`
	SniffEnabled             bool                   `json:"EnableSniff"`
	SniffOverrideDestination bool                   `json:"SniffOverrideDestination"`
	EnableDNS                bool                   `json:"EnableDNS"`
	DomainStrategy           option.DomainStrategy  `json:"DomainStrategy"`
	FallBackConfigs          *FallBackConfigForSing `json:"FallBackConfigs"`
	Multiplex                *MultiplexConfig       `json:"MultiplexConfig"`
}

type SingNtpConfig struct {
	Enable     bool   `json:"Enable"`
	Server     string `json:"Server"`
	ServerPort uint16 `json:"ServerPort"`
}

type FallBackConfigForSing struct {
	// sing-box
	FallBack        FallBack            `json:"FallBack"`
	FallBackForALPN map[string]FallBack `json:"FallBackForALPN"`
}

type FallBack struct {
	Server     string `json:"Server"`
	ServerPort string `json:"ServerPort"`
}

type MultiplexConfig struct {
	Enabled bool          `json:"Enable"`
	Padding bool          `json:"Padding"`
	Brutal  BrutalOptions `json:"Brutal"`
}

type BrutalOptions struct {
	Enabled  bool `json:"Enable"`
	UpMbps   int  `json:"UpMbps"`
	DownMbps int  `json:"DownMbps"`
}

func NewSingOptions() *SingOptions {
	return &SingOptions{
		EnableDNS:                false,
		TCPFastOpen:              false,
		SniffEnabled:             true,
		SniffOverrideDestination: true,
		FallBackConfigs:          &FallBackConfigForSing{},
		Multiplex:                &MultiplexConfig{},
	}
}
