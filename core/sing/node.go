package sing

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/goccy/go-json"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
)

type HttpNetworkConfig struct {
	Header struct {
		Type     string           `json:"type"`
		Request  *json.RawMessage `json:"request"`
		Response *json.RawMessage `json:"response"`
	} `json:"header"`
}

type HttpRequest struct {
	Version string   `json:"version"`
	Method  string   `json:"method"`
	Path    []string `json:"path"`
	Headers struct {
		Host []string `json:"Host"`
	} `json:"headers"`
}

type WsNetworkConfig struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type GrpcNetworkConfig struct {
	ServiceName string `json:"serviceName"`
}

type HttpupgradeNetworkConfig struct {
	Path string `json:"path"`
	Host string `json:"host"`
}

func getInboundOptions(tag string, info *panel.NodeInfo, c *conf.Options) (option.Inbound, error) {
	addr, err := netip.ParseAddr(c.ListenIP)
	if err != nil {
		return option.Inbound{}, fmt.Errorf("the listen ip not vail")
	}
	var domainStrategy option.DomainStrategy
	if c.SingOptions.EnableDNS {
		domainStrategy = c.SingOptions.DomainStrategy
	}
	listen := option.ListenOptions{
		Listen:      (*badoption.Addr)(&addr),
		ListenPort:  uint16(info.Common.ServerPort),
		TCPFastOpen: c.SingOptions.TCPFastOpen,
		InboundOptions: option.InboundOptions{
			SniffEnabled:             c.SingOptions.SniffEnabled,
			SniffOverrideDestination: c.SingOptions.SniffOverrideDestination,
			DomainStrategy:           domainStrategy,
		},
	}
	var multiplex *option.InboundMultiplexOptions
	if c.SingOptions.Multiplex != nil {
		multiplexOption := option.InboundMultiplexOptions{
			Enabled: c.SingOptions.Multiplex.Enabled,
			Padding: c.SingOptions.Multiplex.Padding,
			Brutal: &option.BrutalOptions{
				Enabled:  c.SingOptions.Multiplex.Brutal.Enabled,
				UpMbps:   c.SingOptions.Multiplex.Brutal.UpMbps,
				DownMbps: c.SingOptions.Multiplex.Brutal.DownMbps,
			},
		}
		multiplex = &multiplexOption
	}
	var tls option.InboundTLSOptions
	switch info.Security {
	case panel.Tls:
		if c.CertConfig == nil {
			return option.Inbound{}, fmt.Errorf("the CertConfig is not vail")
		}
		switch c.CertConfig.CertMode {
		case "none", "":
			break // disable
		default:
			tls.Enabled = true
			tls.CertificatePath = c.CertConfig.CertFile
			tls.KeyPath = c.CertConfig.KeyFile
		}
	case panel.Reality:
		tls.Enabled = true
		if info.Type == "anytls" {
			v := info.AnyTLS
			tls.ServerName = v.TlsSettings.ServerName
			port, _ := strconv.Atoi(v.TlsSettings.ServerPort)
			var dest string
			if v.TlsSettings.Dest != "" {
				dest = v.TlsSettings.Dest
			} else {
				dest = tls.ServerName
			}

			mtd, _ := time.ParseDuration(v.RealityConfig.MaxTimeDiff)
			tls.Reality = &option.InboundRealityOptions{
				Enabled:    true,
				ShortID:    []string{v.TlsSettings.ShortId},
				PrivateKey: v.TlsSettings.PrivateKey,
				Xver:       uint8(v.TlsSettings.Xver),
				Handshake: option.InboundRealityHandshakeOptions{
					ServerOptions: option.ServerOptions{
						Server:     dest,
						ServerPort: uint16(port),
					},
				},
				MaxTimeDifference: badoption.Duration(mtd),
			}
		} else {
			v := info.VAllss
			tls.ServerName = v.TlsSettings.ServerName
			port, _ := strconv.Atoi(v.TlsSettings.ServerPort)
			var dest string
			if v.TlsSettings.Dest != "" {
				dest = v.TlsSettings.Dest
			} else {
				dest = tls.ServerName
			}

			mtd, _ := time.ParseDuration(v.RealityConfig.MaxTimeDiff)
			tls.Reality = &option.InboundRealityOptions{
				Enabled:    true,
				ShortID:    []string{v.TlsSettings.ShortId},
				PrivateKey: v.TlsSettings.PrivateKey,
				Xver:       uint8(v.TlsSettings.Xver),
				Handshake: option.InboundRealityHandshakeOptions{
					ServerOptions: option.ServerOptions{
						Server:     dest,
						ServerPort: uint16(port),
					},
				},
				MaxTimeDifference: badoption.Duration(mtd),
			}
		}
	}
	in := option.Inbound{
		Tag: tag,
	}
	switch info.Type {
	case "vmess", "vless":
		n := info.VAllss
		t := option.V2RayTransportOptions{
			Type: n.Network,
		}
		switch n.Network {
		case "tcp":
			if len(n.NetworkSettings) != 0 {
				network := HttpNetworkConfig{}
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				//Todo fix http options
				if network.Header.Type == "http" {
					t.Type = network.Header.Type
					var request HttpRequest
					if network.Header.Request != nil {
						err = json.Unmarshal(*network.Header.Request, &request)
						if err != nil {
							return option.Inbound{}, fmt.Errorf("decode HttpRequest error: %s", err)
						}
						t.HTTPOptions.Host = request.Headers.Host
						t.HTTPOptions.Path = request.Path[0]
						t.HTTPOptions.Method = request.Method
					}
				} else {
					t.Type = ""
				}
			} else {
				t.Type = ""
			}
		case "ws":
			var (
				path    string
				ed      int
				headers map[string]badoption.Listable[string]
			)
			if len(n.NetworkSettings) != 0 {
				network := WsNetworkConfig{}
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				var u *url.URL
				u, err = url.Parse(network.Path)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("parse path error: %s", err)
				}
				path = u.Path
				ed, _ = strconv.Atoi(u.Query().Get("ed"))
				headers = make(map[string]badoption.Listable[string], len(network.Headers))
				for k, v := range network.Headers {
					headers[k] = badoption.Listable[string]{
						v,
					}
				}
			}
			t.WebsocketOptions = option.V2RayWebsocketOptions{
				Path:                path,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
				MaxEarlyData:        uint32(ed),
				Headers:             headers,
			}
		case "grpc":
			network := GrpcNetworkConfig{}
			if len(n.NetworkSettings) != 0 {
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.GRPCOptions = option.V2RayGRPCOptions{
				ServiceName: network.ServiceName,
			}
		case "httpupgrade":
			network := HttpupgradeNetworkConfig{}
			if len(n.NetworkSettings) != 0 {
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
				Path: network.Path,
				Host: network.Host,
			}
		}
		if info.Type == "vless" {
			in.Type = "vless"
			in.Options = &option.VLESSInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: &t,
				Multiplex: multiplex,
			}
		} else {
			in.Type = "vmess"
			in.Options = &option.VMessInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: &t,
				Multiplex: multiplex,
			}
		}
	case "shadowsocks":
		in.Type = "shadowsocks"
		n := info.Shadowsocks
		var keyLength int
		switch n.Cipher {
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			keyLength = 32
		default:
			keyLength = 16
		}
		ssoption := &option.ShadowsocksInboundOptions{
			ListenOptions: listen,
			Method:        n.Cipher,
			Multiplex:     multiplex,
		}
		p := make([]byte, keyLength)
		_, _ = rand.Read(p)
		randomPasswd := string(p)
		if strings.Contains(n.Cipher, "2022") {
			ssoption.Password = n.ServerKey
			randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		}
		ssoption.Users = []option.ShadowsocksUser{{
			Password: randomPasswd,
		}}
		in.Options = ssoption
	case "trojan":
		n := info.Trojan
		t := option.V2RayTransportOptions{
			Type: n.Network,
		}
		switch n.Network {
		case "tcp":
			t.Type = ""
		case "ws":
			var (
				path    string
				ed      int
				headers map[string]badoption.Listable[string]
			)
			if len(n.NetworkSettings) != 0 {
				network := WsNetworkConfig{}
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				var u *url.URL
				u, err = url.Parse(network.Path)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("parse path error: %s", err)
				}
				path = u.Path
				ed, _ = strconv.Atoi(u.Query().Get("ed"))
				headers = make(map[string]badoption.Listable[string], len(network.Headers))
				for k, v := range network.Headers {
					headers[k] = badoption.Listable[string]{
						v,
					}
				}
			}
			t.WebsocketOptions = option.V2RayWebsocketOptions{
				Path:                path,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
				MaxEarlyData:        uint32(ed),
				Headers:             headers,
			}
		case "grpc":
			network := GrpcNetworkConfig{}
			if len(n.NetworkSettings) != 0 {
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.GRPCOptions = option.V2RayGRPCOptions{
				ServiceName: network.ServiceName,
			}
		default:
			t.Type = ""
		}
		in.Type = "trojan"
		trojanoption := &option.TrojanInboundOptions{
			ListenOptions: listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
			Transport: &t,
			Multiplex: multiplex,
		}
		if c.SingOptions.FallBackConfigs != nil {
			// fallback handling
			fallback := c.SingOptions.FallBackConfigs.FallBack
			fallbackPort, err := strconv.Atoi(fallback.ServerPort)
			if err == nil {
				trojanoption.Fallback = &option.ServerOptions{
					Server:     fallback.Server,
					ServerPort: uint16(fallbackPort),
				}
			}
			fallbackForALPNMap := c.SingOptions.FallBackConfigs.FallBackForALPN
			fallbackForALPN := make(map[string]*option.ServerOptions, len(fallbackForALPNMap))
			if err := processFallback(c, fallbackForALPN); err == nil {
				trojanoption.FallbackForALPN = fallbackForALPN
			}
		}
		in.Options = trojanoption
	case "tuic":
		in.Type = "tuic"
		tls.ALPN = append(tls.ALPN, "h3")
		in.Options = &option.TUICInboundOptions{
			ListenOptions:     listen,
			CongestionControl: info.Tuic.CongestionControl,
			ZeroRTTHandshake:  info.Tuic.ZeroRTTHandshake,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "anytls":
		in.Type = "anytls"
		var paddingScheme badoption.Listable[string]
		if info.AnyTLS.PaddingScheme != nil && len(info.AnyTLS.PaddingScheme) != 0 {
			var arr []string
			err := json.Unmarshal(info.AnyTLS.PaddingScheme, &arr)
			if err == nil {
				paddingScheme = badoption.Listable[string](arr)
			}
		}
		in.Options = &option.AnyTLSInboundOptions{
			ListenOptions: listen,
			PaddingScheme: paddingScheme,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}

	case "hysteria":
		in.Type = "hysteria"
		in.Options = &option.HysteriaInboundOptions{
			ListenOptions: listen,
			UpMbps:        info.Hysteria.UpMbps,
			DownMbps:      info.Hysteria.DownMbps,
			Obfs:          info.Hysteria.Obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "hysteria2":
		in.Type = "hysteria2"
		var obfs *option.Hysteria2Obfs
		if info.Hysteria2.ObfsType != "" && info.Hysteria2.ObfsPassword != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     info.Hysteria2.ObfsType,
				Password: info.Hysteria2.ObfsPassword,
			}
		} else if info.Hysteria2.ObfsType != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     "salamander",
				Password: info.Hysteria2.ObfsType,
			}
		}
		in.Options = &option.Hysteria2InboundOptions{
			ListenOptions:         listen,
			UpMbps:                info.Hysteria2.UpMbps,
			DownMbps:              info.Hysteria2.DownMbps,
			IgnoreClientBandwidth: info.Hysteria2.Ignore_Client_Bandwidth,
			Obfs:                  obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	}
	return in, nil
}

func (b *Sing) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	c, err := getInboundOptions(tag, info, config)
	if err != nil {
		return err
	}
	in := b.box.Inbound()
	err = in.Create(
		b.ctx,
		b.box.Router(),
		b.logFactory.NewLogger(F.ToString("inbound/", c.Type, "[", tag, "]")),
		tag,
		c.Type,
		c.Options,
	)

	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (b *Sing) DelNode(tag string) error {
	in := b.box.Inbound()
	err := in.Remove(tag)
	if err != nil {
		return fmt.Errorf("delete inbound error: %s", err)
	}
	return nil
}
