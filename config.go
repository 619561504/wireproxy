package wireproxy

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
	"wireproxy/pkg/cache"
	"wireproxy/pkg/goproxy"

	"github.com/go-ini/ini"

	"net/netip"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

// DeviceConfig contains the information to initiate a wireguard connection
type DeviceConfig struct {
	SecretKey  string
	ListenPort int
	Endpoint   []netip.Addr
	Peers      []PeerConfig
	DNS        []netip.Addr
	MTU        int
}

type TCPClientTunnelConfig struct {
	BindAddress *net.TCPAddr
	Target      string
}

type TCPServerTunnelConfig struct {
	ListenPort int
	Target     string
}

type Socks5Config struct {
	BindAddress string
	Username    string
	Password    string
}

type ConnectServerTunnelConfig struct {
	ListenPort int
	IsServer   bool // 是服务端模式，还是客户端模式
}

func (c *ConnectServerTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	proxy := goproxy.New(goproxy.WithPortPeerCache(cache.DefaultCache), goproxy.WithVirtualTun(vt.VirtualNet), goproxy.WithIsServer(c.IsServer))

	server := &http.Server{
		Addr:         fmt.Sprintf(":%v", c.ListenPort),
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	fmt.Printf("Connect Server Listen on: :%v\n", c.ListenPort)
	var err error
	if c.IsServer {
		err = server.ListenAndServe()
	} else {
		listener, err := vt.VirtualNet.ListenTCP(&net.TCPAddr{Port: c.ListenPort})
		if err != nil {
			panic(err)
		}
		err = server.Serve(listener)
	}

	if err != nil {
		panic(err)
	}
}

type Configuration struct {
	Device   *DeviceConfig
	Routines []RoutineSpawner
}

func parseString(section *ini.Section, keyName string) (string, error) {
	key := section.Key(strings.ToLower(keyName))
	if key == nil {
		return "", errors.New(keyName + " should not be empty")
	}
	return key.String(), nil
}

func parsePort(section *ini.Section, keyName string) (int, error) {
	key := section.Key(keyName)
	if key == nil {
		return 0, errors.New(keyName + " should not be empty")
	}
	port, err := key.Int()
	if err != nil {
		return 0, err
	}

	if !(port >= 0 && port < 65536) {
		return 0, errors.New("port should be >= 0 and < 65536")
	}

	return port, nil
}

func parseTCPAddr(section *ini.Section, keyName string) (*net.TCPAddr, error) {
	addrStr, err := parseString(section, keyName)
	if err != nil {
		return nil, err
	}
	return net.ResolveTCPAddr("tcp", addrStr)
}

func parseBase64KeyToHex(section *ini.Section, keyName string) (string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		return "", err
	}
	result, err := encodeBase64ToHex(key)
	if err != nil {
		return result, err
	}

	return result, nil
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}

func parseNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	var ips []netip.Addr
	for _, str := range key.StringsWithShadows(",") {
		str = strings.TrimSpace(str)
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseCIDRNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	var ips []netip.Addr
	for _, str := range key.StringsWithShadows(",") {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		addr := prefix.Addr()
		if prefix.Bits() != addr.BitLen() {
			return nil, errors.New("interface address subnet should be /32 for IPv4 and /128 for IPv6")
		}

		ips = append(ips, addr)
	}
	return ips, nil
}

func parseAllowedIPs(section *ini.Section) ([]netip.Prefix, error) {
	key := section.Key("AllowedIPs")
	if key == nil {
		return []netip.Prefix{}, nil
	}

	var ips []netip.Prefix
	for _, str := range key.StringsWithShadows(",") {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		ips = append(ips, prefix)
	}
	return ips, nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// ParseInterface parses the [Interface] section and extract the information into `device`
func ParseInterface(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Interface")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Interface] is expected")
	}
	section := sections[0]

	address, err := parseCIDRNetIP(section, "Address")
	if err != nil {
		return err
	}

	device.Endpoint = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.SecretKey = privKey

	dns, err := parseNetIP(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dns

	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	device.ListenPort = 0
	if sectionKey, err := section.GetKey("ListenPort"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.ListenPort = value
	}

	return nil
}

// ParsePeers parses the [Peer] section and extract the information into `peers`
func ParsePeers(cfg *ini.File, peers *[]PeerConfig) error {
	sections, err := cfg.SectionsByName("Peer")
	if len(sections) < 1 || err != nil {
		return errors.New("at least one [Peer] is expected")
	}

	for _, section := range sections {
		peer := PeerConfig{
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			KeepAlive:    0,
		}

		decoded, err := parseBase64KeyToHex(section, "PublicKey")
		if err != nil {
			return err
		}
		peer.PublicKey = decoded

		if sectionKey, err := section.GetKey("PreSharedKey"); err == nil {
			value, err := encodeBase64ToHex(sectionKey.String())
			if err != nil {
				return err
			}
			peer.PreSharedKey = value
		}

		decoded, err = parseString(section, "Endpoint")
		if err == nil {
			decoded, err = resolveIPPAndPort(decoded)
			if err == nil {
				peer.Endpoint = decoded
			}
		}

		if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
			value, err := sectionKey.Int()
			if err != nil {
				return err
			}
			peer.KeepAlive = value
		}

		peer.AllowedIPs, err = parseAllowedIPs(section)
		if err != nil {
			return err
		}

		*peers = append(*peers, peer)
	}
	return nil
}

func parseTCPClientTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &TCPClientTunnelConfig{}
	tcpAddr, err := parseTCPAddr(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = tcpAddr

	targetSection, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = targetSection

	return config, nil
}

func parseTCPServerTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &TCPServerTunnelConfig{}

	listenPort, err := parsePort(section, "ListenPort")
	if err != nil {
		return nil, err
	}
	config.ListenPort = listenPort

	target, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = target

	return config, nil
}

func parseConnectServerTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &ConnectServerTunnelConfig{}

	listenPort, err := parsePort(section, "ListenPort")
	if err != nil {
		return nil, err
	}
	config.ListenPort = listenPort

	// 解析是否是服务器模式
	isServer := section.Key("IsServer")
	if isServer == nil {
		config.IsServer = false
	} else {
		b, _ := isServer.Bool()
		config.IsServer = b
	}

	return config, nil
}

func parseSocks5Config(section *ini.Section) (RoutineSpawner, error) {
	config := &Socks5Config{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, _ := parseString(section, "Username")
	config.Username = username

	password, _ := parseString(section, "Password")
	config.Password = password

	return config, nil
}

// Takes a function that parses an individual section into a config, and apply it on all
// specified sections
func parseRoutinesConfig(routines *[]RoutineSpawner, cfg *ini.File, sectionName string, f func(*ini.Section) (RoutineSpawner, error)) error {
	sections, err := cfg.SectionsByName(sectionName)
	if err != nil {
		return nil
	}

	for _, section := range sections {
		config, err := f(section)
		if err != nil {
			return err
		}

		*routines = append(*routines, config)
	}

	return nil
}

// ParseConfig takes the path of a configuration file and parses it into Configuration
func ParseConfig(path string) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	cfg, err := ini.LoadSources(iniOpt, path)
	if err != nil {
		return nil, err
	}

	device := &DeviceConfig{
		MTU: 1420,
	}

	root := cfg.Section("")
	wgConf, err := root.GetKey("WGConfig")
	wgCfg := cfg
	if err == nil {
		wgCfg, err = ini.LoadSources(iniOpt, wgConf.String())
		if err != nil {
			return nil, err
		}
	}
	// 解析interface
	err = ParseInterface(wgCfg, device)
	if err != nil {
		return nil, err
	}

	err = ParsePeers(wgCfg, &device.Peers)
	if err != nil {
		return nil, err
	}

	var routinesSpawners []RoutineSpawner

	err = parseRoutinesConfig(&routinesSpawners, cfg, "TCPClientTunnel", parseTCPClientTunnelConfig)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "TCPServerTunnel", parseTCPServerTunnelConfig)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "Socks5", parseSocks5Config)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "ConnectServerTunnel", parseConnectServerTunnelConfig)

	if err != nil {
		return nil, err
	}

	return &Configuration{
		Device:   device,
		Routines: routinesSpawners,
	}, nil
}
