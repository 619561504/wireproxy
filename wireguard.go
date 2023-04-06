package wireproxy

import (
	"bytes"
	"fmt"
	"golang.zx2c4.com/wireguard/ipc"
	"log"
	"os"
	"strconv"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	ENV_WG_UAPI_FD = "WG_UAPI_FD"
	interfaceName  = "wg1"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr []netip.Addr
	mtu        int
}

// serialize the config into an IPC request and DeviceSetting
func createIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))
	request.WriteString(fmt.Sprintf("listen_port=%d\n", conf.ListenPort))

	for _, peer := range conf.Peers {
		if len(peer.Endpoint) > 0 {
			request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				endpoint=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
				peer.PublicKey, peer.Endpoint, peer.KeepAlive, peer.PreSharedKey,
			))
		} else {
			request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
				peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
			))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{ipcRequest: request.String(), dns: conf.DNS, deviceAddr: conf.Endpoint, mtu: conf.MTU}
	return setting, nil
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *DeviceConfig) (*VirtualTun, error) {
	setting, err := createIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.deviceAddr, setting.dns, setting.mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	err = dev.IpcSet(setting.ipcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		log.Printf("Failed to determine executable: %v\n", err)
		os.Exit(1)
	}
	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		log.Printf("Failed to listen on uapi socket: %v", err)
		os.Exit(1)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				continue
			}
			go dev.IpcHandle(conn)
		}
	}()

	return &VirtualTun{
		VirtualNet: tnet,
		systemDNS:  len(setting.dns) == 0,
	}, nil
}
