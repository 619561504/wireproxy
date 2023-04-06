/**
 * Created by wuhanjie on 2023/3/28 17:02
 */

package cache

import (
	cc "github.com/patrickmn/go-cache"
	"golang.zx2c4.com/wireguard/device"
	"strconv"
	"time"
)

// PortPeerCache 用于缓存端口的包走那个peer
type PortPeerCache interface {
	Set(port int, key *device.NoisePublicKey)
	Get(port int) *device.NoisePublicKey
}

var DefaultCache = NewDefaultPortPeerCache()

type DefaultPortPeerCache struct {
	cc *cc.Cache
}

func NewDefaultPortPeerCache() *DefaultPortPeerCache {
	c := cc.New(5*time.Minute, 5*time.Minute)
	return &DefaultPortPeerCache{cc: c}
}

func (d *DefaultPortPeerCache) Set(port int, key *device.NoisePublicKey) {
	d.cc.SetDefault(strconv.Itoa(port), key)
}

func (d *DefaultPortPeerCache) Get(port int) *device.NoisePublicKey {

	vv, ok := d.cc.Get(strconv.Itoa(port))
	if ok {
		return vv.(*device.NoisePublicKey)
	}
	return nil
}
