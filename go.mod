module wireproxy

go 1.20

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/akamensky/argparse v1.3.1
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/go-ini/ini v1.66.4
	github.com/google/btree v1.0.1 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.1-0.20230222185716-a3b23cc77e89 // indirect
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20220829161405-d1d08426b27b
	gvisor.dev/gvisor v0.0.0-20221203005347-703fd9b7fbc0
	suah.dev/protect v1.2.0
)

require github.com/patrickmn/go-cache v2.1.0+incompatible

require github.com/stretchr/testify v1.8.0 // indirect

replace golang.zx2c4.com/wireguard => ./pkg/wireguard-go
