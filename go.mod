module github.com/hysterguard/hysterguard

go 1.23.1

require (
	github.com/apernet/hysteria/core/v2 v2.0.0
	github.com/apernet/hysteria/extras/v2 v2.0.0
	github.com/spf13/cobra v1.8.1
	golang.zx2c4.com/wireguard v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/apernet/quic-go v0.54.1-0.20251024023933-5e0818a71079 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace (
	github.com/apernet/hysteria/core/v2 => ../hysteria/core
	github.com/apernet/hysteria/extras/v2 => ../hysteria/extras
	golang.zx2c4.com/wireguard => ../wireguard-go
)
