package check

import (
	"context"
	"net"
	"strings"
)

type InterfaceAddress struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	MTU     int    `json:"mtu"`
}
type ConnectionDetails struct {
	Addresses      []InterfaceAddress `json:"addresses"`
	DefaultRoute   bool               `json:"default_route"`
	RouteInterface string             `json:"route_interface,omitempty"`
}

func (e *Engine) connection(ctx context.Context, j job) Result {
	r := Result{Check: j.id, Target: "local", IPVersion: j.version, Status: "FAIL"}
	d := ConnectionDetails{Addresses: []InterfaceAddress{}}
	interfaces, err := net.Interfaces()
	if err != nil {
		r.Status = "ERROR"
		r.Reason = "インターフェース取得失敗"
		return r
	}
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			r.Status = "ERROR"
			r.Reason = "アドレス取得失敗"
			return r
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && family(ip.String()) == j.version && !ip.IsUnspecified() {
				d.Addresses = append(d.Addresses, InterfaceAddress{i.Name, a.String(), i.MTU})
			}
		}
	}
	cmd, err := e.Platform.route(j.version)
	if err != nil {
		r.Status = "SKIP"
		r.Reason = err.Error()
		return r
	}
	o := e.Runner.Run(ctx, cmd)
	if o.Err != nil {
		r.Status, r.Reason = commandFailure(o)
	} else {
		for _, line := range strings.Split(o.Output, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			if e.Platform.OS == "linux" && f[0] == "default" {
				d.DefaultRoute = true
				for i := 1; i < len(f)-1; i++ {
					if f[i] == "dev" {
						d.RouteInterface = f[i+1]
					}
				}
			}
			if e.Platform.OS == "darwin" && f[0] == "destination:" && len(f) > 1 && f[1] == "default" {
				d.DefaultRoute = true
			}
			if e.Platform.OS == "darwin" && f[0] == "interface:" && len(f) > 1 {
				d.RouteInterface = f[1]
			}
		}
		if len(d.Addresses) > 0 && d.DefaultRoute {
			r.Status = "PASS"
			r.Reason = "有効なインターフェースのアドレスとデフォルトルートを確認（疎通は別検査）"
		} else {
			r.Reason = "アドレスまたはデフォルトルートがありません"
		}
	}
	r.Details = d
	return r
}
