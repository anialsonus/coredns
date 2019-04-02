package adcm_lookup

import (
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/mholt/caddy"
)

var log = clog.NewWithPlugin("adcm_lookup")

func init() {
	caddy.RegisterPlugin("adcm_lookup", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func periodicHostsUpdate(h *Hosts) chan bool {
	parseChan := make(chan bool)

	if h.options.reload == durationOf0s {
		return parseChan
	}

	go func() {
		ticker := time.NewTicker(h.options.reload)
		for {
			select {
			case <-parseChan:
				return
			case <-ticker.C:
				h.readHosts()
			}
		}
	}()
	return parseChan
}

func setup(c *caddy.Controller) error {
	h, err := hostsParse(c)
	if err != nil {
		return plugin.Error("hosts", err)
	}

	parseChan := periodicHostsUpdate(&h)

	c.OnStartup(func() error {
		h.readHosts()
		return nil
	})

	c.OnShutdown(func() error {
		close(parseChan)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})

	return nil
}

func hostsParse(c *caddy.Controller) (Hosts, error) {

	options := newOptions()

	h := Hosts{
		Hostsfile: &Hostsfile{
			hmap:    newHostsMap(),
			options: options,
		},
	}

	inline := []string{}
	i := 0
	for c.Next() {
		if i > 0 {
			return h, plugin.ErrOnce
		}
		i++

		args := c.RemainingArgs()

		if len(args) < 3 {
			return h, c.Errf("not enough params provided")
		} else {
			h.adcm_url = args[0]
			h.adcm_login = args[1]
			h.adcm_pass = args[2]
			args = args[3:]
		}

		origins := make([]string, len(c.ServerBlockKeys))
		copy(origins, c.ServerBlockKeys)
		if len(args) > 0 {
			origins = args
		}

		for i := range origins {
			origins[i] = plugin.Host(origins[i]).Normalize()
		}
		h.Origins = origins

		for c.NextBlock() {
			switch c.Val() {
			case "fallthrough":
				h.Fall.SetZonesFromArgs(c.RemainingArgs())
			case "no_reverse":
				options.autoReverse = false
			case "ttl":
				remaining := c.RemainingArgs()
				if len(remaining) < 1 {
					return h, c.Errf("ttl needs a time in second")
				}
				ttl, err := strconv.Atoi(remaining[0])
				if err != nil {
					return h, c.Errf("ttl needs a number of second")
				}
				if ttl <= 0 || ttl > 65535 {
					return h, c.Errf("ttl provided is invalid")
				}
				options.ttl = uint32(ttl)
			case "reload":
				remaining := c.RemainingArgs()
				if len(remaining) != 1 {
					return h, c.Errf("reload needs a duration (zero seconds to disable)")
				}
				reload, err := time.ParseDuration(remaining[0])
				if err != nil {
					return h, c.Errf("invalid duration for reload '%s'", remaining[0])
				}
				if reload < durationOf0s {
					return h, c.Errf("invalid negative duration for reload '%s'", remaining[0])
				}
				options.reload = reload
			default:
				if len(h.Fall.Zones) == 0 {
					line := strings.Join(append([]string{c.Val()}, c.RemainingArgs()...), " ")
					inline = append(inline, line)
					continue
				}
				return h, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	return h, nil
}
