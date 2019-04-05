// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a modified version of net/hosts.go from the golang repo

package adcm_lookup

import (
	"net"
	"strings"
	"sync"
	"time"
	"net/http"
	"net/url"
	"encoding/json"
	"io/ioutil"
	"strconv"

	"github.com/coredns/coredns/plugin"
)

func parseLiteralIP(addr string) net.IP {
	if i := strings.Index(addr, "%"); i >= 0 {
		// discard ipv6 zone
		addr = addr[0:i]
	}

	return net.ParseIP(addr)
}

func absDomainName(b string) string {
	return plugin.Name(b).Normalize()
}

type options struct {
	// automatically generate IP to Hostname PTR entries
	// for host entries we parse
	autoReverse bool

	// The TTL of the record we generate
	ttl uint32

	// The time between two reload of the configuration
	reload time.Duration
}

func newOptions() *options {
	return &options{
		autoReverse: true,
		ttl:         3600,
		reload:      durationOf5s,
	}
}

type hostsMap struct {
	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byNameV4 map[string][]net.IP
	byNameV6 map[string][]net.IP

	// Key for the list of host names must be a literal IP address
	// including IPv6 address with zone identifier.
	// We don't support old-classful IP address notation.
	byAddr map[string][]string
}

const (
	durationOf0s = time.Duration(0)
	durationOf5s = time.Duration(5 * time.Second)
)

func newHostsMap() *hostsMap {
	return &hostsMap{
		byNameV4: make(map[string][]net.IP),
		byNameV6: make(map[string][]net.IP),
		byAddr:   make(map[string][]string),
	}
}

// Len returns the total number of addresses in the hostmap, this includes
// V4/V6 and any reverse addresses.
func (h *hostsMap) Len() int {
	l := 0
	for _, v4 := range h.byNameV4 {
		l += len(v4)
	}
	for _, v6 := range h.byNameV6 {
		l += len(v6)
	}
	for _, a := range h.byAddr {
		l += len(a)
	}
	return l
}

// Hostsfile contains known host entries.
type Hostsfile struct {
	sync.RWMutex

	// list of zones we are authoritative for
	Origins []string

	// hosts maps for lookups
	hmap *hostsMap

	// inline saves the hosts file that is inlined in a Corefile.
	// We need a copy here as we want to use it to initialize the maps for parse.

	// adcm credentials and url
	adcm_url  string
	adcm_login string
	adcm_pass  string

	// mtime and size are only read and modified by a single goroutine
	mtime time.Time
	size  int64

	options *options
}

// readHosts determines if the cached data needs to be updated based on the size and modification time of the hostsfile.
func (h *Hostsfile) readHosts() {

	newMap := h.populateHostsMaps()
	log.Debugf("Parsed hosts file into %d entries", newMap.Len())

	h.Lock()

	h.hmap = newMap
	// Update the data cache.

	h.Unlock()
}


// Parse reads the hostsfile and populates the byName and byAddr maps.

// ipVersion returns what IP version was used textually
// For why the string is parsed end to start,
// see IPv4-Compatible IPv6 addresses - RFC 4291 section 2.5.5
func ipVersion(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case '.':
			return 4
		case ':':
			return 6
		}
	}
	return 0
}

// LookupStaticHost looks up the IP addresses for the given host from the hosts file.
func (h *Hostsfile) lookupStaticHost(hmapByName map[string][]net.IP, host string) []net.IP {
	fqhost := absDomainName(host)

	h.RLock()
	defer h.RUnlock()

	if len(hmapByName) == 0 {
		return nil
	}

	ips, ok := hmapByName[fqhost]
	if !ok {
		return nil
	}
	ipsCp := make([]net.IP, len(ips))
	copy(ipsCp, ips)
	return ipsCp
}

// LookupStaticHostV4 looks up the IPv4 addresses for the given host from the hosts file.
func (h *Hostsfile) LookupStaticHostV4(host string) []net.IP {
	return h.lookupStaticHost(h.hmap.byNameV4, host)
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the hosts file.
func (h *Hostsfile) LookupStaticHostV6(host string) []net.IP {
	return h.lookupStaticHost(h.hmap.byNameV6, host)
}

// LookupStaticAddr looks up the hosts for the given address from the hosts file.
func (h *Hostsfile) LookupStaticAddr(addr string) []string {
	h.RLock()
	defer h.RUnlock()
	addr = parseLiteralIP(addr).String()
	if addr == "" {
		return nil
	}
	if len(h.hmap.byAddr) == 0 {
		return nil
	}
	hosts, ok := h.hmap.byAddr[addr]
	if !ok {
		return nil
	}
	hostsCp := make([]string, len(hosts))
	copy(hostsCp, hosts)
	return hostsCp
}

type host struct {
	ID int `json:"id"`
	FQDN string `json:"fqdn"`
}

type token struct {
	Token string `json:"token"`
}

type host_config struct {
	Config string `json:"config"`
}

type host_config_e struct {
	AnsibleHost string `json:"ansible_host"`
}

func (h *Hostsfile) populateHostsMaps() *hostsMap  {


	hmap := newHostsMap()
	fqdn_ip := make(map[string]string)
	//type M struct host
	host_url := h.adcm_url + "/api/v1/host/?format=json"
	token_url := h.adcm_url + "/api/v1/token/?format=json"

	httpClient := http.Client{
		Timeout: time.Second * 2, // Maximum of 2 secs
	}

	form := url.Values{}
	form.Set("username", h.adcm_login)
	form.Add("password", h.adcm_pass)
	req, err := http.NewRequest(http.MethodPost, token_url, strings.NewReader(form.Encode()))

	if err != nil {
		log.Error(err)
		return hmap
	}
	req.SetBasicAuth(h.adcm_login, h.adcm_pass)
	req.Header.Set("User-Agent", "core-dns")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, getErr := httpClient.Do(req)
	if getErr != nil {
		log.Error(getErr)
		return hmap
	}
	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Error(readErr)
		return hmap
	}

	token := token{}
	tokenJsonErr := json.Unmarshal(body, &token)
	if tokenJsonErr != nil {
		log.Error(tokenJsonErr)
		return hmap
	}


	req, err = http.NewRequest(http.MethodGet, host_url, nil)
	if err != nil {
		log.Error(err)
		return hmap
	}

	req.Header.Set("User-Agent", "core-dns")
	req.Header.Add("Authorization", "Token " + token.Token)

	res, getErr = httpClient.Do(req)
	if getErr != nil {
		log.Error(getErr)
		return hmap
	}

	body, readErr = ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Error(readErr)
		return hmap
	}

	var hostArr []host
	getHostsErr := json.Unmarshal(body, &hostArr)
	if readErr != nil {
		log.Error(getHostsErr)
		return hmap
	}


	for _, e := range hostArr {
		s := strconv.Itoa(e.ID)
		url := h.adcm_url + "/api/v1/host/" + s + "/config/current/?format=json"
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			log.Error(err)
			return hmap
		}
		req.Header.Set("User-Agent", "core-dns")
		req.Header.Add("Authorization", "Token " + token.Token)

		res, getErr := httpClient.Do(req)
		if getErr != nil {
			log.Error(getErr)
			return hmap
		}
		body, readErr := ioutil.ReadAll(res.Body)
		if readErr != nil {
			log.Error(readErr)
			return hmap
		}
		var host_config map[string]interface{}
		hostConfigJsonErr := json.Unmarshal(body, &host_config)
		if hostConfigJsonErr != nil {
			log.Error(hostConfigJsonErr)
			return hmap
		}
		host_config_e := host_config["config"].(map[string]interface{})
		// host_config_e := host_config_e{}
		// jsonErr := json.Unmarshal([]byte(host_config.Config), &host_config_e)
		// if jsonErr != nil {
		// 	log.Fatal(jsonErr)
		// }
		fqdn_ip[e.FQDN] = host_config_e["ansible_host"].(string)
	}
	for fqdn, ip := range fqdn_ip {
		ver := ipVersion(ip)
		ipp := net.ParseIP(ip)
		if ipp == nil {
			continue
		}
		switch ver {
		case 4:
			hmap.byNameV4[fqdn + "."] = append(hmap.byNameV4[fqdn + "."], ipp)
		case 6:
			hmap.byNameV6[fqdn + "."] = append(hmap.byNameV6[fqdn + "."], ipp)
		default:
			continue
		}
		if !h.options.autoReverse {
			continue
		}
		hmap.byAddr[ipp.String()] = append(hmap.byAddr[ipp.String()], fqdn + ".")
	}
	return hmap
}
