package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/spf13/cobra"
)

var (
	ifaceName string
	debug     bool
	timeout   time.Duration
	interval  time.Duration

	// test flags
	testRounds    int
	testDoRequest bool
	testJSON      bool
	testARP       bool
	testServer    string
	minLeaseSec   int
	maxLeaseSec   int
)

func main() {
	root := &cobra.Command{
		Use:   "dhcpdoc",
		Short: "DHCPv4 testing client (discover/getip/test)",
	}
	root.PersistentFlags().StringVarP(&ifaceName, "iface", "i", "", "Network interface (default: first UP non-loopback with MAC)")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "Enable verbose debug output")

	disc := &cobra.Command{
		Use:          "discover",
		Short:        "Continuously discover DHCP servers and print all offers (Ctrl+C to stop)",
		RunE:         runDiscover,
		SilenceUsage: true,
	}
	disc.Flags().DurationVar(&interval, "interval", 5*time.Second, "Interval between discover rounds")
	disc.Flags().DurationVar(&timeout, "listen-timeout", 2*time.Second, "Listen duration per round for offers")

	getip := &cobra.Command{
		Use:          "getip",
		Short:        "Obtain an IP lease; optionally target a server, request an IP, or spoof MAC",
		RunE:         runGetIP,
		SilenceUsage: true,
	}
	getip.Flags().String("server", "", "DHCP server IP to prefer")
	getip.Flags().String("ip", "", "Specific IP to request (Option 50)")
	getip.Flags().String("mac", "", "Spoof client MAC (e.g., 02:00:de:ad:be:ef)")
	getip.Flags().Duration("timeout", 3*time.Second, "Timeout to wait for DHCP offer")

	testCmd := &cobra.Command{
		Use:          "test",
		Short:        "Validate DHCP servers and replies (discover, optional request, multi-round report)",
		RunE:         runTest,
		SilenceUsage: true,
	}
	testCmd.Flags().DurationVar(&timeout, "timeout", 3*time.Second, "Capture window for offers per round")
	testCmd.Flags().IntVar(&testRounds, "rounds", 1, "Number of discover rounds")
	testCmd.Flags().BoolVar(&testDoRequest, "request", false, "After choosing an offer, send REQUEST and validate ACK")
	testCmd.Flags().BoolVar(&testJSON, "json", false, "Emit JSON report")
	testCmd.Flags().BoolVar(&testARP, "arp-verify", false, "Linux-only: ARP probe offered IP(s) before requesting")
	testCmd.Flags().StringVar(&testServer, "server", "", "Prefer/require specific DHCP server in tests")
	testCmd.Flags().IntVar(&minLeaseSec, "min-lease", 0, "Warn if lease time is below this many seconds (0=disabled)")
	testCmd.Flags().IntVar(&maxLeaseSec, "max-lease", 0, "Warn if lease time is above this many seconds (0=disabled)")

	root.AddCommand(disc, getip, testCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// =============================
// discover
// =============================

func runDiscover(cmd *cobra.Command, args []string) error {
	iface, hw, err := pickInterface(ifaceName)
	if err != nil {
		return err
	}
	if debug {
		fmt.Printf("[debug] using iface=%s hw=%s\n", iface.Name, hw.String())
	}

	// Use raw sockets on Linux to bypass firewall
	if runtime.GOOS == "linux" {
		return runDiscoverRaw(iface, hw)
	}

	// Fallback to UDP sockets on other platforms
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}

	conn, err := createDHCPConn(iface)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("Listening for DHCP servers (Ctrl+C to stop)...")
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nstopping discover.")
			return nil
		default:
		}

		xid := randomXID()
		discover, err := dhcpv4.NewDiscovery(hw, dhcpv4.WithBroadcast(true))
		if err != nil {
			if debug {
				fmt.Printf("[debug] build discover: %v\n", err)
			}
			time.Sleep(interval)
			continue
		}
		discover.TransactionID = xid
		discover.UpdateOption(dhcpv4.OptParameterRequestList(
			dhcpv4.OptionSubnetMask,
			dhcpv4.OptionRouter,
			dhcpv4.OptionDomainNameServer,
			dhcpv4.OptionDomainName,
			dhcpv4.OptionServerIdentifier,
			dhcpv4.OptionBroadcastAddress,
		))
		wire := discover.ToBytes()
		if debug {
			fmt.Printf("[debug] sending DHCPDISCOVER xid=0x%08x (%d bytes)\n%s\n", xidToUint32(xid), len(wire), prettyPacket(discover))
		}
		_, _ = conn.WriteToUDP(wire, raddr)

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		roundStart := time.Now()
		for {
			buf := make([]byte, 3000)
			n, src, rerr := conn.ReadFromUDP(buf)
			if rerr != nil {
				break
			}
			pkt, perr := dhcpv4.FromBytes(buf[:n])
			if perr != nil || pkt.MessageType() != dhcpv4.MessageTypeOffer || pkt.TransactionID != xid {
				continue
			}
			server := src.IP
			if sid := pkt.ServerIdentifier(); sid != nil {
				server = sid
			}
			offerIP := pkt.YourIPAddr
			host := pkt.Options.Get(dhcpv4.OptionHostName)
			lat := time.Since(roundStart)

			fmt.Printf("OFFER from %s → yiaddr=%s (latency=%s)", server, offerIP, lat.Round(time.Millisecond))
			if len(host) > 0 {
				fmt.Printf(" host=%q", string(host))
			}
			fmt.Println()
			if debug {
				fmt.Println(prettyPacket(pkt))
			}
		}

		time.Sleep(interval)
	}
}

func runDiscoverRaw(iface *net.Interface, hw net.HardwareAddr) error {
	conn, err := newRawDHCPConn(iface)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("Listening for DHCP servers (Ctrl+C to stop)...")
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nstopping discover.")
			return nil
		default:
		}

		xid := randomXID()
		discover, err := dhcpv4.NewDiscovery(hw, dhcpv4.WithBroadcast(true))
		if err != nil {
			if debug {
				fmt.Printf("[debug] build discover: %v\n", err)
			}
			time.Sleep(interval)
			continue
		}
		discover.TransactionID = xid
		discover.UpdateOption(dhcpv4.OptParameterRequestList(
			dhcpv4.OptionSubnetMask,
			dhcpv4.OptionRouter,
			dhcpv4.OptionDomainNameServer,
			dhcpv4.OptionDomainName,
			dhcpv4.OptionServerIdentifier,
			dhcpv4.OptionBroadcastAddress,
		))
		wire := discover.ToBytes()
		if debug {
			fmt.Printf("[debug] sending DHCPDISCOVER xid=0x%08x (%d bytes)\n%s\n", xidToUint32(xid), len(wire), prettyPacket(discover))
		}

		if err := conn.sendDHCP(wire, hw); err != nil {
			if debug {
				fmt.Printf("[debug] send error: %v\n", err)
			}
			time.Sleep(interval)
			continue
		}

		_ = conn.SetReadTimeout(timeout)
		roundStart := time.Now()
		deadline := time.Now().Add(timeout)

		for time.Now().Before(deadline) {
			dhcpBytes, err := conn.recvDHCP()
			if err != nil {
				continue
			}
			pkt, perr := dhcpv4.FromBytes(dhcpBytes)
			if perr != nil || pkt.MessageType() != dhcpv4.MessageTypeOffer || pkt.TransactionID != xid {
				continue
			}

			server := pkt.ServerIPAddr
			if sid := pkt.ServerIdentifier(); sid != nil {
				server = sid
			}
			offerIP := pkt.YourIPAddr
			host := pkt.Options.Get(dhcpv4.OptionHostName)
			lat := time.Since(roundStart)

			fmt.Printf("OFFER from %s → yiaddr=%s (latency=%s)", server, offerIP, lat.Round(time.Millisecond))
			if len(host) > 0 {
				fmt.Printf(" host=%q", string(host))
			}
			fmt.Println()
			if debug {
				fmt.Println(prettyPacket(pkt))
			}
		}

		time.Sleep(interval)
	}
}

// =============================
// getip
// =============================

func runGetIP(cmd *cobra.Command, args []string) error {
	iface, hw, err := pickInterface(ifaceName)
	if err != nil {
		return err
	}

	flagServer, _ := cmd.Flags().GetString("server")
	flagIP, _ := cmd.Flags().GetString("ip")
	flagMAC, _ := cmd.Flags().GetString("mac")
	flagTimeout, _ := cmd.Flags().GetDuration("timeout")

	if flagMAC != "" {
		m, err := net.ParseMAC(flagMAC)
		if err != nil {
			return fmt.Errorf("invalid --mac: %w", err)
		}
		hw = m
	}

	var requestedIP net.IP
	if flagIP != "" {
		requestedIP = net.ParseIP(flagIP)
		if requestedIP == nil || requestedIP.To4() == nil {
			return errors.New("invalid --ip (must be IPv4)")
		}
	}

	var targetServer net.IP
	if flagServer != "" {
		targetServer = net.ParseIP(flagServer)
		if targetServer == nil || targetServer.To4() == nil {
			return errors.New("invalid --server (must be IPv4)")
		}
	}

	// Use raw sockets on Linux to bypass firewall
	if runtime.GOOS == "linux" {
		return runGetIPRaw(iface, hw, requestedIP, targetServer, flagTimeout)
	}

	// Fallback to UDP sockets on other platforms
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	conn, err := createDHCPConn(iface)
	if err != nil {
		return err
	}
	defer conn.Close()

	offer, server, _, err := doDiscoverOnce(conn, hw, requestedIP, targetServer, flagTimeout)
	if err != nil {
		return err
	}
	if debug {
		fmt.Printf("[debug] selected OFFER yiaddr=%s from %s\n", offer.YourIPAddr, server)
		fmt.Println(prettyPacket(offer))
	}

	if requestedIP != nil {
		offer.UpdateOption(dhcpv4.OptRequestedIPAddress(requestedIP))
	}

	req, err := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.ClientHWAddr = hw

	if _, err := conn.WriteToUDP(req.ToBytes(), raddr); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		buf := make([]byte, 3000)
		n, _, rerr := conn.ReadFromUDP(buf)
		if rerr != nil {
			return errors.New("no DHCPACK/NAK received")
		}
		pkt, perr := dhcpv4.FromBytes(buf[:n])
		if perr != nil || pkt.TransactionID != req.TransactionID {
			continue
		}
		switch pkt.MessageType() {
		case dhcpv4.MessageTypeAck:
			fmt.Printf("ACK: leased %s\n", pkt.YourIPAddr)
			if debug {
				fmt.Println(prettyPacket(pkt))
			}
			return nil
		case dhcpv4.MessageTypeNak:
			return errors.New("NAK: server declined the request")
		}
	}
}

func runGetIPRaw(iface *net.Interface, hw net.HardwareAddr, requestedIP, targetServer net.IP, timeout time.Duration) error {
	conn, err := newRawDHCPConn(iface)
	if err != nil {
		return err
	}
	defer conn.Close()

	if debug {
		fmt.Printf("[debug] using raw sockets on iface=%s hw=%s\n", iface.Name, hw)
	}

	offer, server, _, err := doDiscoverOnceRaw(conn, hw, requestedIP, targetServer, timeout)
	if err != nil {
		return err
	}
	if debug {
		fmt.Printf("[debug] selected OFFER yiaddr=%s from %s\n", offer.YourIPAddr, server)
		fmt.Println(prettyPacket(offer))
	}

	_, ack, err := doRequestOnceRaw(conn, hw, offer)
	if err != nil {
		return err
	}

	fmt.Printf("ACK: leased %s\n", ack.YourIPAddr)
	if debug {
		fmt.Println(prettyPacket(ack))
	}
	return nil
}

// =============================
// test (validator)
// =============================

type Check struct {
	Name  string `json:"name"`
	Level string `json:"level"` // OK|WARN|ERR
	Msg   string `json:"msg"`
}

type PerServerRound struct {
	Server     string   `json:"server"`
	OfferIP    string   `json:"offer_ip"`
	LatencyMS  int64    `json:"latency_ms"`
	Checks     []Check  `json:"checks"`
	PRLMissing []int    `json:"prl_missing,omitempty"`
	NBNS       []string `json:"nbns,omitempty"`
	Routes121  []string `json:"routes_121,omitempty"`
	Routes249  []string `json:"routes_249,omitempty"`
	WPAD       string   `json:"wpad,omitempty"`
	Domain119  []string `json:"domain_search,omitempty"`
}

type PerServerAggregate struct {
	Server          string   `json:"server"`
	OfferIPs        []string `json:"offer_ips"`
	Subnets         []string `json:"subnets"`
	OfferCount      int      `json:"offer_count"`
	AvgLatencyMS    int64    `json:"avg_latency_ms"`
	MinLatencyMS    int64    `json:"min_latency_ms"`
	MaxLatencyMS    int64    `json:"max_latency_ms"`
	UnstableSubnets bool     `json:"unstable_subnets"`
	UnstableIP      bool     `json:"unstable_ip"`
}

type TestReport struct {
	Interface string               `json:"interface"`
	Rounds    int                  `json:"rounds"`
	Results   []PerServerRound     `json:"results"`
	Summary   []PerServerAggregate `json:"summary"`
	Errors    int                  `json:"errors"`
	Warnings  int                  `json:"warnings"`
}

func runTest(cmd *cobra.Command, args []string) error {
	ifi, hw, err := pickInterface(ifaceName)
	if err != nil {
		return err
	}

	// Use raw sockets on Linux to bypass firewall
	if runtime.GOOS == "linux" {
		return runTestRaw(ifi, hw)
	}

	conn, err := createDHCPConn(ifi)
	if err != nil {
		return err
	}
	defer conn.Close()

	var targetServer net.IP
	if testServer != "" {
		targetServer = net.ParseIP(testServer)
		if targetServer == nil || targetServer.To4() == nil {
			return fmt.Errorf("invalid --server: %q", testServer)
		}
	}

	report := TestReport{Interface: ifi.Name, Rounds: testRounds}
	agg := map[string]*PerServerAggregate{}

	for round := 0; round < testRounds; round++ {
		offer, server, latency, err := doDiscoverOnce(conn, hw, nil, targetServer, timeout)
		if err != nil {
			continue
		}

		roundRes := validateOffer(offer, server, latency)

		// Optional ARP probe
		if testARP {
			if err := arpProbe(ifi, hw, offer.YourIPAddr); err != nil {
				roundRes.Checks = append(roundRes.Checks, Check{"arp_probe", "WARN", fmt.Sprintf("probe issue: %v", err)})
			} else {
				roundRes.Checks = append(roundRes.Checks, Check{"arp_probe", "OK", "no ARP reply (free)"})
			}
		}

		// Optional REQUEST/ACK
		if testDoRequest {
			startReq := time.Now()
			req, ack, err := doRequestOnce(conn, hw, offer)
			if err != nil {
				roundRes.Checks = append(roundRes.Checks, Check{"request_ack", "ERR", err.Error()})
			} else {
				ackLat := time.Since(startReq)
				roundRes.Checks = append(roundRes.Checks, Check{"request_ack", "OK", "ACK received"})
				roundRes.Checks = append(roundRes.Checks, Check{"ack_latency", "OK", ackLat.Round(time.Millisecond).String()})
				validateACK(offer, req, ack, &roundRes)
			}
		}

		report.Results = append(report.Results, roundRes)

		// Aggregate stats
		skey := server.String()
		if agg[skey] == nil {
			agg[skey] = &PerServerAggregate{Server: skey, MinLatencyMS: 1 << 62}
		}
		a := agg[skey]
		a.OfferCount++
		a.OfferIPs = appendUnique(a.OfferIPs, offer.YourIPAddr.String())
		subnet := inferSubnet(offer)
		a.Subnets = appendUnique(a.Subnets, subnet)
		ms := latency.Milliseconds()
		a.AvgLatencyMS += ms
		if ms < a.MinLatencyMS {
			a.MinLatencyMS = ms
		}
		if ms > a.MaxLatencyMS {
			a.MaxLatencyMS = ms
		}
	}

	// Finalize aggregates
	for _, a := range agg {
		if a.OfferCount > 0 {
			a.AvgLatencyMS = a.AvgLatencyMS / int64(a.OfferCount)
			a.UnstableSubnets = len(a.Subnets) > 1
			a.UnstableIP = len(a.OfferIPs) > 1
			report.Summary = append(report.Summary, *a)
		}
	}

	// Count severities
	for _, r := range report.Results {
		for _, c := range r.Checks {
			switch c.Level {
			case "ERR":
				report.Errors++
			case "WARN":
				report.Warnings++
			}
		}
	}

	if testJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Human-friendly output
	fmt.Printf("== DHCP Server Test Report (iface=%s, rounds=%d) ==\n", report.Interface, report.Rounds)
	for _, r := range report.Results {
		fmt.Printf("\nServer: %s  Offer: %s  Latency=%dms\n", r.Server, r.OfferIP, r.LatencyMS)
		for _, c := range r.Checks {
			fmt.Printf("  [%s] %-16s %s\n", c.Level, c.Name, c.Msg)
		}
	}
	if len(report.Summary) > 0 {
		fmt.Println("\n-- Summary --")
		for _, s := range report.Summary {
			fmt.Printf("Server %s: offers=%d, lat(ms) min/avg/max=%d/%d/%d, subnets=%v, ips=%v",
				s.Server, s.OfferCount, s.MinLatencyMS, s.AvgLatencyMS, s.MaxLatencyMS, s.Subnets, s.OfferIPs)
			if s.UnstableSubnets {
				fmt.Printf("  [WARN subnet instability]")
			}
			if s.UnstableIP {
				fmt.Printf("  [WARN IP churn]")
			}
			fmt.Println()
		}
	}
	if report.Errors > 0 {
		return fmt.Errorf("test found %d error(s), %d warning(s)", report.Errors, report.Warnings)
	}
	if report.Warnings > 0 {
		fmt.Printf("Completed with %d warning(s)\n", report.Warnings)
	}
	return nil
}

func runTestRaw(ifi *net.Interface, hw net.HardwareAddr) error {
	conn, err := newRawDHCPConn(ifi)
	if err != nil {
		return err
	}
	defer conn.Close()

	var targetServer net.IP
	if testServer != "" {
		targetServer = net.ParseIP(testServer)
		if targetServer == nil || targetServer.To4() == nil {
			return fmt.Errorf("invalid --server: %q", testServer)
		}
	}

	report := TestReport{Interface: ifi.Name, Rounds: testRounds}
	agg := map[string]*PerServerAggregate{}

	for round := 0; round < testRounds; round++ {
		offer, server, latency, err := doDiscoverOnceRaw(conn, hw, nil, targetServer, timeout)
		if err != nil {
			continue
		}

		roundRes := validateOffer(offer, server, latency)

		// Optional ARP probe
		if testARP {
			if err := arpProbe(ifi, hw, offer.YourIPAddr); err != nil {
				roundRes.Checks = append(roundRes.Checks, Check{"arp_probe", "WARN", fmt.Sprintf("probe issue: %v", err)})
			} else {
				roundRes.Checks = append(roundRes.Checks, Check{"arp_probe", "OK", "no ARP reply (free)"})
			}
		}

		// Optional REQUEST/ACK
		if testDoRequest {
			startReq := time.Now()
			req, ack, err := doRequestOnceRaw(conn, hw, offer)
			if err != nil {
				roundRes.Checks = append(roundRes.Checks, Check{"request_ack", "ERR", err.Error()})
			} else {
				ackLat := time.Since(startReq)
				roundRes.Checks = append(roundRes.Checks, Check{"request_ack", "OK", "ACK received"})
				roundRes.Checks = append(roundRes.Checks, Check{"ack_latency", "OK", ackLat.Round(time.Millisecond).String()})
				validateACK(offer, req, ack, &roundRes)
			}
		}

		report.Results = append(report.Results, roundRes)

		// Aggregate stats
		skey := server.String()
		if agg[skey] == nil {
			agg[skey] = &PerServerAggregate{Server: skey, MinLatencyMS: 1 << 62}
		}
		a := agg[skey]
		a.OfferCount++
		a.OfferIPs = appendUnique(a.OfferIPs, offer.YourIPAddr.String())
		subnet := inferSubnet(offer)
		a.Subnets = appendUnique(a.Subnets, subnet)
		ms := latency.Milliseconds()
		a.AvgLatencyMS += ms
		if ms < a.MinLatencyMS {
			a.MinLatencyMS = ms
		}
		if ms > a.MaxLatencyMS {
			a.MaxLatencyMS = ms
		}
	}

	// Finalize aggregates
	for _, a := range agg {
		if a.OfferCount > 0 {
			a.AvgLatencyMS = a.AvgLatencyMS / int64(a.OfferCount)
			a.UnstableSubnets = len(a.Subnets) > 1
			a.UnstableIP = len(a.OfferIPs) > 1
			report.Summary = append(report.Summary, *a)
		}
	}

	// Count severities
	for _, r := range report.Results {
		for _, c := range r.Checks {
			switch c.Level {
			case "ERR":
				report.Errors++
			case "WARN":
				report.Warnings++
			}
		}
	}

	if testJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Human-friendly output
	fmt.Printf("== DHCP Server Test Report (iface=%s, rounds=%d) ==\n", report.Interface, report.Rounds)
	for _, r := range report.Results {
		fmt.Printf("\nServer: %s  Offer: %s  Latency=%dms\n", r.Server, r.OfferIP, r.LatencyMS)
		for _, c := range r.Checks {
			fmt.Printf("  [%s] %-16s %s\n", c.Level, c.Name, c.Msg)
		}
	}
	if len(report.Summary) > 0 {
		fmt.Println("\n-- Summary --")
		for _, s := range report.Summary {
			fmt.Printf("Server %s: offers=%d, lat(ms) min/avg/max=%d/%d/%d, subnets=%v, ips=%v",
				s.Server, s.OfferCount, s.MinLatencyMS, s.AvgLatencyMS, s.MaxLatencyMS, s.Subnets, s.OfferIPs)
			if s.UnstableSubnets {
				fmt.Printf("  [WARN subnet instability]")
			}
			if s.UnstableIP {
				fmt.Printf("  [WARN IP churn]")
			}
			fmt.Println()
		}
	}
	if report.Errors > 0 {
		return fmt.Errorf("test found %d error(s), %d warning(s)", report.Errors, report.Warnings)
	}
	if report.Warnings > 0 {
		fmt.Printf("Completed with %d warning(s)\n", report.Warnings)
	}
	return nil
}

// ----- test helpers -----

func doDiscoverOnce(conn *net.UDPConn, hw net.HardwareAddr, requestedIP net.IP, targetServer net.IP, listen time.Duration) (*dhcpv4.DHCPv4, net.IP, time.Duration, error) {
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	xid := randomXID()
	discover, err := dhcpv4.NewDiscovery(hw, dhcpv4.WithBroadcast(true))
	if err != nil {
		return nil, nil, 0, err
	}
	discover.TransactionID = xid
	if requestedIP != nil {
		discover.UpdateOption(dhcpv4.OptRequestedIPAddress(requestedIP))
	}
	discover.UpdateOption(dhcpv4.OptParameterRequestList(
		dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter, dhcpv4.OptionDomainNameServer,
		dhcpv4.OptionDomainName, dhcpv4.OptionServerIdentifier, dhcpv4.OptionBroadcastAddress,
	))
	start := time.Now()
	if debug {
		fmt.Printf("[debug] doDiscoverOnce: sending DHCPDISCOVER xid=0x%08x hw=%s\n", xidToUint32(xid), hw)
	}
	if _, err := conn.WriteToUDP(discover.ToBytes(), raddr); err != nil {
		return nil, nil, 0, fmt.Errorf("send discover: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(listen))
	var chosen *dhcpv4.DHCPv4
	var server net.IP
	for {
		buf := make([]byte, 3000)
		n, src, rerr := conn.ReadFromUDP(buf)
		if rerr != nil {
			if debug {
				fmt.Printf("[debug] doDiscoverOnce: read error (timeout?): %v\n", rerr)
			}
			break
		}
		if debug {
			fmt.Printf("[debug] doDiscoverOnce: received %d bytes from %s\n", n, src)
		}
		pkt, perr := dhcpv4.FromBytes(buf[:n])
		if perr != nil {
			if debug {
				fmt.Printf("[debug] doDiscoverOnce: parse error: %v\n", perr)
			}
			continue
		}
		if debug {
			fmt.Printf("[debug] doDiscoverOnce: parsed packet type=%s xid=0x%08x (want 0x%08x)\n", pkt.MessageType(), xidToUint32(pkt.TransactionID), xidToUint32(xid))
		}
		if pkt.TransactionID != xid || pkt.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}
		sid := pkt.ServerIdentifier()
		server = src.IP
		if sid != nil {
			server = sid
		}
		if targetServer != nil && !server.Equal(targetServer) {
			continue
		}
		chosen = pkt
		break
	}
	if chosen == nil {
		return nil, nil, 0, errors.New("no suitable DHCPOFFER received")
	}
	return chosen, server, time.Since(start), nil
}

func doRequestOnce(conn *net.UDPConn, hw net.HardwareAddr, offer *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4, error) {
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	req, err := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	req.ClientHWAddr = hw
	if _, err := conn.WriteToUDP(req.ToBytes(), raddr); err != nil {
		return nil, nil, fmt.Errorf("send request: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		buf := make([]byte, 3000)
		n, _, rerr := conn.ReadFromUDP(buf)
		if rerr != nil {
			return req, nil, errors.New("no DHCPACK/NAK received")
		}
		pkt, perr := dhcpv4.FromBytes(buf[:n])
		if perr != nil || pkt.TransactionID != req.TransactionID {
			continue
		}
		switch pkt.MessageType() {
		case dhcpv4.MessageTypeAck:
			return req, pkt, nil
		case dhcpv4.MessageTypeNak:
			return req, nil, errors.New("NAK: server declined the request")
		}
	}
}

func validateOffer(pkt *dhcpv4.DHCPv4, server net.IP, latency time.Duration) PerServerRound {
	res := PerServerRound{
		Server:    server.String(),
		OfferIP:   pkt.YourIPAddr.String(),
		LatencyMS: latency.Milliseconds(),
	}

	raw := rawOptions(pkt)
	get := func(code byte) []byte {
		if vv := raw[code]; len(vv) > 0 {
			return vv[0]
		}
		return nil
	}
	add := func(name, level, msg string) { res.Checks = append(res.Checks, Check{name, level, msg}) }

	// Core
	if pkt.ServerIdentifier() == nil {
		add("server_id", "ERR", "missing Option 54")
	} else {
		add("server_id", "OK", "present")
	}
	lease := pkt.IPAddressLeaseTime(0)
	if lease <= 0 {
		add("lease", "ERR", "missing/zero lease time (51)")
	} else {
		add("lease", "OK", lease.String())
		if minLeaseSec > 0 && int(lease/time.Second) < minLeaseSec {
			add("lease_policy", "WARN", fmt.Sprintf("below policy (%ds)", minLeaseSec))
		}
		if maxLeaseSec > 0 && int(lease/time.Second) > maxLeaseSec {
			add("lease_policy", "WARN", fmt.Sprintf("above policy (%ds)", maxLeaseSec))
		}
	}

	if v := get(44); len(v) >= 4 {
		nbns := ipsToStrings(decodeIPList(v))
		res.NBNS = nbns
		add("nbns", "OK", strings.Join(nbns, " "))
	}

	// T1/T2
	if v := get(58); len(v) == 4 {
		t1 := time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		add("t1", "OK", t1.String())
		if lease > 0 {
			r := float64(t1) / float64(lease)
			if r < 0.4 || r > 0.6 {
				add("t1_ratio", "WARN", fmt.Sprintf("%.0f%% of lease", r*100))
			}
		}
	} else {
		add("t1", "WARN", "missing 58")
	}
	if v := get(59); len(v) == 4 {
		t2 := time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		add("t2", "OK", t2.String())
		if lease > 0 {
			r := float64(t2) / float64(lease)
			if r < 0.8 || r > 0.95 {
				add("t2_ratio", "WARN", fmt.Sprintf("%.0f%% of lease", r*100))
			}
		}
	} else {
		add("t2", "WARN", "missing 59")
	}

	// Network basics
	maskOpt := pkt.Options.Get(dhcpv4.OptionSubnetMask)
	if len(maskOpt) != 4 {
		add("subnet_mask", "ERR", "missing (1)")
	} else {
		add("subnet_mask", "OK", fmt.Sprintf("%d.%d.%d.%d", maskOpt[0], maskOpt[1], maskOpt[2], maskOpt[3]))
	}
	routers := pkt.Router()
	if len(routers) == 0 {
		add("router", "ERR", "missing (3)")
	} else {
		add("router", "OK", fmt.Sprintf("%v", ipsToStrings(routers)))
	}
	dns := pkt.DNS()
	if len(dns) == 0 {
		add("dns", "WARN", "missing (6)")
	} else {
		add("dns", "OK", fmt.Sprintf("%v", ipsToStrings(dns)))
	}

	// PRL echo (55): check that commonly requested options are present
	prlExpected := []int{1, 3, 6, 15, 54, 28, 121}
	if v := get(55); len(v) > 0 {
		missing := prlMissing(v, raw, prlExpected)
		if len(missing) > 0 {
			res.PRLMissing = missing
			add("prl_echo", "WARN", fmt.Sprintf("omitted requested options: %v", missing))
		} else {
			add("prl_echo", "OK", "server supplied requested options")
		}
	}

	// MTU (26)
	if v := pkt.Options.Get(dhcpv4.OptionInterfaceMTU); len(v) == 2 {
		mtu := binary.BigEndian.Uint16(v)
		if mtu < 576 || mtu > 9216 {
			add("mtu", "WARN", fmt.Sprintf("unusual %d", mtu))
		} else {
			add("mtu", "OK", fmt.Sprintf("%d", mtu))
		}
	}

	// Classless routes 121/249
	if v := get(121); len(v) > 0 {
		res.Routes121 = decodeCSR(v)
		add("routes_121", "OK", strings.Join(res.Routes121, " | "))
	}
	if v := get(249); len(v) > 0 {
		res.Routes249 = decodeCSR(v)
		add("routes_249", "OK", strings.Join(res.Routes249, " | "))
	}
	if len(res.Routes121) > 0 && len(res.Routes249) > 0 && strings.Join(res.Routes121, ",") != strings.Join(res.Routes249, ",") {
		add("routes_consistency", "WARN", "121 and 249 differ")
	}

	// WPAD (252)
	if v := get(252); len(v) > 0 {
		s := string(v)
		res.WPAD = s
		if u, e := url.Parse(s); e == nil && (u.Scheme == "http" || u.Scheme == "https") {
			add("wpad", "OK", s)
		} else {
			add("wpad", "WARN", fmt.Sprintf("malformed %q", s))
		}
	}

	// Domain Search (119)
	if v := get(119); len(v) > 0 {
		domains, err := decodeDomainSearch(v)
		if err != nil {
			add("domain_search", "WARN", fmt.Sprintf("malformed: %v", err))
		} else {
			res.Domain119 = domains
			add("domain_search", "OK", strings.Join(domains, ", "))
		}
	}

	// Same-subnet sanity
	if len(maskOpt) == 4 && len(routers) > 0 && pkt.YourIPAddr.To4() != nil {
		mask := net.IPv4Mask(maskOpt[0], maskOpt[1], maskOpt[2], maskOpt[3])
		if !pkt.YourIPAddr.Mask(mask).Equal(routers[0].Mask(mask)) {
			add("router_subnet", "WARN", fmt.Sprintf("router %s not in client subnet", routers[0]))
		}
	}

	return res
}

func validateACK(offer, req, ack *dhcpv4.DHCPv4, res *PerServerRound) {
	add := func(name, level, msg string) { res.Checks = append(res.Checks, Check{name, level, msg}) }

	if ack.MessageType() != dhcpv4.MessageTypeAck {
		add("ack_type", "ERR", "not an ACK")
		return
	}
	// Server ID present
	if ack.ServerIdentifier() == nil {
		add("ack_server_id", "ERR", "missing Option 54")
	} else {
		add("ack_server_id", "OK", "present")
	}
	// yiaddr matches OFFER
	if !ack.YourIPAddr.Equal(offer.YourIPAddr) {
		add("ack_yiaddr", "WARN", fmt.Sprintf("ACK yiaddr %s differs from OFFER %s", ack.YourIPAddr, offer.YourIPAddr))
	} else {
		add("ack_yiaddr", "OK", ack.YourIPAddr.String())
	}
	// DNS/router/mask presence
	if len(ack.DNS()) == 0 {
		add("ack_dns", "WARN", "no DNS (6)")
	} else {
		add("ack_dns", "OK", fmt.Sprintf("%v", ipsToStrings(ack.DNS())))
	}
	if len(ack.Router()) == 0 {
		add("ack_router", "ERR", "no router (3)")
	} else {
		add("ack_router", "OK", fmt.Sprintf("%v", ipsToStrings(ack.Router())))
	}
	if v := ack.Options.Get(dhcpv4.OptionSubnetMask); len(v) != 4 {
		add("ack_subnet_mask", "ERR", "missing (1)")
	} else {
		add("ack_subnet_mask", "OK", fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3]))
	}
	// Lease/T1/T2 again
	lease := ack.IPAddressLeaseTime(0)
	if lease <= 0 {
		add("ack_lease", "ERR", "missing/zero (51)")
	} else {
		add("ack_lease", "OK", lease.String())
	}
	raw := rawOptions(ack)
	if v := first(raw[58]); len(v) == 4 {
		t1 := time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		add("ack_t1", "OK", t1.String())
	}
	if v := first(raw[59]); len(v) == 4 {
		t2 := time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		add("ack_t2", "OK", t2.String())
	}
}

// =============================
// shared helpers
// =============================

func pickInterface(name string) (*net.Interface, net.HardwareAddr, error) {
	if name != "" {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil, nil, fmt.Errorf("interface %s: %w", name, err)
		}
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 || len(ifi.HardwareAddr) == 0 {
			return nil, nil, fmt.Errorf("interface %s is down/loopback or has no MAC", name)
		}
		return ifi, ifi.HardwareAddr, nil
	}
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, ifi := range ifis {
		if (ifi.Flags&net.FlagUp) != 0 && (ifi.Flags&net.FlagLoopback) == 0 && len(ifi.HardwareAddr) > 0 {
			return &ifi, ifi.HardwareAddr, nil
		}
	}
	return nil, nil, errors.New("no suitable interface found; specify with --iface")
}

func prettyPacket(p *dhcpv4.DHCPv4) string {
	var b strings.Builder
	b.WriteString(p.Summary())

	// MTU (26)
	if v := p.Options.Get(dhcpv4.OptionInterfaceMTU); len(v) == 2 {
		mtu := binary.BigEndian.Uint16(v)
		b.WriteString(fmt.Sprintf("\n  MTU=%d", mtu))
	}

	// Raw tricky options via TLV
	raw := rawOptions(p)
	get := func(code byte) []byte {
		if vv := raw[code]; len(vv) > 0 {
			return vv[0]
		}
		return nil
	}
	if v := get(44); len(v) >= 4 {
		b.WriteString(fmt.Sprintf("\n  NBNS=%s", strings.Join(ipsToStrings(decodeIPList(v)), ", ")))
	}
	if v := get(121); len(v) > 0 {
		b.WriteString(fmt.Sprintf("\n  Routes(121)=%s", strings.Join(decodeCSR(v), " | ")))
	}
	if v := get(249); len(v) > 0 {
		b.WriteString(fmt.Sprintf("\n  Routes(249)=%s", strings.Join(decodeCSR(v), " | ")))
	}
	if v := get(252); len(v) > 0 {
		b.WriteString(fmt.Sprintf("\n  WPAD=%s", string(v)))
	}
	if v := get(119); len(v) > 0 {
		if ds, err := decodeDomainSearch(v); err == nil {
			b.WriteString(fmt.Sprintf("\n  DomainSearch=%s", strings.Join(ds, ", ")))
		}
	}
	if v := get(58); len(v) == 4 {
		t1 := time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		b.WriteString(fmt.Sprintf("\n  T1=%s", t1))
	}
	if v := get(59); len(v) == 4 {
		t2 := time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		b.WriteString(fmt.Sprintf("\n  T2=%s", t2))
	}

	b.WriteString("\n---- RAW HEX ----\n")
	b.WriteString(hex.Dump(p.ToBytes()))
	b.WriteString("-----------------\n")
	return b.String()
}

func decodeIPList(b []byte) []net.IP {
	out := []net.IP{}
	for i := 0; i+3 < len(b); i += 4 {
		out = append(out, net.IPv4(b[i], b[i+1], b[i+2], b[i+3]))
	}
	return out
}

// RFC 3442 / MSFT 249 decoder
func decodeCSR(b []byte) []string {
	routes := []string{}
	i := 0
	for i < len(b) {
		pfxLen := int(b[i])
		i++
		if pfxLen > 32 {
			break
		}
		octets := (pfxLen + 7) / 8
		if i+octets+4 > len(b) {
			break
		}
		dst := make([]byte, 4)
		copy(dst, b[i:i+octets])
		i += octets
		gw := net.IPv4(b[i], b[i+1], b[i+2], b[i+3])
		i += 4
		mask := net.CIDRMask(pfxLen, 32)
		network := net.IP(maskIP(dst, mask))
		routes = append(routes, fmt.Sprintf("%s/%d via %s", network.String(), pfxLen, gw))
	}
	return routes
}

func maskIP(ip []byte, mask net.IPMask) []byte {
	out := make([]byte, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip[i] & mask[i]
	}
	return out
}

func ipsToStrings(v []net.IP) []string {
	out := make([]string, 0, len(v))
	for _, ip := range v {
		out = append(out, ip.String())
	}
	return out
}

// RFC 3397 Domain Search decode
func decodeDomainSearch(b []byte) ([]string, error) {
	var out []string
	for i := 0; i < len(b); {
		var labels []string
		for {
			if i >= len(b) {
				return nil, errors.New("truncated domain search")
			}
			l := int(b[i])
			i++
			if l == 0 {
				break
			}
			if i+l > len(b) {
				return nil, errors.New("bad label length")
			}
			labels = append(labels, string(b[i:i+l]))
			i += l
		}
		out = append(out, strings.Join(labels, "."))
	}
	return out, nil
}

// raw TLV options extracted from packet bytes; keeps duplicates (map[code][]value)
func rawOptions(p *dhcpv4.DHCPv4) map[byte][][]byte {
	res := make(map[byte][][]byte)
	raw := p.ToBytes()
	magic := []byte{0x63, 0x82, 0x53, 0x63}
	start := -1
	for i := 0; i+len(magic) <= len(raw); i++ {
		if raw[i] == magic[0] && raw[i+1] == magic[1] && raw[i+2] == magic[2] && raw[i+3] == magic[3] {
			start = i + 4
			break
		}
	}
	if start < 0 {
		return res
	}
	i := start
	for i < len(raw) {
		code := raw[i]
		i++
		if code == 255 {
			break
		}
		if code == 0 {
			continue
		}
		if i >= len(raw) {
			break
		}
		l := int(raw[i])
		i++
		if i+l > len(raw) || l < 0 {
			break
		}
		val := make([]byte, l)
		copy(val, raw[i:i+l])
		i += l
		res[code] = append(res[code], val)
	}
	return res
}

func prlMissing(prl []byte, opt map[byte][][]byte, expected []int) []int {
	m := map[int]bool{}
	for _, e := range prl {
		m[int(e)] = true
	}
	var missing []int
	for _, code := range expected {
		if !m[code] {
			continue // client didn't request it, don't demand it
		}
		if _, ok := opt[byte(code)]; !ok {
			missing = append(missing, code)
		}
	}
	return missing
}

func inferSubnet(p *dhcpv4.DHCPv4) string {
	m := p.Options.Get(dhcpv4.OptionSubnetMask)
	if len(m) != 4 || p.YourIPAddr.To4() == nil {
		return "unknown"
	}
	mask := net.IPv4Mask(m[0], m[1], m[2], m[3])
	return fmt.Sprintf("%s/%d", p.YourIPAddr.Mask(mask), maskOnes(mask))
}

func maskOnes(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func first(m [][]byte) []byte {
	if len(m) > 0 {
		return m[0]
	}
	return nil
}

func randomXID() dhcpv4.TransactionID {
	var xid dhcpv4.TransactionID
	u := rand.Uint32()
	xid[0] = byte(u >> 24)
	xid[1] = byte(u >> 16)
	xid[2] = byte(u >> 8)
	xid[3] = byte(u)
	return xid
}

func xidToUint32(xid dhcpv4.TransactionID) uint32 {
	return uint32(xid[0])<<24 | uint32(xid[1])<<16 | uint32(xid[2])<<8 | uint32(xid[3])
}

// ----- ARP probe (Linux only; best-effort) -----
func arpProbe(ifi *net.Interface, srcMAC net.HardwareAddr, targetIP net.IP) error {
	if runtime.GOOS != "linux" {
		return errors.New("ARP verify supported on Linux only")
	}
	if targetIP == nil || targetIP.To4() == nil {
		return errors.New("target IP invalid")
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0806))) // ARP
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(0x0806),
		Ifindex:  ifi.Index,
		Halen:    uint8(len(srcMAC)),
	}
	copy(addr.Addr[:], srcMAC)

	// Ethernet header
	eth := make([]byte, 14)
	for i := 0; i < 6; i++ {
		eth[i] = 0xff // broadcast
	}
	copy(eth[6:12], srcMAC)
	eth[12] = 0x08
	eth[13] = 0x06

	// ARP request (who-has targetIP, sender IP 0.0.0.0)
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)      // HTYPE Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // PTYPE IPv4
	arp[4] = 6                                   // HLEN
	arp[5] = 4                                   // PLEN
	binary.BigEndian.PutUint16(arp[6:8], 1)      // OPER request
	copy(arp[8:14], srcMAC)                      // SHA
	copy(arp[14:18], []byte{0, 0, 0, 0})         // SPA 0.0.0.0
	copy(arp[18:24], []byte{0, 0, 0, 0, 0, 0})   // THA
	copy(arp[24:28], targetIP.To4())             // TPA
	frame := append(eth, arp...)

	// Send probes and listen briefly for replies
	for i := 0; i < 3; i++ {
		if err := syscall.Sendto(fd, frame, 0, &addr); err != nil {
			return fmt.Errorf("arp send: %w", err)
		}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 0, Usec: 200000})

		buf := make([]byte, 1500)
		n, _, e := syscall.Recvfrom(fd, buf, 0)
		if e == nil && n >= 42 && buf[12] == 0x08 && buf[13] == 0x06 {
			// ARP packet; OP at [20:22] in Ethernet+ARP frame
			if binary.BigEndian.Uint16(buf[20:22]) == 2 { // reply
				// TPA is at Ethernet(14)+ARP(24:28)= [38:42)
				tpa := net.IPv4(buf[38], buf[39], buf[40], buf[41])
				if tpa.Equal(targetIP) {
					return fmt.Errorf("duplicate IP detected: %s responds", targetIP)
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// =============================
// Raw socket DHCP (bypasses firewall)
// =============================

// rawDHCPConn holds state for raw socket DHCP communication
type rawDHCPConn struct {
	fd    int
	iface *net.Interface
	mac   net.HardwareAddr
}

// newRawDHCPConn creates a raw AF_PACKET socket for DHCP
func newRawDHCPConn(iface *net.Interface) (*rawDHCPConn, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("raw DHCP sockets only supported on Linux")
	}

	// ETH_P_IP = 0x0800
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0800)))
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}

	// Bind to interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(0x0800),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind to interface: %w", err)
	}

	return &rawDHCPConn{
		fd:    fd,
		iface: iface,
		mac:   iface.HardwareAddr,
	}, nil
}

func (r *rawDHCPConn) Close() error {
	return syscall.Close(r.fd)
}

func (r *rawDHCPConn) SetReadTimeout(d time.Duration) error {
	tv := syscall.Timeval{
		Sec:  int64(d / time.Second),
		Usec: int64((d % time.Second) / time.Microsecond),
	}
	return syscall.SetsockoptTimeval(r.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

// sendDHCP sends a DHCP packet via raw socket
func (r *rawDHCPConn) sendDHCP(dhcpPayload []byte, srcMAC net.HardwareAddr) error {
	// Build: Ethernet + IP + UDP + DHCP
	frame := buildDHCPFrame(srcMAC, dhcpPayload)

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(0x0800),
		Ifindex:  r.iface.Index,
		Halen:    6,
	}
	// Broadcast destination
	copy(addr.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	return syscall.Sendto(r.fd, frame, 0, &addr)
}

// recvDHCP receives a DHCP packet via raw socket
func (r *rawDHCPConn) recvDHCP() ([]byte, error) {
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(r.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	if n < 14+20+8 { // Eth + IP + UDP minimum
		return nil, errors.New("packet too short")
	}

	// Parse Ethernet header
	etherType := binary.BigEndian.Uint16(buf[12:14])
	if etherType != 0x0800 {
		return nil, errors.New("not IP packet")
	}

	// Parse IP header
	ipStart := 14
	if buf[ipStart]>>4 != 4 {
		return nil, errors.New("not IPv4")
	}
	ipHdrLen := int(buf[ipStart]&0x0f) * 4
	protocol := buf[ipStart+9]
	if protocol != 17 { // UDP
		return nil, errors.New("not UDP")
	}

	// Parse UDP header
	udpStart := ipStart + ipHdrLen
	if udpStart+8 > n {
		return nil, errors.New("UDP header truncated")
	}
	srcPort := binary.BigEndian.Uint16(buf[udpStart : udpStart+2])
	dstPort := binary.BigEndian.Uint16(buf[udpStart+2 : udpStart+4])

	// DHCP: server sends from port 67, client receives on port 68
	if srcPort != 67 || dstPort != 68 {
		return nil, errors.New("not DHCP")
	}

	// Extract DHCP payload
	dhcpStart := udpStart + 8
	if dhcpStart >= n {
		return nil, errors.New("no DHCP payload")
	}

	return buf[dhcpStart:n], nil
}

// buildDHCPFrame builds Ethernet + IP + UDP frame with DHCP payload
func buildDHCPFrame(srcMAC net.HardwareAddr, dhcpPayload []byte) []byte {
	udpLen := 8 + len(dhcpPayload)
	ipLen := 20 + udpLen
	frameLen := 14 + ipLen

	frame := make([]byte, frameLen)

	// Ethernet header (14 bytes)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst: broadcast
	copy(frame[6:12], srcMAC)                                    // src
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)             // EtherType: IPv4

	// IP header (20 bytes, no options)
	ip := frame[14:]
	ip[0] = 0x45                                       // Version 4, IHL 5
	ip[1] = 0x00                                       // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen)) // Total length
	binary.BigEndian.PutUint16(ip[4:6], 0)             // ID
	binary.BigEndian.PutUint16(ip[6:8], 0)             // Flags/Fragment
	ip[8] = 64                                         // TTL
	ip[9] = 17                                         // Protocol: UDP
	// ip[10:12] = checksum (calculated below)
	copy(ip[12:16], []byte{0, 0, 0, 0})         // Src: 0.0.0.0
	copy(ip[16:20], []byte{255, 255, 255, 255}) // Dst: 255.255.255.255

	// IP checksum
	ipChecksum := ipHeaderChecksum(ip[:20])
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum)

	// UDP header (8 bytes)
	udp := frame[14+20:]
	binary.BigEndian.PutUint16(udp[0:2], 68)             // Src port (DHCP client)
	binary.BigEndian.PutUint16(udp[2:4], 67)             // Dst port (DHCP server)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen)) // Length
	binary.BigEndian.PutUint16(udp[6:8], 0)              // Checksum (0 = disabled for IPv4 UDP)

	// DHCP payload
	copy(frame[14+20+8:], dhcpPayload)

	return frame
}

// ipHeaderChecksum calculates IP header checksum
func ipHeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// doDiscoverOnceRaw performs DHCP discover using raw sockets (bypasses firewall)
func doDiscoverOnceRaw(conn *rawDHCPConn, hw net.HardwareAddr, requestedIP net.IP, targetServer net.IP, listen time.Duration) (*dhcpv4.DHCPv4, net.IP, time.Duration, error) {
	xid := randomXID()
	discover, err := dhcpv4.NewDiscovery(hw, dhcpv4.WithBroadcast(true))
	if err != nil {
		return nil, nil, 0, err
	}
	discover.TransactionID = xid
	if requestedIP != nil {
		discover.UpdateOption(dhcpv4.OptRequestedIPAddress(requestedIP))
	}
	discover.UpdateOption(dhcpv4.OptParameterRequestList(
		dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter, dhcpv4.OptionDomainNameServer,
		dhcpv4.OptionDomainName, dhcpv4.OptionServerIdentifier, dhcpv4.OptionBroadcastAddress,
	))

	if debug {
		fmt.Printf("[debug] doDiscoverOnceRaw: sending DHCPDISCOVER xid=0x%08x hw=%s\n", xidToUint32(xid), hw)
	}

	start := time.Now()
	if err := conn.sendDHCP(discover.ToBytes(), hw); err != nil {
		return nil, nil, 0, fmt.Errorf("send discover: %w", err)
	}

	if err := conn.SetReadTimeout(listen); err != nil {
		return nil, nil, 0, fmt.Errorf("set timeout: %w", err)
	}

	deadline := time.Now().Add(listen)
	var chosen *dhcpv4.DHCPv4
	var server net.IP

	for time.Now().Before(deadline) {
		dhcpBytes, err := conn.recvDHCP()
		if err != nil {
			if debug {
				// Don't spam on timeout
				if !strings.Contains(err.Error(), "resource temporarily unavailable") {
					fmt.Printf("[debug] doDiscoverOnceRaw: recv error: %v\n", err)
				}
			}
			continue
		}

		pkt, perr := dhcpv4.FromBytes(dhcpBytes)
		if perr != nil {
			if debug {
				fmt.Printf("[debug] doDiscoverOnceRaw: parse error: %v\n", perr)
			}
			continue
		}

		if debug {
			fmt.Printf("[debug] doDiscoverOnceRaw: got packet type=%s xid=0x%08x (want 0x%08x)\n",
				pkt.MessageType(), xidToUint32(pkt.TransactionID), xidToUint32(xid))
		}

		if pkt.TransactionID != xid || pkt.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}

		sid := pkt.ServerIdentifier()
		if sid != nil {
			server = sid
		} else {
			server = pkt.ServerIPAddr
		}

		if targetServer != nil && !server.Equal(targetServer) {
			continue
		}

		chosen = pkt
		break
	}

	if chosen == nil {
		return nil, nil, 0, errors.New("no suitable DHCPOFFER received")
	}
	return chosen, server, time.Since(start), nil
}

// doRequestOnceRaw performs DHCP request using raw sockets
func doRequestOnceRaw(conn *rawDHCPConn, hw net.HardwareAddr, offer *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4, error) {
	req, err := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	req.ClientHWAddr = hw
	req.SetBroadcast()

	if err := conn.sendDHCP(req.ToBytes(), hw); err != nil {
		return nil, nil, fmt.Errorf("send request: %w", err)
	}

	if err := conn.SetReadTimeout(3 * time.Second); err != nil {
		return nil, nil, fmt.Errorf("set timeout: %w", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		dhcpBytes, err := conn.recvDHCP()
		if err != nil {
			continue
		}

		pkt, perr := dhcpv4.FromBytes(dhcpBytes)
		if perr != nil || pkt.TransactionID != req.TransactionID {
			continue
		}

		switch pkt.MessageType() {
		case dhcpv4.MessageTypeAck:
			return req, pkt, nil
		case dhcpv4.MessageTypeNak:
			return req, nil, errors.New("NAK: server declined the request")
		}
	}

	return req, nil, errors.New("no DHCPACK/NAK received")
}

// createDHCPConn creates a UDP connection suitable for DHCP with proper socket options
func createDHCPConn(iface *net.Interface) (*net.UDPConn, error) {
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: 68}

	// Use ListenConfig to set socket options before bind
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				// Allow address reuse
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					sockErr = fmt.Errorf("SO_REUSEADDR: %w", err)
					return
				}
				// Enable broadcast
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
					sockErr = fmt.Errorf("SO_BROADCAST: %w", err)
					return
				}
				// Bind to specific interface (Linux only, critical for receiving broadcast replies)
				if runtime.GOOS == "linux" && iface != nil {
					if err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name); err != nil {
						sockErr = fmt.Errorf("SO_BINDTODEVICE: %w", err)
						return
					}
				}
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", laddr.String())
	if err != nil {
		return nil, fmt.Errorf("bind udp/68: %w (need root and ensure no other DHCP client is bound)", err)
	}

	return conn.(*net.UDPConn), nil
}
