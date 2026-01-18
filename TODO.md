# DHCPv6 Support

- [ ] Add `--ipv6` flag to commands
- [ ] Import `dhcpv6` package from insomniacslk/dhcp
- [ ] Create DUID generation function (client identifier)
- [ ] Create raw IPv6 socket connection (AF_PACKET with ETH_P_IPV6)
- [ ] Build IPv6 + UDP header construction for raw packets
- [ ] Implement `doSolicitOnce` (DHCPv6 equivalent of discover)
- [ ] Implement `doRequestOnceV6` for DHCPv6 Request/Reply
- [ ] Add `runGetIPv6` function
- [ ] Add `runDiscoverV6` function
- [ ] Add `runTestV6` function
- [ ] Parse DHCPv6 options (IA_NA, IA_TA, IA_PD, DNS, domain search)
- [ ] Add DHCPv6 validation checks in test command
- [ ] Update prettyPacket for DHCPv6 output
- [ ] Handle multicast addresses (ff02::1:2 for servers)
- [ ] Test with actual DHCPv6 server
