
extern "C" {
extern bool attach_bpf_icmp6_ra(int fd, const char *ifname);
extern bool attach_bpf_dhcp6_info(int fd, const char *ifname);
}

