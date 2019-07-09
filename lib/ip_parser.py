from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError, iter_unique_ips

def parse_targets(target):
    if '-' in target:
        ip_range = target.split('-')
        try:
            hosts = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            try:
                start_ip = IPAddress(ip_range[0])

                start_ip_words = list(start_ip.words)
                start_ip_words[-1] = ip_range[1]
                start_ip_words = [str(v) for v in start_ip_words]

                end_ip = IPAddress('.'.join(start_ip_words))

                t = IPRange(start_ip, end_ip)
            except AddrFormatError:
                t = target
    else:
        try:
            t = IPNetwork(target)
        except AddrFormatError:
            t = target

    if type(t) == IPNetwork or type(t) == IPRange:
        t = [str(ip) for ip in list(t)]
        return t
    else:
        return [str(t.strip())]

def from_file(file):
    ips=[]
    OPENFILE=open(file,'r')
    for line in OPENFILE:
        if "/" in line:
            subnet_ips=iter_unique_ips(line)
            for ip in subnet_ips:
                ips.append(ip)
        else:
            tmp=line.rstrip()
            ips.append(tmp)
    return ips