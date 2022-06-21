#!/bin/bash -u

die() { echo "$@">&2; exit 1; }

(($# == 1)) || die "\
Usage:

    dhcpcd.sh interface [&> logfile]

A simple dhcp client daemon using dora.

Bring up specified interface using dhcp, fork a dhcp lease renew loop in the background and exit 0. Note the
background process may subsequently terminate with an error if the lease can't be renewed.

If the interface can't be brought up, exit 1. Depending on what failed the interface may be left in a partially
configured state.
"

iface=$1

me="${0##*/}@$iface"

# Look for executables, dora can be in same directory as this script
dora=$(type -p ${0%/*}/dora) || dora=$(type -p dora) || die "$me: need executable 'dora'"
ip=$(type -p ip) || die "$me: need executable 'ip'"
sed=$(type -p sed) || die "$me: need executable 'sed'"

((UID)) && die "$me: must be run as root"

# given a dora output string, configure or die
configure()
{
    # $1=address $2=subnet $3=broadcast $4=router $5=dnsserver $6=domainname $7=dhcpserver $8=leaseseconds
    echo "$me: configuring address=$1, router=$4, dnsserver=$5, dhcpserver=$7, leaseseconds=$8"
    $ip addr add $1 dev $iface || die "$me: unable to assign address"
    [[ $4 == "0.0.0.0" ]] || $ip route add default via $4 dev $iface || die "$me: unable to set default route"
    [[ $5 == "0.0.0.0" ]] || echo "nameserver $5" >> /etc/resolv.conf || die "$me: unable to set nameserver"
    # set globals
    configured="$@"     # remember what is configured
    dhcpserver=$7       # these are used by the renew process
    leaseseconds=$8
}

# undo last configure
unconfigure()
{
    if [[ $configured ]]; then
        echo
        set -- $configured
        configured=""
        # $1=address $2=subnet $3=broadcast $4=router $5=dnsserver $6=domainname $7=dhcpserver $8=leaseseconds
        echo "$me: deconfiguring address=$1, router=$4, dnsserver=$5, dhcpserver=$7"
        $dora release $7 $iface
        [[ $5 == "0.0.0.0" ]] || $sed -i "/^nameserver $5$/d" /etc/resolv.conf
        [[ $4 == "0.0.0.0" ]] || $ip route del default via $4
        $ip addr del $1 dev $iface
    fi
}

# configure or die
$ip link set up dev $iface || die "$me: invalid interface"
new=$($dora -m acquire $iface) || die "$me: dora acquire failed"
configure $new

# interface is up, fork a lease renew process
{
    # unconfigure on exit
    trap unconfigure EXIT

    if ((!leaseseconds)); then
        # In theory the zero-second lease is the same as an infinity lease except the client won't re-request the
        # address on the next boot. But since we don't store leases anyway, it's just an infinity lease.
        while true; do sleep 100d; done
    fi

    while true; do
        # sleep and renew
        zzz=$((leaseseconds/2));
        echo "$me: sleeping $zzz seconds until T1"
        sleep $zzz
        if new=$($dora -m renew $dhcpserver $iface); then
            echo "$me: renew OK"
            [[ $new == $configured ]] && continue
        else
            zzz=$(((leaseseconds*3)/8))
            echo "$me: renew failed, sleeping $zzz seconds until T2"
            sleep $zzz
            if new=$($dora -m rebind $iface); then
                echo "$me: rebind OK"
                [[ $new == $configured ]] && continue
            else
                zzz=$((leaseseconds/8))
                echo "$me: rebind failed, sleeping $zzz seconds until lease expires"
                sleep $zzz
                new="" # force acquire
            fi
        fi
        # lease expired or server gave new info, reconfigure or die
        unconfigure
        [[ $new ]] || new=$($dora -m acquire $iface) || die "$me: dora acquire failed"
        configure $new
    done
} &

# success!
disown -ha
echo $! > /tmp/$me
echo "$me: interface is up, renew process is pid $!, pidfile is /tmp/$me"
