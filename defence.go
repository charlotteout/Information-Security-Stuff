package main

import (
    "os"
    "student.ch/netsec/isl/defense/common"
)

const (
    // Global constants
    TreshholdIP = 50
)

var (
    // Here, you can define variables that keep state for your firewall
    MapASIP map[string]int = make(map[string]int)
    drop_first_packets = true
)


// Helper function for inspecting packets. Feel free to change / remove this
func printPkt(packet *common.Pkt) {
    printPktSCION(packet.SCION)
    printPktUDP(packet.UDP)
}

// Decide whether to forward or drop a packet based on SCION / UDP header.
// This function receives all packets with the customer as destination


//The attacker always sends just one packet from one IP in def2
//Therefore, if we always drop the first packet coming from one IP
//unless we detect are we in def1. The packets we unrightfully dropped
//in def1 is small as there the number of IP's sending us packets is small
// (only 2)

func ForwardPacket(packet *common.Pkt) bool {

    IP_string := string(packet.SCION.SrcAS) + string(packet.SCION.SrcHost)



    //if we receive the first packet of an IP and we did not detect that
    //we are in def1 (yet) we drop the packet.
    if MapASIP[IP_string] < 1 {
        MapASIP[IP_string]++
        if drop_first_packets{
            return false
        }
    }else{
        //we still update the number of packets from an IP
        MapASIP[IP_string]++
    }

    if MapASIP[IP_string] > TreshholdIP {
        drop_first_packets = false
        return false
    }
    return true
}

func main() {
    done := make(chan int, 1)
    go runFirewall("/usr/local/lib/firewall.so", done) // start the firewall
    code := <-done // wait for an exit code on the channel
    os.Exit(code)
}
