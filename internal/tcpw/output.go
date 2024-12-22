// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package tcpw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"structs"
	"unsafe"

	"github.com/Asphaltt/tcpw/internal/strx"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	structs.HostLayout
	Comm       [16]byte
	Pid        uint32
	AddrFamily addrFamily
	IsActive   uint8
	Pad        uint8
	Proto      [32]byte
	Data       [108]byte
}

func (ev *Event) output(sb *strings.Builder, f *TcpwFlags) bool {
	le, be := binary.LittleEndian, binary.BigEndian

	comm := strx.NullTerminated(ev.Comm[:])
	proto := strx.NullTerminated(ev.Proto[:])
	fmt.Fprintf(sb, "tcpw: pid=%d comm=%s af=%s proto=%s",
		ev.Pid, comm, ev.AddrFamily, proto)

	switch proto {
	case "TCP", "UDP", "TCPv6", "UDPv6":
		if (proto == "UDP" || proto == "UDPv6") && !f.UDP {
			return false
		}

		rport, lport := be.Uint16(ev.Data[0:2]), le.Uint16(ev.Data[2:4])

		var raddr, laddr net.IP
		if ev.AddrFamily == AF_INET {
			raddr, laddr = net.IP(ev.Data[4:8]), net.IP(ev.Data[8:12])
		} else if ev.AddrFamily == AF_INET6 {
			raddr, laddr = net.IP(ev.Data[4:20]), net.IP(ev.Data[20:36])
		} else {
			return false
		}

		indicator := "--"
		if proto == "TCP" {
			if ev.IsActive == 1 {
				indicator = "->"
			} else {
				indicator = "<-"
			}
		}
		if ev.AddrFamily == AF_INET {
			fmt.Fprintf(sb, " %s:%d %s %s:%d", laddr, lport, indicator, raddr, rport)
		} else {
			fmt.Fprintf(sb, " [%s]:%d %s [%s]:%d", laddr, lport, indicator, raddr, rport)
		}

	case "UNIX-STREAM", "UNIX-DGRAM":
		if !f.UnixSocket {
			return false
		}
		path := strx.NullTerminated(ev.Data[:])
		fmt.Fprintf(sb, " path=%s", path)

	default:
		return false
	}

	return true
}

func Run(reader *ringbuf.Reader, f *TcpwFlags) error {
	const sizeofEvent = unsafe.Sizeof(Event{})

	var record ringbuf.Record
	record.RawSample = make([]byte, sizeofEvent)

	var sb strings.Builder

	for {
		err := reader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		// spew.Dump(record)

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
		if event.output(&sb, f) {
			log.Println(sb.String())
		}

		sb.Reset()
	}
}
