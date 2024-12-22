// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package tcpw

type addrFamily uint16

const (
	AF_UNSPEC addrFamily = 0
	AF_UNIX   addrFamily = 1
	AF_INET   addrFamily = 2
	AF_INET6  addrFamily = 10
)

func (af addrFamily) String() string {
	addrFamilies := make([]string, 64)
	addrFamilies[AF_UNSPEC] = "AF_UNSPEC"
	addrFamilies[AF_UNIX] = "AF_UNIX"
	addrFamilies[AF_INET] = "AF_INET"
	addrFamilies[AF_INET6] = "AF_INET6"

	if int(af) >= len(addrFamilies) {
		return "unknown"
	}

	s := addrFamilies[af]
	if s == "" {
		return "unknown"
	}

	return s
}
