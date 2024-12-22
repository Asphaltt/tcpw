// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package tcpw

import (
	"slices"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

func isInt(typ btf.Type) bool {
	i, ok := typ.(*btf.Int)
	return ok && i.Name == "int"
}

func isBool(typ btf.Type) bool {
	def, ok := typ.(*btf.Typedef)
	return ok && def.Name == "bool"
}

func isConnectFunc(fn *btf.Func) bool {
	fnProto := fn.Type.(*btf.FuncProto)
	if len(fnProto.Params) != 4 {
		return false
	}

	return mybtf.IsStructPointer(fnProto.Params[0].Type, "socket") &&
		mybtf.IsStructPointer(fnProto.Params[1].Type, "sockaddr") &&
		isInt(fnProto.Params[2].Type) &&
		isInt(fnProto.Params[3].Type)
}

func isAcceptFunc(fn *btf.Func) bool {
	fnProto := fn.Type.(*btf.FuncProto)
	if len(fnProto.Params) != 4 {
		return false
	}

	return mybtf.IsStructPointer(fnProto.Params[0].Type, "socket") &&
		mybtf.IsStructPointer(fnProto.Params[1].Type, "socket") &&
		isInt(fnProto.Params[2].Type) &&
		isBool(fnProto.Params[3].Type)
}

func FindFuncs(spec *btf.Spec) ([]string, []string, error) {
	var connectFuncs, acceptFuncs []string

	iter := spec.Iterate()
	for iter.Next() {
		fn, ok := iter.Type.(*btf.Func)
		if !ok {
			continue
		}

		fnName := fn.Name
		if strings.HasSuffix(fnName, "_connect") {
			if isConnectFunc(fn) {
				connectFuncs = append(connectFuncs, fnName)
			}
		} else if strings.HasSuffix(fnName, "_accept") {
			if isAcceptFunc(fn) {
				acceptFuncs = append(acceptFuncs, fnName)
			}
		}
	}

	slices.Sort(connectFuncs)
	slices.Sort(acceptFuncs)

	return slices.Compact(connectFuncs), slices.Compact(acceptFuncs), nil
}
