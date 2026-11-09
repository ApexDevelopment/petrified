package network

// Exports for petrified's differential tests. This file is copied into a
// pristine copy of the upstream package at build time.

import (
	"crypto/ed25519"
	"time"

	"github.com/Arceliar/phony"
	bfilter "github.com/bits-and-blooms/bloom/v3"

	"github.com/Arceliar/ironwood/types"
)

func petrifiedDecode(kind string, data []byte) (wireEncodeable, error) {
	switch kind {
	case "sigreq":
		v := new(routerSigReq)
		return v, v.decode(data)
	case "sigres":
		v := new(routerSigRes)
		return v, v.decode(data)
	case "announce":
		v := new(routerAnnounce)
		return v, v.decode(data)
	case "bloom":
		v := newBloom()
		return v, v.decode(data)
	case "lookup":
		v := new(pathLookup)
		return v, v.decode(data)
	case "notify":
		v := new(pathNotify)
		return v, v.decode(data)
	case "broken":
		v := new(pathBroken)
		return v, v.decode(data)
	case "traffic":
		v := new(traffic)
		return v, v.decode(data)
	}
	return nil, types.ErrUnrecognizedMessage
}

func PetrifiedReencode(kind string, data []byte) ([]byte, error) {
	obj, err := petrifiedDecode(kind, data)
	if err != nil {
		return nil, err
	}
	return obj.encode(nil)
}

func PetrifiedCheck(kind string, data []byte, node, parent []byte) (bool, error) {
	obj, err := petrifiedDecode(kind, data)
	if err != nil {
		return false, err
	}
	var n, p publicKey
	copy(n[:], node)
	copy(p[:], parent)
	switch v := obj.(type) {
	case *routerSigRes:
		return v.check(n, p), nil
	case *routerAnnounce:
		return v.check(), nil
	case *pathNotify:
		return v.check(), nil
	}
	return true, nil
}

func PetrifiedBloomWords(keys [][]byte) []uint64 {
	b := newBloom()
	for _, key := range keys {
		var pk publicKey
		copy(pk[:], key)
		b.addKey(pk)
	}
	return append([]uint64(nil), b.filter.BitSet().Bytes()...)
}

func PetrifiedBloomTest(words []uint64, key []byte) bool {
	return bfilter.From(append([]uint64(nil), words...), bloomFilterK).Test(key)
}

func PetrifiedBloomLocations(data []byte) []uint64 {
	return bfilter.Locations(data, bloomFilterK)
}

// PetrifiedRouter exposes the tree logic of a node with maintenance stopped.
type PetrifiedRouter struct {
	pc    *PacketConn
	order uint64
}

func NewPetrifiedRouter(secret ed25519.PrivateKey) (*PetrifiedRouter, error) {
	pc, err := NewPacketConn(secret)
	if err != nil {
		return nil, err
	}
	phony.Block(&pc.core.router, pc.core.router._shutdown)
	return &PetrifiedRouter{pc: pc}, nil
}

func (h *PetrifiedRouter) block(f func(r *router)) {
	r := &h.pc.core.router
	phony.Block(r, func() { f(r) })
}

func (h *PetrifiedRouter) Update(data []byte) (accepted bool, err error) {
	ann := new(routerAnnounce)
	if err = ann.decode(data); err != nil {
		return
	}
	h.block(func(r *router) { accepted = r._update(ann) })
	return
}

func (h *PetrifiedRouter) AddPeer(key []byte, prio uint8, lagMs uint64) uint64 {
	var pk publicKey
	copy(pk[:], key)
	p := &peer{key: pk, prio: prio, order: h.order}
	h.order++
	h.block(func(r *router) {
		if _, isIn := r.peers[pk]; !isIn {
			r.peers[pk] = make(map[*peer]struct{})
			r.sent[pk] = make(map[publicKey]struct{})
		}
		r.peers[pk][p] = struct{}{}
		r.lags[p] = time.Duration(lagMs) * time.Millisecond
	})
	return p.order
}

func (h *PetrifiedRouter) RootAndPath(key []byte) (root []byte, path []uint64) {
	var pk publicKey
	copy(pk[:], key)
	h.block(func(r *router) {
		rt, ps := r._getRootAndPath(pk)
		root = append(root, rt[:]...)
		path = []uint64{}
		for _, port := range ps {
			path = append(path, uint64(port))
		}
	})
	return
}

func (h *PetrifiedRouter) RootAndDists(key []byte) (root []byte, dists map[string]uint64, valid bool) {
	var pk publicKey
	copy(pk[:], key)
	h.block(func(r *router) {
		rt, ds, ok := r._getRootAndDists(pk)
		root = append(root, rt[:]...)
		dists = make(map[string]uint64)
		for k, d := range ds {
			dists[k.addr().String()] = d
		}
		valid = ok
	})
	return
}

func toPorts(path []uint64) []peerPort {
	ports := make([]peerPort, 0, len(path))
	for _, p := range path {
		ports = append(ports, peerPort(p))
	}
	return ports
}

func (h *PetrifiedRouter) Dist(path []uint64, key []byte) (dist uint64) {
	var pk publicKey
	copy(pk[:], key)
	h.block(func(r *router) { dist = r._getDist(toPorts(path), pk) })
	return
}

func (h *PetrifiedRouter) Ancestry(key []byte) (anc [][]byte) {
	var pk publicKey
	copy(pk[:], key)
	h.block(func(r *router) {
		anc = [][]byte{}
		for _, k := range r._getAncestry(pk) {
			anc = append(anc, append([]byte(nil), k[:]...))
		}
	})
	return
}

func (h *PetrifiedRouter) Lookup(path []uint64, watermark *uint64) (next []byte, order uint64) {
	h.block(func(r *router) {
		if p := r._lookup(toPorts(path), watermark); p != nil {
			next = append(next, p.key[:]...)
			order = p.order
		}
	})
	return
}

// PetrifiedCoords returns this node's root and coordinates.
func (pc *PacketConn) PetrifiedCoords() (root []byte, path []uint64) {
	r := &pc.core.router
	phony.Block(r, func() {
		rt, ps := r._getRootAndPath(pc.core.crypto.publicKey)
		root = append(root, rt[:]...)
		path = []uint64{}
		for _, port := range ps {
			path = append(path, uint64(port))
		}
	})
	return
}
