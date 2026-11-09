package encrypted

// Exports for petrified's differential tests. This file is copied into a
// pristine copy of the upstream package at build time.

import (
	"golang.org/x/crypto/curve25519"
)

func PetrifiedEdPubToBox(pub []byte) []byte {
	var ep edPub
	copy(ep[:], pub)
	b, _ := ep.toBox()
	return b[:]
}

func PetrifiedEdPrivToBox(priv []byte) []byte {
	var ep edPriv
	copy(ep[:], priv)
	return ep.toBox()[:]
}

func PetrifiedBoxPubForPriv(priv []byte) []byte {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pub
}

func PetrifiedGetShared(pub, priv []byte) []byte {
	var bp boxPub
	var bk boxPriv
	var shared boxShared
	copy(bp[:], pub)
	copy(bk[:], priv)
	getShared(&shared, &bp, &bk)
	return shared[:]
}

func PetrifiedBoxSeal(msg []byte, nonce uint64, shared []byte) []byte {
	var s boxShared
	copy(s[:], shared)
	return boxSeal(nil, msg, nonce, &s)
}

func PetrifiedBoxOpen(boxed []byte, nonce uint64, shared []byte) ([]byte, bool) {
	var s boxShared
	copy(s[:], shared)
	return boxOpen(nil, boxed, nonce, &s)
}

func PetrifiedSessionInitEncrypt(fromPriv, toPub []byte, password string, current, next []byte, keySeq, seq uint64) []byte {
	var from edPriv
	var to edPub
	copy(from[:], fromPriv)
	copy(to[:], toPub)
	var init sessionInit
	copy(init.current[:], current)
	copy(init.next[:], next)
	init.keySeq, init.seq = keySeq, seq
	data, err := init.encrypt(&from, &to, newGroupAuth(password))
	if err != nil {
		panic(err)
	}
	return data
}

func PetrifiedSessionInitDecrypt(ownPriv, fromPub, data []byte, password string) (current, next []byte, keySeq, seq uint64, ok bool) {
	var own edPriv
	var from edPub
	copy(own[:], ownPriv)
	copy(from[:], fromPub)
	var init sessionInit
	if ok = init.decrypt(own.toBox(), &from, data, newGroupAuth(password)); ok {
		current, next = init.current[:], init.next[:]
		keySeq, seq = init.keySeq, init.seq
	}
	return
}
