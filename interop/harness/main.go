// Command harness drives the Go implementation of Ironwood for petrified's
// interop tests.
//
//	harness vectors
//	    Answers JSON requests on stdin, one per line, about wire formats,
//	    crypto, and tree logic.
//	harness node -type network|encrypted|signed -seed HEX [-password P]
//	    Runs a node on a localhost TCP listener, controlled over stdin.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Arceliar/ironwood/encrypted"
	"github.com/Arceliar/ironwood/network"
	"github.com/Arceliar/ironwood/signed"
	"github.com/Arceliar/ironwood/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: harness vectors | harness node ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "vectors":
		runVectors()
	case "node":
		runNode(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}

func mustHex(s string) []byte {
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bs
}

func hexList(bss [][]byte) []string {
	out := []string{}
	for _, bs := range bss {
		out = append(out, hex.EncodeToString(bs))
	}
	return out
}

/***********
 * vectors *
 ***********/

type request struct {
	Op        string   `json:"op"`
	Kind      string   `json:"kind"`
	Data      string   `json:"data"`
	Node      string   `json:"node"`
	Parent    string   `json:"parent"`
	Key       string   `json:"key"`
	Keys      []string `json:"keys"`
	Words     []uint64 `json:"words"`
	Seed      string   `json:"seed"`
	Prio      uint8    `json:"prio"`
	LagMs     uint64   `json:"lag_ms"`
	Path      []uint64 `json:"path"`
	Watermark *uint64  `json:"watermark"`
	Nonce     uint64   `json:"nonce"`
	Shared    string   `json:"shared"`
	Msg       string   `json:"msg"`
	Pub       string   `json:"pub"`
	Priv      string   `json:"priv"`
	Password  string   `json:"password"`
	Current   string   `json:"current"`
	Next      string   `json:"next"`
	KeySeq    uint64   `json:"key_seq"`
	Seq       uint64   `json:"seq"`
}

type response map[string]any

func privFromSeed(seed string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(mustHex(seed))
}

func handleVector(req *request, h **network.PetrifiedRouter) response {
	switch req.Op {
	case "reencode":
		out, err := network.PetrifiedReencode(req.Kind, mustHex(req.Data))
		if err != nil {
			return response{"error": err.Error()}
		}
		return response{"data": hex.EncodeToString(out)}
	case "check":
		ok, err := network.PetrifiedCheck(req.Kind, mustHex(req.Data), mustHex(req.Node), mustHex(req.Parent))
		if err != nil {
			return response{"error": err.Error()}
		}
		return response{"valid": ok}
	case "key_valid":
		var key [32]byte
		copy(key[:], mustHex(req.Key))
		return response{"valid": types.IsPublicKeyValid(key)}
	case "verify":
		return response{"valid": ed25519.Verify(mustHex(req.Key), mustHex(req.Msg), mustHex(req.Data))}
	case "sign":
		return response{"sig": hex.EncodeToString(ed25519.Sign(privFromSeed(req.Seed), mustHex(req.Msg)))}
	case "bloom_words":
		var keys [][]byte
		for _, k := range req.Keys {
			keys = append(keys, mustHex(k))
		}
		return response{"words": network.PetrifiedBloomWords(keys)}
	case "bloom_locations":
		return response{"locations": network.PetrifiedBloomLocations(mustHex(req.Data))}
	case "bloom_test":
		return response{"present": network.PetrifiedBloomTest(req.Words, mustHex(req.Key))}
	case "ed_pub_to_box":
		return response{"key": hex.EncodeToString(encrypted.PetrifiedEdPubToBox(mustHex(req.Key)))}
	case "ed_priv_to_box":
		return response{"key": hex.EncodeToString(encrypted.PetrifiedEdPrivToBox(privFromSeed(req.Seed)))}
	case "box_pub":
		return response{"key": hex.EncodeToString(encrypted.PetrifiedBoxPubForPriv(mustHex(req.Priv)))}
	case "shared":
		return response{"key": hex.EncodeToString(encrypted.PetrifiedGetShared(mustHex(req.Pub), mustHex(req.Priv)))}
	case "box_seal":
		return response{"data": hex.EncodeToString(encrypted.PetrifiedBoxSeal(mustHex(req.Msg), req.Nonce, mustHex(req.Shared)))}
	case "box_open":
		msg, ok := encrypted.PetrifiedBoxOpen(mustHex(req.Data), req.Nonce, mustHex(req.Shared))
		if !ok {
			return response{"error": "open failed"}
		}
		return response{"msg": hex.EncodeToString(msg)}
	case "init_encrypt":
		data := encrypted.PetrifiedSessionInitEncrypt(privFromSeed(req.Seed), mustHex(req.Key), req.Password,
			mustHex(req.Current), mustHex(req.Next), req.KeySeq, req.Seq)
		return response{"data": hex.EncodeToString(data)}
	case "init_decrypt":
		current, next, keySeq, seq, ok := encrypted.PetrifiedSessionInitDecrypt(privFromSeed(req.Seed), mustHex(req.Key), mustHex(req.Data), req.Password)
		if !ok {
			return response{"error": "decrypt failed"}
		}
		return response{"current": hex.EncodeToString(current), "next": hex.EncodeToString(next), "key_seq": keySeq, "seq": seq}
	case "router_new":
		router, err := network.NewPetrifiedRouter(privFromSeed(req.Seed))
		if err != nil {
			return response{"error": err.Error()}
		}
		*h = router
		return response{}
	case "router_update":
		accepted, err := (*h).Update(mustHex(req.Data))
		if err != nil {
			return response{"error": err.Error()}
		}
		return response{"accepted": accepted}
	case "router_add_peer":
		return response{"order": (*h).AddPeer(mustHex(req.Key), req.Prio, req.LagMs)}
	case "router_root_and_path":
		root, path := (*h).RootAndPath(mustHex(req.Key))
		return response{"root": hex.EncodeToString(root), "path": path}
	case "router_root_and_dists":
		root, dists, valid := (*h).RootAndDists(mustHex(req.Key))
		return response{"root": hex.EncodeToString(root), "dists": dists, "valid": valid}
	case "router_dist":
		return response{"dist": (*h).Dist(req.Path, mustHex(req.Key))}
	case "router_ancestry":
		return response{"ancestry": hexList((*h).Ancestry(mustHex(req.Key)))}
	case "router_lookup":
		next, order := (*h).Lookup(req.Path, req.Watermark)
		res := response{"next": nil, "order": nil, "watermark": req.Watermark}
		if next != nil {
			res["next"] = hex.EncodeToString(next)
			res["order"] = order
		}
		return res
	}
	return response{"error": "unknown op " + req.Op}
}

func runVectors() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	var h *network.PetrifiedRouter
	for in.Scan() {
		var req request
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			panic(err)
		}
		if err := enc.Encode(handleVector(&req, &h)); err != nil {
			panic(err)
		}
		out.Flush()
	}
}

/********
 * node *
 ********/

type nodeConn interface {
	types.PacketConn
	PetrifiedCoords() ([]byte, []uint64)
	GetTree() []network.DebugTreeInfo
	GetPeers() []network.DebugPeerInfo
}

type networkNode struct{ *network.PacketConn }

func (n networkNode) GetTree() []network.DebugTreeInfo  { return n.Debug.GetTree() }
func (n networkNode) GetPeers() []network.DebugPeerInfo { return n.Debug.GetPeers() }

type encryptedNode struct{ *encrypted.PacketConn }

func (n encryptedNode) PetrifiedCoords() ([]byte, []uint64) { return n.PacketConn.PacketConn.PetrifiedCoords() }
func (n encryptedNode) GetTree() []network.DebugTreeInfo   { return n.PacketConn.PacketConn.Debug.GetTree() }
func (n encryptedNode) GetPeers() []network.DebugPeerInfo  { return n.PacketConn.PacketConn.Debug.GetPeers() }

type signedNode struct{ *signed.PacketConn }

func (n signedNode) PetrifiedCoords() ([]byte, []uint64) { return n.PacketConn.PacketConn.PetrifiedCoords() }
func (n signedNode) GetTree() []network.DebugTreeInfo   { return n.PacketConn.PacketConn.Debug.GetTree() }
func (n signedNode) GetPeers() []network.DebugPeerInfo  { return n.PacketConn.PacketConn.Debug.GetPeers() }

var outMutex sync.Mutex

func emit(format string, args ...any) {
	outMutex.Lock()
	defer outMutex.Unlock()
	fmt.Printf(format+"\n", args...)
}

// handshake exchanges public keys, then hands the connection to the node.
func handshake(node nodeConn, conn net.Conn) {
	self := []byte(node.PrivateKey().Public().(ed25519.PublicKey))
	if _, err := conn.Write(self); err != nil {
		conn.Close()
		return
	}
	peerKey := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(conn, peerKey); err != nil {
		conn.Close()
		return
	}
	emit("connected %s", hex.EncodeToString(peerKey))
	err := node.HandleConn(peerKey, conn, 0)
	emit("disconnected %s %v", hex.EncodeToString(peerKey), err)
}

func runNode(args []string) {
	flags := flag.NewFlagSet("node", flag.ExitOnError)
	kind := flags.String("type", "encrypted", "network, encrypted, or signed")
	seed := flags.String("seed", "", "hex ed25519 seed")
	password := flags.String("password", "", "encrypted session password")
	flags.Parse(args)
	priv := privFromSeed(*seed)
	var node nodeConn
	var err error
	switch *kind {
	case "network":
		var pc *network.PacketConn
		pc, err = network.NewPacketConn(priv)
		node = networkNode{pc}
	case "encrypted":
		var pc *encrypted.PacketConn
		pc, err = encrypted.NewPacketConnWithPassword(priv, *password)
		node = encryptedNode{pc}
	case "signed":
		var pc *signed.PacketConn
		pc, err = signed.NewPacketConn(priv)
		node = signedNode{pc}
	}
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handshake(node, conn)
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := node.ReadFrom(buf)
			if err != nil {
				return
			}
			emit("recv %s %s", hex.EncodeToString(from.(types.Addr)), hex.EncodeToString(buf[:n]))
		}
	}()
	emit("listening %s %s", listener.Addr(), hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	for in.Scan() {
		fields := strings.Fields(in.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "connect":
			conn, err := net.Dial("tcp", fields[1])
			if err != nil {
				emit("error %v", err)
				continue
			}
			go handshake(node, conn)
		case "send":
			if _, err := node.WriteTo(mustHex(fields[2]), types.Addr(mustHex(fields[1]))); err != nil {
				emit("error %v", err)
			}
		case "lookup":
			node.SendLookup(mustHex(fields[1]))
		case "coords":
			root, path := node.PetrifiedCoords()
			bs, _ := json.Marshal(path)
			emit("coords %s %s", hex.EncodeToString(root), bs)
		case "tree":
			tree := map[string]string{}
			for _, info := range node.GetTree() {
				tree[hex.EncodeToString(info.Key)] = hex.EncodeToString(info.Parent)
			}
			bs, _ := json.Marshal(tree)
			emit("tree %s", bs)
		case "peers":
			emit("peers %d", len(node.GetPeers()))
		case "close":
			node.Close()
			listener.Close()
			emit("closed")
		case "quit":
			node.Close()
			return
		}
	}
	node.Close()
}
