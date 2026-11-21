/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"go.uber.org/atomic"

	"github.com/ivlev-dev/umbrawg/go/conn"
	"github.com/ivlev-dev/umbrawg/go/conn/bindtest"
	"github.com/ivlev-dev/umbrawg/go/tun"
	"github.com/ivlev-dev/umbrawg/go/tun/tuntest"
)

// uapiCfg returns a string that contains cfg formatted use with IpcSet.
// cfg is a series of alternating key/value strings.
// uapiCfg exists because editors and humans like to insert
// whitespace into configs, which can cause failures, some of which are silent.
// For example, a leading blank newline causes the remainder
// of the config to be silently ignored.
func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
func genConfigs(tb testing.TB, cfg ...string) (cfgs, endpointCfgs [2]string) {
	var key1, key2 NoisePrivateKey
	_, err := rand.Read(key1[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	pub1, pub2 := key1.publicKey(), key2.publicKey()

	args0 := append([]string(nil), cfg...)
	args0 = append(args0, []string{
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32",
	}...)
	cfgs[0] = uapiCfg(args0...)

	endpointCfgs[0] = uapiCfg(
		"public_key", hex.EncodeToString(pub2[:]),
		"endpoint", "127.0.0.1:%d",
	)

	args1 := append([]string(nil), cfg...)
	args1 = append(args1, []string{
		"private_key", hex.EncodeToString(key2[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub1[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.1/32",
	}...)

	cfgs[1] = uapiCfg(args1...)
	endpointCfgs[1] = uapiCfg(
		"public_key", hex.EncodeToString(pub1[:]),
		"endpoint", "127.0.0.1:%d",
	)
	return
}

// A testPair is a pair of testPeers.
type testPair [2]testPeer

// A testPeer is a peer used for testing.
type testPeer struct {
	tun *tuntest.ChannelTUN
	dev *Device
	ip  netip.Addr
}

type SendDirection bool

const (
	Ping SendDirection = true
	Pong SendDirection = false
)

func (d SendDirection) String() string {
	if d == Ping {
		return "ping"
	}
	return "pong"
}

// testTransitTimeout bounds how long one packet may take to cross the tunnel.
// The first packet normally triggers a handshake. If a handshake datagram is
// lost it is retransmitted after RekeyTimeout (5s) plus up to
// RekeyTimeoutJitterMaxMs (334ms) of jitter, and a loaded CI machine may need
// more than one retry. 30s leaves room for about five retries, while a truly
// broken tunnel still fails the test in reasonable time.
const testTransitTimeout = 30 * time.Second

func (pair *testPair) Send(
	tb testing.TB,
	ping SendDirection,
	done chan struct{},
) {
	tb.Helper()
	pair.sendWithTimeout(tb, ping, done, testTransitTimeout)
}

// sendWithTimeout injects a ping and waits up to timeout for it to arrive on
// the other side. It reports how long the packet took and whether it transited.
func (pair *testPair) sendWithTimeout(
	tb testing.TB,
	ping SendDirection,
	done chan struct{},
	timeout time.Duration,
) (time.Duration, bool) {
	tb.Helper()
	p0, p1 := pair[0], pair[1]
	if !ping {
		// pong is the new ping
		p0, p1 = p1, p0
	}

	msg := tuntest.Ping(p0.ip, p1.ip)
	p1.tun.Outbound <- msg
	start := time.Now()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var err error
	select {
	case msgRecv := <-p0.tun.Inbound:
		if !bytes.Equal(msg, msgRecv) {
			err = fmt.Errorf("%s did not transit correctly", ping)
		}
	case <-timer.C:
		err = fmt.Errorf("%s did not transit", ping)
	case <-done:
	}
	elapsed := time.Since(start)
	if err != nil {
		// The error may have occurred because the test is done.
		select {
		case <-done:
			return elapsed, false
		default:
		}
		// Real error.
		pair.logState(tb, ping.String(), elapsed, timeout)
		tb.Error(err)
		return elapsed, false
	}
	return elapsed, true
}

// logState dumps the state that matters when a packet does not transit, so a
// CI failure contains enough context to be diagnosed without a rerun.
func (pair *testPair) logState(tb testing.TB, what string, elapsed, timeout time.Duration) {
	tb.Helper()
	tb.Logf("%s did not transit: elapsed=%v timeout=%v", what, elapsed.Round(time.Millisecond), timeout)
	for i := range pair {
		dev := pair[i].dev
		tb.Logf("dev%d: ip=%v state=%v up=%v s4=%d h4=%v",
			i, pair[i].ip, dev.deviceState(), dev.isUp(),
			dev.paddings.transport.Load(), dev.headers.transport.Load().ToString(),
		)
		dev.peers.RLock()
		for pub, peer := range dev.peers.keyMap {
			peer.endpoint.Lock()
			endpoint := "<none>"
			if peer.endpoint.val != nil {
				endpoint = peer.endpoint.val.DstToString()
			}
			peer.endpoint.Unlock()

			peer.keypairs.RLock()
			current, previous := peer.keypairs.current, peer.keypairs.previous
			next := peer.keypairs.next.Load()
			peer.keypairs.RUnlock()
			initiator := current != nil && current.isInitiator

			lastHandshake := "never"
			if n := peer.lastHandshakeNano.Load(); n != 0 {
				lastHandshake = time.Since(time.Unix(0, n)).Round(time.Millisecond).String() + " ago"
			}
			tb.Logf("dev%d: peer(%s…): endpoint=%s tx=%d rx=%d keypair current=%v next=%v previous=%v initiator=%v lastHandshake=%s",
				i, hex.EncodeToString(pub[:2]), endpoint,
				peer.txBytes.Load(), peer.rxBytes.Load(),
				current != nil, next != nil, previous != nil, initiator, lastHandshake,
			)
		}
		dev.peers.RUnlock()
	}
}

// testPairOptions customizes genTestPair for tests that need to observe or
// interleave with device startup. Nil fields are ignored.
type testPairOptions struct {
	// wrapTUN, if set, wraps the ChannelTUN before it is handed to NewDevice.
	wrapTUN func(i int, dev tun.Device) tun.Device
	// beforeIpcSet, if set, runs after NewDevice and before IpcSet.
	beforeIpcSet func(i int, dev *Device)
}

// genTestPair creates a testPair.
func genTestPair(
	tb testing.TB,
	realSocket bool,
	extraCfg ...string,
) testPair {
	return genTestPairWith(tb, realSocket, testPairOptions{}, extraCfg...)
}

func genTestPairWith(
	tb testing.TB,
	realSocket bool,
	opts testPairOptions,
	extraCfg ...string,
) (pair testPair) {
	var cfg, endpointCfg [2]string
	cfg, endpointCfg = genConfigs(tb, extraCfg...)

	var binds [2]conn.Bind
	if realSocket {
		binds[0], binds[1] = conn.NewDefaultBind(), conn.NewDefaultBind()
	} else {
		binds = bindtest.NewChannelBinds()
	}
	// Bring up a ChannelTun for each config.
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		level := LogLevelVerbose
		if _, ok := tb.(*testing.B); ok && !testing.Verbose() {
			level = LogLevelError
		}
		tunDevice := p.tun.TUN()
		if opts.wrapTUN != nil {
			tunDevice = opts.wrapTUN(i, tunDevice)
		}
		p.dev = NewDevice(tunDevice, binds[i], NewLogger(level, fmt.Sprintf("dev%d: ", i)))
		if opts.beforeIpcSet != nil {
			opts.beforeIpcSet(i, p.dev)
		}
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			tb.Errorf("failed to configure device %d: %v", i, err)
			p.dev.Close()
			continue
		}
		if err := p.dev.Up(); err != nil {
			tb.Errorf("failed to bring up device %d: %v", i, err)
			p.dev.Close()
			continue
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	}
	for i := range pair {
		p := &pair[i]
		if err := p.dev.IpcSet(endpointCfg[i]); err != nil {
			tb.Errorf("failed to configure device endpoint %d: %v", i, err)
			p.dev.Close()
			continue
		}
		// The device is ready. Close it when the test completes.
		tb.Cleanup(p.dev.Close)
	}
	return
}

func TestTwoDevicePing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true)
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}

// readNotifyTUN reports when the device's TUN reader enters Read. The reader
// samples per-packet configuration (such as the transport padding) before
// calling Read, so tests can use this to observe the "sampled, then blocked"
// state and only then change the configuration.
type readNotifyTUN struct {
	tun.Device
	started chan struct{}
	once    sync.Once
}

func (t *readNotifyTUN) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	t.once.Do(func() { close(t.started) })
	return t.Device.Read(packets, sizes, offset)
}

// TestAWGTransportPaddingConfiguredAfterDeviceStart is a regression test for
// the transport padding being sampled before the blocking TUN read. The device
// and its reader exist first, s4 is configured afterwards, and the very first
// packet must already use the configured padding. With the old behaviour the
// packet went out with padding 0, the peer dropped it as an unknown message
// type and recovery required a rekey retry (RekeyTimeout, 5s).
func TestAWGTransportPaddingConfiguredAfterDeviceStart(t *testing.T) {
	goroutineLeakCheck(t)

	readStarted := make(chan struct{})
	pair := genTestPairWith(t, true, testPairOptions{
		wrapTUN: func(i int, dev tun.Device) tun.Device {
			if i != 1 {
				return dev
			}
			// Device 1 sends the first packet (Ping), so its TUN reader is the
			// one that must have sampled s4 before the configuration arrives.
			return &readNotifyTUN{Device: dev, started: readStarted}
		},
		beforeIpcSet: func(i int, _ *Device) {
			if i != 1 {
				return
			}
			// Give the freshly started reader a chance to reach Read; if it
			// never does, the pre-condition of this test is gone.
			timer := time.NewTimer(testTransitTimeout)
			defer timer.Stop()
			select {
			case <-readStarted:
			case <-timer.C:
				t.Fatalf("TUN reader of dev1 did not enter Read")
			}
		},
	}, "s4", "25")

	const firstPacketDeadline = 2 * time.Second
	elapsed, ok := pair.sendWithTimeout(t, Ping, nil, firstPacketDeadline)
	if !ok {
		t.Fatalf("first packet after configuring s4 did not transit within %v (elapsed %v)",
			firstPacketDeadline, elapsed.Round(time.Millisecond))
	}
	if elapsed >= firstPacketDeadline {
		t.Fatalf("first packet after configuring s4 took %v, want < %v", elapsed.Round(time.Millisecond), firstPacketDeadline)
	}
	t.Logf("first packet after configuring s4 transited in %v", elapsed.Round(time.Millisecond))
}

// Run test with -race=false to avoid the race for setting the default msgTypes 2 times
func TestAWGDevicePing(t *testing.T) {
	goroutineLeakCheck(t)

	// A full AWG profile is intentionally exercised: junk packets of
	// 500..1000 bytes (sent in one batch, so they add no delay), per-message
	// padding s1..s4 and obfuscated header ranges h1..h4.
	pair := genTestPair(t, true,
		"jc", "5",
		"jmin", "500",
		"jmax", "1000",
		"s1", "15",
		"s2", "18",
		"s3", "20",
		"s4", "25",
		"h1", "123456-123500",
		"h2", "67543-67550",
		"h3", "123123-123200",
		"h4", "32345-32350",
	)

	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}

// Needs to be stopped with Ctrl-C
func TestAWGHandshakeDevicePing(t *testing.T) {
	t.Skip("This test is intended to be run manually, not as part of the test suite.")

	signalContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	isRunning := atomic.NewBool(true)
	go func() {
		<-signalContext.Done()
		fmt.Println("Waiting to finish")
		isRunning.Store(false)
	}()

	goroutineLeakCheck(t)
	pair := genTestPair(t, true,
		"i1", "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>",
		"i2", "<b 0xf6ab3267fa><c><b 0xf6ab><t><rc 10>",
		"i3", "<b 0xf6ab3267fa><c><b 0xf6ab><t><rd 10>",
		"i4", "<b 0xf6ab3267fa><r 100>",
		// "jc", "1",
		// "jmin", "500",
		// "jmax", "1000",
		// "s1", "30",
		// "s2", "40",
		// "h1", "123456",
		// "h2", "67543",
		// "h4", "32345",
		// "h3", "123123",
	)
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		for isRunning.Load() {
			pair.Send(t, Ping, nil)
			time.Sleep(2 * time.Second)
		}
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		for isRunning.Load() {
			pair.Send(t, Pong, nil)
			time.Sleep(2 * time.Second)
		}
	})
}

func TestUpDown(t *testing.T) {
	goroutineLeakCheck(t)
	const itrials = 50
	const otrials = 10

	for n := 0; n < otrials; n++ {
		pair := genTestPair(t, false)
		for i := range pair {
			for k := range pair[i].dev.peers.keyMap {
				pair[i].dev.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=1\n", hex.EncodeToString(k[:])))
			}
		}
		var wg sync.WaitGroup
		wg.Add(len(pair))
		for i := range pair {
			go func(d *Device) {
				defer wg.Done()
				for i := 0; i < itrials; i++ {
					if err := d.Up(); err != nil {
						t.Errorf("failed up bring up device: %v", err)
					}
					time.Sleep(time.Duration(rand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
					if err := d.Down(); err != nil {
						t.Errorf("failed to bring down device: %v", err)
					}
					time.Sleep(time.Duration(rand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
				}
			}(pair[i].dev)
		}
		wg.Wait()
		for i := range pair {
			pair[i].dev.Up()
			pair[i].dev.Close()
		}
	}
}

// TestConcurrencySafety does other things concurrently with tunnel use.
// It is intended to be used with the race detector to catch data races.
func TestConcurrencySafety(t *testing.T) {
	pair := genTestPair(t, true)
	done := make(chan struct{})

	const warmupIters = 10
	var warmup sync.WaitGroup
	warmup.Add(warmupIters)
	go func() {
		// Send data continuously back and forth until we're done.
		// Note that we may continue to attempt to send data
		// even after done is closed.
		i := warmupIters
		for ping := Ping; ; ping = !ping {
			pair.Send(t, ping, done)
			select {
			case <-done:
				return
			default:
			}
			if i > 0 {
				warmup.Done()
				i--
			}
		}
	}()
	warmup.Wait()

	applyCfg := func(cfg string) {
		err := pair[0].dev.IpcSet(cfg)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Change persistent_keepalive_interval concurrently with tunnel use.
	t.Run("persistentKeepaliveInterval", func(t *testing.T) {
		var pub NoisePublicKey
		for key := range pair[0].dev.peers.keyMap {
			pub = key
			break
		}
		cfg := uapiCfg(
			"public_key", hex.EncodeToString(pub[:]),
			"persistent_keepalive_interval", "1",
		)
		for i := 0; i < 1000; i++ {
			applyCfg(cfg)
		}
	})

	// Change private keys concurrently with tunnel use.
	t.Run("privateKey", func(t *testing.T) {
		bad := uapiCfg("private_key", "7777777777777777777777777777777777777777777777777777777777777777")
		good := uapiCfg("private_key", hex.EncodeToString(pair[0].dev.staticIdentity.privateKey[:]))
		// Set iters to a large number like 1000 to flush out data races quickly.
		// Don't leave it large. That can cause logical races
		// in which the handshake is interleaved with key changes
		// such that the private key appears to be unchanging but
		// other state gets reset, which can cause handshake failures like
		// "Received packet with invalid mac1".
		const iters = 1
		for i := 0; i < iters; i++ {
			applyCfg(bad)
			applyCfg(good)
		}
	})

	// Perform bind updates and keepalive sends concurrently with tunnel use.
	t.Run("bindUpdate and keepalive", func(t *testing.T) {
		const iters = 10
		for i := 0; i < iters; i++ {
			for _, peer := range pair {
				peer.dev.BindUpdate()
				peer.dev.SendKeepalivesToPeersWithCurrentKeypair()
			}
		}
	})

	close(done)
}

func BenchmarkLatency(b *testing.B) {
	pair := genTestPair(b, true)

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair.Send(b, Ping, nil)
		pair.Send(b, Pong, nil)
	}
}

func BenchmarkThroughput(b *testing.B) {
	pair := genTestPair(b, true)

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	// Measure how long it takes to receive b.N packets,
	// starting when we receive the first packet.
	var recv atomic.Uint64
	var elapsed time.Duration
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var start time.Time
		for {
			<-pair[0].tun.Inbound
			new := recv.Add(1)
			if new == 1 {
				start = time.Now()
			}
			// Careful! Don't change this to else if; b.N can be equal to 1.
			if new == uint64(b.N) {
				elapsed = time.Since(start)
				return
			}
		}
	}()

	// Send packets as fast as we can until we've received enough.
	ping := tuntest.Ping(pair[0].ip, pair[1].ip)
	pingc := pair[1].tun.Outbound
	var sent uint64
	for recv.Load() != uint64(b.N) {
		sent++
		pingc <- ping
	}
	wg.Wait()

	b.ReportMetric(float64(elapsed)/float64(b.N), "ns/op")
	b.ReportMetric(1-float64(b.N)/float64(sent), "packet-loss")
}

func BenchmarkUAPIGet(b *testing.B) {
	pair := genTestPair(b, true)
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair[0].dev.IpcGetOperation(io.Discard)
	}
}

func goroutineLeakCheck(t *testing.T) {
	goroutines := func() (int, []byte) {
		p := pprof.Lookup("goroutine")
		b := new(bytes.Buffer)
		p.WriteTo(b, 1)
		return p.Count(), b.Bytes()
	}

	startGoroutines, startStacks := goroutines()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		// Give goroutines time to exit, if they need it.
		for i := 0; i < 10000; i++ {
			if runtime.NumGoroutine() <= startGoroutines {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		endGoroutines, endStacks := goroutines()
		t.Logf("starting stacks:\n%s\n", startStacks)
		t.Logf("ending stacks:\n%s\n", endStacks)
		t.Fatalf("expected %d goroutines, got %d, leak?", startGoroutines, endGoroutines)
	})
}

type fakeBindSized struct {
	size int
}

func (b *fakeBindSized) Open(
	port uint16,
) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, 0, nil
}

func (b *fakeBindSized) Close() error { return nil }

func (b *fakeBindSized) SetMark(mark uint32) error { return nil }

func (b *fakeBindSized) Send(bufs [][]byte, ep conn.Endpoint) error { return nil }

func (b *fakeBindSized) ParseEndpoint(s string) (conn.Endpoint, error) { return nil, nil }

func (b *fakeBindSized) BatchSize() int { return b.size }

type fakeTUNDeviceSized struct {
	size int
}

func (t *fakeTUNDeviceSized) File() *os.File { return nil }

func (t *fakeTUNDeviceSized) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	return 0, nil
}

func (t *fakeTUNDeviceSized) Write(bufs [][]byte, offset int) (int, error) { return 0, nil }

func (t *fakeTUNDeviceSized) MTU() (int, error) { return 0, nil }

func (t *fakeTUNDeviceSized) Name() (string, error) { return "", nil }

func (t *fakeTUNDeviceSized) Events() <-chan tun.Event { return nil }

func (t *fakeTUNDeviceSized) Close() error { return nil }

func (t *fakeTUNDeviceSized) BatchSize() int { return t.size }

func TestBatchSize(t *testing.T) {
	d := Device{}

	d.net.bind = &fakeBindSized{1}
	d.tun.device = &fakeTUNDeviceSized{1}
	if want, got := 1, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}

	d.net.bind = &fakeBindSized{1}
	d.tun.device = &fakeTUNDeviceSized{128}
	if want, got := 128, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}

	d.net.bind = &fakeBindSized{128}
	d.tun.device = &fakeTUNDeviceSized{1}
	if want, got := 128, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}

	d.net.bind = &fakeBindSized{128}
	d.tun.device = &fakeTUNDeviceSized{128}
	if want, got := 128, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}
}
