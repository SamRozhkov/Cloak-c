// Measures the growth rate of Go Cloak's replay cache, which is the
// structure ours was sized against and the one reference bug #12 is
// about.
//
// WHAT IT MODELS, and why the model is the real thing. Upstream's cache
// is one field:
//
//	UsedRandom map[[32]byte]int64          (internal/server/state.go:47)
//
// written by registerRandom (state.go:227-232) from AuthFirstPacket
// (internal/server/auth.go:76) -- BEFORE the UID is authorised, as that
// function's own doc comment says ("It doesn't check if the user is
// authorised"). Nothing bounds it. The only thing that ever removes an
// entry is UsedRandomCleaner (state.go:214-225), which is
// `for { time.Sleep(replayCacheAgeLimit); ... }` with
// replayCacheAgeLimit = 12 * time.Hour (state.go:211) -- the sleep comes
// FIRST, so for the first twelve hours of a server's life nothing is
// deleted at all.
//
// So the growth rate is the per-entry cost of exactly this map type, and
// that is what this program measures: insert N distinct 32-byte keys,
// sample the heap, fit bytes per entry. No part of Cloak is imported,
// because no part of Cloak is involved -- the type is the whole
// mechanism.
//
//	go run ./tools/soak/go_replay_growth -n 4000000
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"runtime"
)

func main() {
	n := flag.Int("n", 4000000, "entries to insert")
	step := flag.Int("step", 250000, "sample every this many inserts")
	flag.Parse()

	m := map[[32]byte]int64{}
	var ms runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	fmt.Println("entries,heap_alloc,heap_sys,delta_per_entry")

	var k [32]byte
	for i := 0; i < *n; i++ {
		// Distinct keys, spread across the whole 32 bytes so the map's
		// hashing sees the same kind of input a real random field is.
		binary.LittleEndian.PutUint64(k[0:], uint64(i))
		binary.LittleEndian.PutUint64(k[8:], uint64(i)*0x9e3779b97f4a7c15)
		binary.LittleEndian.PutUint64(k[16:], ^uint64(i))
		binary.LittleEndian.PutUint64(k[24:], uint64(i)<<17)
		m[k] = int64(i)
		if (i+1)%*step == 0 {
			runtime.GC()
			runtime.ReadMemStats(&ms)
			per := float64(ms.HeapAlloc-base) / float64(i+1)
			fmt.Printf("%d,%d,%d,%.2f\n", i+1, ms.HeapAlloc, ms.HeapSys, per)
		}
	}
	// Keep the map alive past the last sample.
	if len(m) != *n {
		fmt.Println("# unexpected len", len(m))
	}
}
