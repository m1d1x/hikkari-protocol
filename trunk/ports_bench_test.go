package trunk

import (
	"testing"
)

// benchFull fills the book the way the entry's did on 12.11: 11457 of 12768
// ports dead, a pool's worth in use, and measures one Take and release.
func benchFull(b *testing.B, dead int) {
	book, err := NewPortBook(20000, 32767, DefaultDeadFor)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < dead; i++ {
		book.Dead(20000 + i)
	}
	var held []func()
	for i := 0; i < 32; i++ {
		_, release, err := book.Take()
		if err != nil {
			b.Fatal(err)
		}
		held = append(held, release)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, release, err := book.Take()
		if err != nil {
			b.Fatal(err)
		}
		release()
	}
	b.StopTimer()
	for _, r := range held {
		r()
	}
}

func BenchmarkPortBookTakeEmpty(b *testing.B) { benchFull(b, 0) }
func BenchmarkPortBookTakeFull(b *testing.B)  { benchFull(b, 11457) }
