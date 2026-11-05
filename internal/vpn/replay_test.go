package vpn

import "testing"

func TestReplayFilter(t *testing.T) {
	var f replayFilter
	steps := []struct {
		counter uint64
		want    bool
		why     string
	}{
		{0, true, "premier paquet"},
		{0, false, "rejeu immédiat"},
		{1, true, "suivant"},
		{5, true, "saut en avant (paquets 2-4 perdus ou en retard)"},
		{3, true, "paquet en retard, jamais vu"},
		{3, false, "paquet en retard rejoué"},
		{5, false, "rejeu du plus récent"},
		{replayWindow + 5, true, "grand saut"},
		{6, true, "ancien mais dans la fenêtre, jamais vu"},
		{5, false, "au bord exact de la fenêtre, déjà vu"},
		{4, false, "juste hors de la fenêtre"},
		{2, false, "très ancien"},
		{100000, true, "saut plus grand que toute la fenêtre"},
		{100000 - replayWindow, true, "bord de la nouvelle fenêtre"},
		{replayWindow + 5, false, "ancien compteur, hors fenêtre"},
		{rejectAfterMessages, false, "limite absolue de messages"},
	}
	for _, s := range steps {
		if got := f.accept(s.counter); got != s.want {
			t.Fatalf("%s : accept(%d) = %v, attendu %v", s.why, s.counter, got, s.want)
		}
	}
}

func TestReplayFilterEveryCounterOnce(t *testing.T) {
	var f replayFilter
	// ordre désordonné mais dans la fenêtre : chaque compteur accepté une seule fois
	for base := uint64(0); base < 20000; base += 100 {
		for i := uint64(99); ; i-- {
			if !f.accept(base + i) {
				t.Fatalf("compteur %d refusé à tort", base+i)
			}
			if f.accept(base + i) {
				t.Fatalf("compteur %d accepté deux fois", base+i)
			}
			if i == 0 {
				break
			}
		}
	}
}
