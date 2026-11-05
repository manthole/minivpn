package vpn

// Protection contre le rejeu des paquets de données (méthode de la RFC 6479).
//
// Chaque paquet porte un compteur qui augmente de 1 à chaque envoi. Le récepteur retient
// le plus grand compteur vu et, dans une fenêtre glissante, les compteurs déjà acceptés.
// UDP peut perdre ou désordonner les paquets : on accepte donc un compteur plus petit que
// le maximum, à condition qu'il soit dans la fenêtre et jamais vu. Un attaquant qui
// renvoie un paquet capturé est rejeté, même si le paquet est parfaitement authentique.
//
// À n'appeler qu'APRÈS avoir vérifié l'authenticité du paquet : sinon un attaquant
// pourrait faire avancer la fenêtre avec des compteurs inventés et bloquer le trafic.

const (
	replayBlockBits = 64
	replayBlocks    = 32                                   // 32 × 64 = 2048 bits
	replayWindow    = (replayBlocks - 1) * replayBlockBits // 1984 paquets de tolérance
)

type replayFilter struct {
	last uint64
	ring [replayBlocks]uint64
}

// accept renvoie true si le compteur est nouveau, et l'enregistre.
func (f *replayFilter) accept(counter uint64) bool {
	if counter >= rejectAfterMessages {
		return false
	}
	block := counter / replayBlockBits
	if counter > f.last {
		// on avance la fenêtre : les blocs qui en sortent sont remis à zéro
		current := f.last / replayBlockBits
		diff := block - current
		if diff > replayBlocks {
			diff = replayBlocks
		}
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i%replayBlocks] = 0
		}
		f.last = counter
	} else if f.last-counter > replayWindow {
		return false // trop ancien : hors de la fenêtre
	}
	bit := uint64(1) << (counter % replayBlockBits)
	w := &f.ring[block%replayBlocks]
	if *w&bit != 0 {
		return false // déjà vu : rejeu
	}
	*w |= bit
	return true
}
