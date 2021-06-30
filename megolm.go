package main

import (
	"fmt"
)

const (
	SHA256_BLOCK_LENGTH        = 64
	SHA256_OUTPUT_LENGTH       = 32
	MEGOLM_RATCHET_PART_LENGTH = 32
	MEGOLM_RATCHET_PARTS       = 4
	MEGOLM_RATCHET_LENGTH      = (MEGOLM_RATCHET_PARTS * MEGOLM_RATCHET_PART_LENGTH)
	OLM_PROTOCOL_VERSION       = 3
)

var HASH_KEY_SEEDS = [MEGOLM_RATCHET_PARTS]byte{0x00, 0x01, 0x02, 0x03}

type Megolm struct {
	data    [][]byte
	counter int
}

func NewMegolm(initialData []byte, initialCounter int) (*Megolm, error) {
	if len(initialData) != MEGOLM_RATCHET_LENGTH {
		return nil, fmt.Errorf("megolm initial data must be %d bytes. Got %d.", MEGOLM_RATCHET_LENGTH, len(initialData))
	}

	data := make([][]byte, MEGOLM_RATCHET_PARTS)
	for i := 0; i < MEGOLM_RATCHET_PARTS; i++ {
		data[i] = make([]byte, MEGOLM_RATCHET_PART_LENGTH)
		start := i * MEGOLM_RATCHET_PART_LENGTH
		copy(data[i], initialData[start:start+MEGOLM_RATCHET_PART_LENGTH])
	}

	return &Megolm{
		data:    data,
		counter: initialCounter,
	}, nil
}

func (m *Megolm) Data() []byte {
	data := make([]byte, MEGOLM_RATCHET_LENGTH)
	for i := 0; i < MEGOLM_RATCHET_PARTS; i++ {
		start := i * MEGOLM_RATCHET_PART_LENGTH
		copy(data[start:start+MEGOLM_RATCHET_PART_LENGTH], m.data[i])
	}

	return data
}

func (m *Megolm) Advance() {
	mask := 0x00FFFFFF
	h := 0
	m.counter++

	/* figure out how much we need to rekey */
	for h < MEGOLM_RATCHET_PARTS {
		if m.counter&mask == 0 {
			break
		}

		h++
		mask >>= 8
	}

	// update R[h:3] based on h
	for i := MEGOLM_RATCHET_PARTS - 1; i >= h; i-- {
		m.rehashPart(h, i)
	}
}

func (m *Megolm) AdvanceTo(advanceTo int) {
	/* starting with R0, see if we need to update each part of the hash */
	for j := 0; j < MEGOLM_RATCHET_PARTS; j++ {
		shift := (MEGOLM_RATCHET_PARTS - j - 1) * 8
		mask := 0xffffffff << shift

		/* how many times do we need to rehash this part?
		 *
		 * '& 0xff' ensures we handle integer wraparound correctly
		 */
		steps :=
			((advanceTo >> shift) - (m.counter >> shift)) & 0xff

		if steps == 0 {
			/* deal with the edge case where megolm->counter is slightly larger
			 * than advanceTo. This should only happen for R(0), and implies
			 * that advanceTo has wrapped around and we need to advance R(0)
			 * 256 times.
			 */
			if advanceTo < m.counter {
				steps = 0x100
			} else {
				continue
			}
		}

		/* for all but the last step, we can just bump R(j) without regard
		 * to R(j+1)...R(3).
		 */
		for steps > 1 {
			m.rehashPart(j, j)
			steps--
		}

		/* on the last step we also need to bump R(j+1)...R(3).
		 *
		 * (Theoretically, we could skip bumping R(j+2) if we're going to bump
		 * R(j+1) again, but the code to figure that out is a bit baroque and
		 * doesn't save us much).
		 */
		for k := 3; k >= j; k-- {
			m.rehashPart(j, k)
		}
		m.counter = advanceTo & mask
	}
}

func (m *Megolm) rehashPart(fromPart, toPart int) {
	newPart := HMACSHA256(
		m.data[fromPart],
		[]byte{HASH_KEY_SEEDS[toPart]},
	)
	m.data[toPart] = newPart
}
