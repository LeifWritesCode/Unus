package unus

import "time"

var (
	goflake *_goflake = newGoflake()
)

type _goflake struct {
	epoch    time.Time
	sequence int64
	ticker   *time.Ticker
}

func newGoflake() *_goflake {
	goflake := &_goflake{
		epoch:    time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		sequence: 0,
	}

	ticker := time.NewTicker(time.Second)
	go func() {
		for range ticker.C {
			goflake.sequence = 0
		}
	}()

	goflake.ticker = ticker
	return goflake
}

// returns a simple snowflake where the top 44 bits are time and lower 20 are
// sequence
func (g *_goflake) Next() int64 {
	current_time := time.Now().UTC()
	diff := current_time.Sub(g.epoch)

	time_bits := diff.Milliseconds() << 20
	return time_bits + g.sequence
}

// stops the snowflake ticking
func (g *_goflake) Dispose() {
	g.ticker.Stop()
}
