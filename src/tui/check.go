package tui

import (
	"math"
	"strings"
)

const checkColor = "\x1b[38;5;77m"

// check draws a ✓ in braille dots, revealed along its stroke up to progress (0..1).
func check(progress float64, w, h int) []string {
	pw, ph := w*2, h*4
	size := float64(min(ph, pw)) * 0.8
	cx, cy := float64(pw)/2, float64(ph)/2
	pts := [][2]float64{{-0.45, 0}, {-0.12, 0.33}, {0.5, -0.33}}
	r := max(1, size*0.07)
	grid := make([]bool, pw*ph)
	stamp := func(x, y float64) {
		for dy := -r; dy <= r; dy++ {
			for dx := -r; dx <= r; dx++ {
				col, row := int(math.Round(x+dx)), int(math.Round(y+dy))
				if dx*dx+dy*dy <= r*r && col >= 0 && col < pw && row >= 0 && row < ph {
					grid[row*pw+col] = true
				}
			}
		}
	}
	var total float64
	for i := 1; i < len(pts); i++ {
		total += math.Hypot(pts[i][0]-pts[i-1][0], pts[i][1]-pts[i-1][1]) * size
	}
	left := progress * total
	for i := 1; i < len(pts) && left > 0; i++ {
		a, b := pts[i-1], pts[i]
		l := math.Hypot(b[0]-a[0], b[1]-a[1]) * size
		for t := 0.0; t <= min(l, left); t += 0.5 {
			f := t / l
			stamp(cx+(a[0]+(b[0]-a[0])*f)*size, cy+(a[1]+(b[1]-a[1])*f)*size)
		}
		left -= l
	}

	out := make([]string, h)
	for row := range h {
		var b strings.Builder
		for col := range w {
			var bits rune
			for dy := range 4 {
				for dx := range 2 {
					if grid[(row*4+dy)*pw+col*2+dx] {
						bits |= dotBit[dy][dx]
					}
				}
			}
			if bits == 0 {
				b.WriteByte(' ')
				continue
			}
			b.WriteString(checkColor + string(0x2800+bits) + reset)
		}
		out[row] = b.String()
	}
	return out
}
