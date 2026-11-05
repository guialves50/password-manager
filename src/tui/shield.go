package tui

import (
	"fmt"
	"math"
	"strings"
)

const (
	thickness = 0.14
	bottom    = -1.3
)

var (
	dotBit = [4][2]rune{{0x01, 0x08}, {0x02, 0x10}, {0x04, 0x20}, {0x40, 0x80}}
	bayer  = [4][2]float64{{0, 4}, {6, 2}, {1, 5}, {7, 3}}
)

var light = normalize(-0.5, 0.6, 1)

type cell struct {
	z    float64
	lum  float64
	side bool
}

func halfWidth(v float64) float64 {
	if v >= 0 {
		return 1
	}
	return 1 - (v/bottom)*(v/bottom)
}

func slope(v float64) float64 {
	if v >= 0 {
		return 0
	}
	return -2 * v / (bottom * bottom)
}

func engraved(u, v float64) bool {
	if u*u+(v-0.2)*(v-0.2) < 0.04 {
		return true
	}
	return math.Abs(u) < 0.07+0.1*(0.2-v) && v > -0.5 && v < 0.2
}

func raised(u, v float64) bool {
	return math.Abs(u) > halfWidth(v)-0.16 || v > 0.84
}

func normalize(x, y, z float64) [3]float64 {
	n := math.Sqrt(x*x + y*y + z*z)
	return [3]float64{x / n, y / n, z / n}
}

func shieldRaster(angle float64, w, h int) raster {
	pw, ph := w*2, h*4
	scale := float64(min(h, 22)*4-1) / (1 - bottom)
	if 2*scale+1 > float64(pw) {
		scale = float64(pw-1) / 2
	}
	cx, cy := float64(pw-1)/2, float64(ph-1)/2-(1+bottom)/2*scale
	grid := make([]cell, pw*ph)
	sin, cos := math.Sincos(angle)

	plot := func(x, y, z, nx, ny, nz, shade float64, side bool) {
		rx, rz := x*cos+z*sin, -x*sin+z*cos
		col, row := int(math.Round(cx+rx*scale)), int(math.Round(cy-y*scale))
		if col < 0 || col >= pw || row < 0 || row >= ph {
			return
		}
		c := &grid[row*pw+col]
		if c.lum != 0 && rz <= c.z {
			return
		}
		n := [3]float64{nx*cos + nz*sin, ny, -nx*sin + nz*cos}
		dot := max(0, n[0]*light[0]+n[1]*light[1]+n[2]*light[2])
		*c = cell{z: rz, lum: max(0.01, shade*(0.2+0.8*dot)), side: side}
	}

	step := 0.5 / scale
	for v := bottom; v <= 1; v += step / 2 {
		hw := halfWidth(v)
		for u := -hw; u <= hw; u += step {
			shade := 0.75
			switch {
			case engraved(u, v):
				shade = 0.35
			case raised(u, v):
				shade = 1
			}
			plot(u, v, thickness, 0, 0, 1, shade, false)
			plot(u, v, -thickness, 0, 0, -1, shade, false)
		}
		n := normalize(1, -slope(v), 0)
		for z := -thickness; z <= thickness; z += step {
			plot(hw, v, z, n[0], n[1], 0, 1, true)
			plot(-hw, v, z, -n[0], n[1], 0, 1, true)
		}
	}
	for u := -1.0; u <= 1; u += step {
		for z := -thickness; z <= thickness; z += step {
			plot(u, 1, z, 0, 1, 0, 1, true)
		}
	}

	r := newRaster(w, h)
	for row := range h {
		for col := range w {
			var sum float64
			lit, sides := 0, 0
			var on []int
			for dy := range 4 {
				for dx := range 2 {
					i := (row*4+dy)*pw + col*2 + dx
					c := grid[i]
					if c.lum == 0 {
						continue
					}
					if lit == 0 || c.lum >= (bayer[dy][dx]+0.5)/8*0.8 {
						on = append(on, i)
					}
					lit++
					sum += c.lum
					if c.side {
						sides++
					}
				}
			}
			if lit == 0 {
				continue
			}
			for _, i := range on {
				r.on[i] = true
			}
			lum := sum / float64(lit)
			r.color[row*w+col] = 238 + min(17, int(lum*18))
			if 2*sides > lit {
				r.color[row*w+col] = 67 + 6*min(2, int(lum*3))
			}
		}
	}
	return r
}

func shield(angle float64, w, h int) []string {
	return shieldRaster(angle, w, h).lines()
}

// raster is a braille canvas: on holds the 2x4 dots of every cell, color the
// 256-color index of each cell.
type raster struct {
	w, h  int
	on    []bool
	color []int
}

func newRaster(w, h int) raster {
	return raster{w: w, h: h, on: make([]bool, w*2*h*4), color: make([]int, w*h)}
}

func (r raster) lines() []string {
	pw := r.w * 2
	out := make([]string, r.h)
	for row := range r.h {
		var b strings.Builder
		for col := range r.w {
			var bits rune
			for dy := range 4 {
				for dx := range 2 {
					if r.on[(row*4+dy)*pw+col*2+dx] {
						bits |= dotBit[dy][dx]
					}
				}
			}
			if bits == 0 {
				b.WriteByte(' ')
				continue
			}
			fmt.Fprintf(&b, "\x1b[38;5;%dm%c\x1b[0m", r.color[row*r.w+col], 0x2800+bits)
		}
		out[row] = b.String()
	}
	return out
}
