package tui

import (
	"math"
	"sort"
	"time"
)

const (
	checkColor = "\x1b[38;5;77m"
	green      = 77

	drawEnd    = 700 * time.Millisecond  // stroke drawn, easing out
	popEnd     = 1100 * time.Millisecond // grows and settles back
	ringEnd    = 1400 * time.Millisecond // ring of dots spreads and fades
	morphStart = 2200 * time.Millisecond // dots start flying to the shield
)

// confirmation is the frame el into the ✓ animation; at checkShow it is
// exactly the shield at angle, so the TUI can hand over without a jump.
func confirmation(el time.Duration, angle float64, w, h int) []string {
	frac := func(a, b time.Duration) float64 { return min(1, max(0, float64(el-a)/float64(b-a))) }
	draw := 1 - math.Pow(1-frac(0, drawEnd), 3)
	r := checkRaster(draw, 1+0.18*math.Sin(math.Pi*frac(drawEnd, popEnd)), w, h)
	if el > drawEnd && el < ringEnd {
		ring(r, frac(drawEnd, ringEnd))
	}
	if el >= morphStart {
		r = morph(r, shieldRaster(angle, w, h), frac(morphStart, checkShow))
	}
	return r.lines()
}

func checkSize(w, h int) (size, cx, cy float64) {
	return float64(min(h*4, w*2)) * 0.8, float64(w), float64(h * 2)
}

// checkRaster draws the ✓ stroke revealed up to progress (0..1), scaled by scale.
func checkRaster(progress, scale float64, w, h int) raster {
	out := newRaster(w, h)
	pw, ph := w*2, h*4
	size, cx, cy := checkSize(w, h)
	size *= scale
	pts := [][2]float64{{-0.45, 0}, {-0.12, 0.33}, {0.5, -0.33}}
	rad := max(1, size*0.07)
	stamp := func(x, y float64) {
		for dy := -rad; dy <= rad; dy++ {
			for dx := -rad; dx <= rad; dx++ {
				col, row := int(math.Round(x+dx)), int(math.Round(y+dy))
				if dx*dx+dy*dy <= rad*rad && col >= 0 && col < pw && row >= 0 && row < ph {
					out.set(col, row, green)
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
	return out
}

func (r raster) set(col, row, color int) {
	r.on[row*r.w*2+col] = true
	r.color[(row/4)*r.w+col/2] = color
}

// ring adds a circle of dots that grows from the ✓ outward and thins out as p → 1.
func ring(r raster, p float64) {
	size, cx, cy := checkSize(r.w, r.h)
	rad := size * (0.35 + 0.4*p)
	n := int(2 * math.Pi * rad)
	for i := range n {
		if float64(i%8)/8 >= 1-p {
			continue
		}
		a := 2 * math.Pi * float64(i) / float64(n)
		col, row := int(math.Round(cx+rad*math.Cos(a))), int(math.Round(cy+rad*math.Sin(a)))
		if col >= 0 && col < r.w*2 && row >= 0 && row < r.h*4 {
			r.set(col, row, green)
		}
	}
}

// morph flies every dot of src to a dot of dst. Dots are paired in polar
// order around the center and start staggered, so the ✓ swirls into the
// shield; at t = 1 the result is exactly dst.
func morph(src, dst raster, t float64) raster {
	a, b := points(src), points(dst)
	if len(a) == 0 || len(b) == 0 {
		return dst
	}
	n := max(len(a), len(b))
	out := newRaster(dst.w, dst.h)
	arrived, total := make([]int, len(out.color)), make([]int, len(out.color))
	from := make([]int, len(out.color))
	for k := range n {
		pa, pb := a[k*len(a)/n], b[k*len(b)/n]
		p := min(1, max(0, (t-0.35*float64(k)/float64(n))/0.65))
		p = p * p * (3 - 2*p)
		col := int(math.Round(pa[0] + (pb[0]-pa[0])*p))
		row := int(math.Round(pa[1] + (pb[1]-pa[1])*p))
		out.on[row*out.w*2+col] = true
		cell := (row/4)*out.w + col/2
		total[cell]++
		if p >= 0.5 {
			arrived[cell]++
		}
		from[cell] = src.color[(int(pa[1])/4)*src.w+int(pa[0])/2]
	}
	for i := range out.color {
		out.color[i] = from[i]
		if 2*arrived[i] >= total[i] && dst.color[i] != 0 {
			out.color[i] = dst.color[i]
		}
	}
	return out
}

func points(r raster) [][2]float64 {
	var out [][2]float64
	pw := r.w * 2
	for i, on := range r.on {
		if on {
			out = append(out, [2]float64{float64(i % pw), float64(i / pw)})
		}
	}
	cx, cy := float64(pw)/2, float64(r.h*2)
	sort.SliceStable(out, func(i, j int) bool {
		return math.Atan2(out[i][1]-cy, out[i][0]-cx) < math.Atan2(out[j][1]-cy, out[j][0]-cx)
	})
	return out
}
