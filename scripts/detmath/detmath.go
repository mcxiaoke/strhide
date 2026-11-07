// Go port of `rust/src/stego/detmath.rs`.
//
// The four functions must produce the same bits as the Rust original and as
// `detmath.py`: only + - * / on float64 plus bit-level frexp/ldexp, same order,
// same term counts. Run it to print the four digests and compare with the
// constants pinned in the Rust test module:
//
//	go run detmath.go
package main

import (
	"fmt"
	"math"
	"os"
)

const (
	ln2Hi = 6.9314718036912382e-1
	ln2Lo = 1.9082149292705877e-10
	invLn2 = 1.4426950408889634

	pio2_1     = 1.5707963267341256
	pio2_2     = 6.077100506303966e-11
	pio2_3     = 2.022266248795951e-21
	twoOverPi  = 0.6366197723675813
	sqrt2      = 1.4142135623730951

	expHi = 709.782712893384
	expLo = -745.1332191019411
)

var expC = [14]float64{
	1.0,
	0.5,
	1.0 / 6.0,
	1.0 / 24.0,
	1.0 / 120.0,
	1.0 / 720.0,
	1.0 / 5040.0,
	1.0 / 40320.0,
	1.0 / 362880.0,
	1.0 / 3628800.0,
	1.0 / 39916800.0,
	1.0 / 479001600.0,
	1.0 / 6227020800.0,
	1.0 / 87178291200.0,
}

var sinC = [8]float64{
	-1.0 / 6.0,
	1.0 / 120.0,
	-1.0 / 5040.0,
	1.0 / 362880.0,
	-1.0 / 39916800.0,
	1.0 / 6227020800.0,
	-1.0 / 1307674368000.0,
	1.0 / 355687428096000.0,
}

var cosC = [8]float64{
	-0.5,
	1.0 / 24.0,
	-1.0 / 720.0,
	1.0 / 40320.0,
	-1.0 / 3628800.0,
	1.0 / 479001600.0,
	-1.0 / 87178291200.0,
	1.0 / 20922789888000.0,
}

func ldexp(y float64, k int32) float64 {
	for k > 1023 {
		y *= math.Float64frombits(0x7FE0000000000000)
		k -= 1023
	}
	for k < -1022 {
		y *= math.Float64frombits(0x0010000000000000)
		k += 1022
	}
	return y * math.Float64frombits(uint64(1023+k)<<52)
}

func frexp(x float64) (float64, int32) {
	bits := math.Float64bits(x)
	exp := int32((bits >> 52) & 0x7FF)
	if exp == 0 {
		if x == 0 {
			return 0, 0
		}
		m, e := frexp(x * math.Float64frombits(0x4350000000000000))
		return m, e - 54
	}
	return math.Float64frombits((bits & 0x800FFFFFFFFFFFFF) | 0x3FE0000000000000), exp - 1022
}

func roundI32(x float64) int32 {
	if x >= 0 {
		return int32(x + 0.5)
	}
	return int32(x - 0.5)
}

func exp(x float64) float64 {
	if math.IsNaN(x) {
		return x
	}
	if x > expHi {
		return math.Inf(1)
	}
	if x < expLo {
		return 0
	}
	k := roundI32(x * invLn2)
	kf := float64(k)
	r := (x - kf*ln2Hi) - kf*ln2Lo

	p := expC[13]
	for i := 12; i > 0; i-- {
		p = expC[i] + r*p
	}
	p = expC[0] + r*p
	return ldexp(1.0+r*p, k)
}

func ln(x float64) float64 {
	if math.IsNaN(x) || x < 0 {
		return math.NaN()
	}
	if x == 0 {
		return math.Inf(-1)
	}
	if math.IsInf(x, 1) {
		return math.Inf(1)
	}
	m, e := frexp(x)
	m *= 2.0
	e--
	if m > sqrt2 {
		m *= 0.5
		e++
	}
	s := (m - 1.0) / (m + 1.0)
	z := s * s
	p := 1.0 / 23.0
	for d := 21.0; d > 1.0; d -= 2.0 {
		p = 1.0/d + z*p
	}
	p = 1.0 + z*p
	lnM := 2.0 * s * p
	ef := float64(e)
	return ef*ln2Hi + (ef*ln2Lo + lnM)
}

func ln1p(x float64) float64 {
	if math.IsNaN(x) || x < -1.0 {
		return math.NaN()
	}
	if x == -1.0 {
		return math.Inf(-1)
	}
	if math.Abs(x) < 0.0625 {
		term := x
		sum := 0.0
		for n := 1.0; n <= 12.0; n += 1.0 {
			if int32(n)&1 == 1 {
				sum += term / n
			} else {
				sum -= term / n
			}
			term *= x
		}
		return sum
	}
	return ln(1.0 + x)
}

func sinSmall(r float64) float64 {
	z := r * r
	p := sinC[len(sinC)-1]
	for i := len(sinC) - 2; i > 0; i-- {
		p = sinC[i] + z*p
	}
	p = sinC[0] + z*p
	return r * (1.0 + z*p)
}

func cosSmall(r float64) float64 {
	z := r * r
	q := cosC[len(cosC)-1]
	for i := len(cosC) - 2; i > 0; i-- {
		q = cosC[i] + z*q
	}
	q = cosC[0] + z*q
	return 1.0 + z*q
}

func cos(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return math.NaN()
	}
	n := roundI32(x * twoOverPi)
	nf := float64(n)
	r := ((x - nf*pio2_1) - nf*pio2_2) - nf*pio2_3
	switch n & 3 {
	case 0:
		return cosSmall(r)
	case 1:
		return -sinSmall(r)
	case 2:
		return -cosSmall(r)
	default:
		return sinSmall(r)
	}
}

func fnv1a(f func(index int) float64, n int) uint64 {
	h := uint64(0xCBF29CE484222325)
	for i := 0; i < n; i++ {
		bits := math.Float64bits(f(i))
		for s := 0; s < 64; s += 8 {
			h ^= (bits >> s) & 0xFF
			h *= 0x00000100000001B3
		}
	}
	return h
}

func digests() [4]uint64 {
	var d [4]uint64

	expInputs := make([]float64, 0, 481+120)
	for i := -240; i <= 240; i++ {
		expInputs = append(expInputs, float64(i)*0.37)
	}
	for i := 0; i < 120; i++ {
		expInputs = append(expInputs, 1e-6*float64(i))
	}
	h := uint64(0xCBF29CE484222325)
	for _, x := range expInputs {
		bits := math.Float64bits(exp(x))
		for s := 0; s < 64; s += 8 {
			h ^= (bits >> s) & 0xFF
			h *= 0x00000100000001B3
		}
	}
	d[0] = h

	d[1] = fnv1a(func(i int) float64 {
		if i < 400 {
			return ln(float64(i+1) * 0.71)
		}
		return ln(1e-12 * float64(i-400+1))
	}, 460)

	idx := 0
	d[2] = fnv1a(func(int) float64 {
		k := idx / 9
		a := idx % 9
		idx++
		return cos(math.Pi * float64(k) * float64(2*a+1) / 18.0)
	}, 81)

	d[3] = fnv1a(func(i int) float64 { return ln1p(float64(i) * 0.003) }, 200)
	return d
}

func main() {
	want := [4]uint64{0x68107BF871D53DF2, 0x6021EF64DB0E27EF, 0x55F3C5ACB971153A, 0x23E6E71DCCF69B20}
	names := [4]string{"exp", "ln", "cos", "ln_1p"}
	got := digests()
	ok := true
	for i, name := range names {
		good := got[i] == want[i]
		ok = ok && good
		verdict := "ok"
		if !good {
			verdict = "MISMATCH"
		}
		fmt.Printf("%-7s %016x %s (rust %016x)\n", name, got[i], verdict, want[i])
	}
	if !ok {
		os.Exit(1)
	}
}
