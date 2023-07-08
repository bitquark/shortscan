package maths

// This seems unnecessary
func Min(a, b int) int {
	if a <= b {
		return a
	} else {
		return b
	}
}

// ... and this
func Max(a, b int) int {
	if a >= b {
		return a
	} else {
		return b
	}
}

// ... yeah
func MaxFloat32(a, b float32) float32 {
	if a >= b {
		return a
	} else {
		return b
	}
}
