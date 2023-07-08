package levenshtein

import (
        "unicode/utf8"
	"github.com/bitquark/shortscan/pkg/maths"
)

// Distance returns the Levenshtein edit distance for two strings
// Borrowed from: https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Levenshtein_distance#Go
func Distance(a, b string) int {

	f := make([]int, utf8.RuneCountInString(b)+1)

	for j := range f {
		f[j] = j
	}

	for _, ca := range a {
		j := 1
		fj1 := f[0]
		f[0]++
		for _, cb := range b {
			mn := maths.Min(f[j]+1, f[j-1]+1)
			if cb != ca {
				mn = maths.Min(mn, fj1+1)
			} else {
				mn = maths.Min(mn, fj1)
			}

			fj1, f[j] = f[j], mn
			j++
		}
	}

	return f[len(f)-1]

}
