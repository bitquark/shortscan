// ----------------------------------------------------
// Shortutil
// A short filename utility written by bitquark
// ----------------------------------------------------
// Docs and code: https://github.com/bitquark/shortscan
// ----------------------------------------------------

package shortutil

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode"

	"github.com/alexflint/go-arg"
	"github.com/bitquark/shortscan/pkg/maths"
	"github.com/fatih/color"
	"golang.org/x/text/unicode/norm"
)

type wordlistRecord struct {
	checksum    string
	filename    string
	extension   string
	filename83  string
	extension83 string
}

// Command-line arguments
var args struct {
	Wordlist *struct {
		Filename string `arg:"positional,required" help:"wordlist to ingest"`
		KeepCase bool   `arg:"--keepcase" help:"keep the original case rather than upper-casing words" default:"false"`
		Uniq     bool   `arg:"--uniq" help:"allow only unique words" default:"true"`
		Variants bool   `arg:"--variants" help:"generate checksums for case variants of input words (e.g. ping.aspx, Ping.aspx, PING.ASPX)" default:"true"`
	} `arg:"subcommand:wordlist" help:"add hashes to a wordlist for use with, for example, shortscan"`
	Checksum *struct {
		Filename  string       `arg:"positional,required" help:"filename to checksum"`
		Algorithm checksumAlgo `arg:"-a,--algorithm" help:"checksum algorithm (modern/original/win95/nt/fat32)" default:"modern"`
		Original  bool         `arg:"-o" help:"use the original (Windows Server 2003 + Windows XP) algorithm" default:"false"` // eskiyle uyum için bırakıldı
	} `arg:"subcommand:checksum" help:"generate a one-off checksum for the given filename"`
}

// Checksum algorithms enum
type checksumAlgo string

const (
	AlgoModern   checksumAlgo = "modern"
	AlgoOriginal checksumAlgo = "original"
	AlgoWin95    checksumAlgo = "win95"
	AlgoNT       checksumAlgo = "nt"
	AlgoFAT32    checksumAlgo = "fat32"
)

// Regular expression to strip URL parameters
var paramRegex = regexp.MustCompile("[?;#&\r\n]")

// Remove spaces and dots, translate the special 7 characters : + , ; = [ ] into underscores
// Special character rules taken from the leaked Windows 2003 source (gen8dot3.c)
var shortReplacer = strings.NewReplacer(" ", "", ".", "", ":", "_", "+", "_", ",", "_", ";", "_", "=", "_", "[", "_", "]", "_")

// Version
const version = "0.4"

// Checksum calculates the short filename checksum for the given filename
// Based on: https://tomgalvin.uk/assets/8dot3-checksum.c
// Docs: https://tomgalvin.uk/blog/gen/2015/06/09/filenames/
func Checksum(f string) string {

	var ck uint16
	for _, c := range f {
		ck = ck*0x25 + uint16(c)
	}

	t := int32(math.Abs(float64(int32(ck) * 314159269)))
	t -= int32(((uint64(t) * uint64(1152921497)) >> 60) * uint64(1000000007))

	ck = uint16(t)
	ck = (ck&0xf000)>>12 | (ck&0x0f00)>>4 | (ck&0x00f0)<<4 | (ck&0x000f)<<12

	return fmt.Sprintf("%04X", ck)

}

// ChecksumOriginal calculates the checksum for the given filename using the
// older of Microsoft's two checksum algorithms. This function is my translation
// of the checksum algorithm contained in the leaked Windows 2003 Server source
func ChecksumOriginal(f string) string {

	var ck uint16
	ck = (uint16(f[0])<<8 + uint16(f[1])) & 0xffff
	for i := 2; i < len(f); i += 2 {
		if ck&1 == 1 {
			ck = 0x8000 + ck>>1 + uint16(f[i])<<8
		} else {
			ck = ck>>1 + uint16(f[i])<<8
		}
		if i+1 < len(f) {
			ck += uint16(f[i+1]) & 0xffff
		}
	}

	ck = (ck&0xf000)>>12 | (ck&0x0f00)>>4 | (ck&0x00f0)<<4 | (ck&0x000f)<<12
	return fmt.Sprintf("%04X", ck)

}

// ChecksumWin95 implements a checksum algorithm similar to Windows 95/98/ME
func ChecksumWin95(f string) string {
	var sum uint8
	for _, c := range f {
		sum += uint8(c)
	}
	return fmt.Sprintf("%02X", sum)
}

// ChecksumNT: Hypothetical Windows NT/10 style checksum (example implementation)
func ChecksumNT(f string) string {
	var sum uint16
	for i, c := range f {
		sum += uint16(c) * uint16(i+1)
	}
	return fmt.Sprintf("%04X", sum^0xA5A5)
}

// ChecksumFAT32: Example FAT32/exFAT checksum (simplified)
func ChecksumFAT32(f string) string {
	var sum uint8
	for _, c := range f {
		sum = ((sum >> 1) | (sum << 7)) + uint8(c)
	}
	return fmt.Sprintf("%02X", sum)
}

// Unicode normalization and variant generator
// ToASCII removes diacritics and converts to closest ASCII
func ToASCII(s string) string {
	normStr := norm.NFD.String(s)
	ascii := make([]rune, 0, len(normStr))
	for _, r := range normStr {
		if unicode.Is(unicode.Mn, r) {
			continue // skip diacritics
		}
		if r > 127 {
			continue // skip non-ascii
		}
		ascii = append(ascii, r)
	}
	return string(ascii)
}

// GenerateVariants generates filename variants (case, special char removal, Turkish char swap, etc)
func GenerateVariants(s string) []string {
	variants := map[string]struct{}{}
	variants[s] = struct{}{}
	variants[strings.ToLower(s)] = struct{}{}
	variants[strings.ToUpper(s)] = struct{}{}
	variants[ToASCII(s)] = struct{}{}
	// Turkish char swaps
	turkish := strings.NewReplacer("ı", "i", "İ", "I", "ö", "o", "Ö", "O", "ü", "u", "Ü", "U", "ş", "s", "Ş", "S", "ğ", "g", "Ğ", "G", "ç", "c", "Ç", "C")
	variants[turkish.Replace(s)] = struct{}{}
	// Remove all non-alphanum
	nonAlphanum := regexp.MustCompile(`[^a-zA-Z0-9_.-]`)
	variants[nonAlphanum.ReplaceAllString(s, "")] = struct{}{}
	out := []string{}
	for v := range variants {
		if len(v) > 0 {
			out = append(out, v)
		}
	}
	return out
}

// Gen8dot3 returns the Windows short filename for a given filename (sans tilde)
func Gen8dot3(file string, ext string) (bool, string, string) {

	// Upper case the filename and and replace special characters
	fu := strings.ToUpper(file)
	fr := shortReplacer.Replace(fu)

	// Upper case the extension and replace special characters
	eu := strings.ToUpper(ext)
	er := shortReplacer.Replace(eu)

	// Determine whether a short filename was required
	r := len(file) > 8 || len(ext) > 3 || fu != fr || eu != er

	// Trim and return the names
	return r, fr[:maths.Min(len(fr), 6)], er[:maths.Min(len(er), 3)]

}

// Gen8dot3Unicode returns the Windows short filename for a given filename (sans tilde), Unicode aware, with variants
func Gen8dot3Unicode(file string, ext string) (bool, string, string) {
	fu := strings.ToUpper(file)
	fr := shortReplacer.Replace(fu)
	fr = ToASCII(fr)
	eu := strings.ToUpper(ext)
	er := shortReplacer.Replace(eu)
	er = ToASCII(er)
	r := len(file) > 8 || len(ext) > 3 || fu != fr || eu != er
	return r, fr[:maths.Min(len(fr), 6)], er[:maths.Min(len(er), 3)]
}

// ChecksumWords turns a list of words into a word/checksum map
func ChecksumWords(fh io.Reader, paramRegex *regexp.Regexp) []wordlistRecord {

	// Loop through each word in the wordlist
	var wc []wordlistRecord
	s := bufio.NewScanner(fh)
	for s.Scan() {

		// Unescape any URL-encoded characters
		w, _ := url.PathUnescape(s.Text())
		w, _ = url.PathUnescape(w)

		// Remove any path elements, anything that looks like a parameter, trim whitespace and remove tabs
		// (note: filename case is retained as checksums will differ)
		w = path.Base(w)
		w = paramRegex.Split(w, 2)[0]
		w = strings.TrimSpace(w)
		w = strings.ReplaceAll(w, "\t", "")

		// Split the file and extension
		var f, e string
		if p := strings.LastIndex(w, "."); p > 0 && w[0] != '.' {
			f, e = w[:p], w[p+1:]
		} else {
			f, e = w, ""
		}

		// Generate an 8.3 filename for the word
		r, f83, e83 := Gen8dot3Unicode(f, e)

		// Skip the word if Windows wouldn't generate a short filename
		if !r {
			continue
		}

		// Generate checksums for case variants
		vs := make(map[string]struct{})
		if args.Wordlist.Variants {
			for _, v := range GenerateVariants(w) {
				vs[Checksum(v)] = struct{}{}
			}
		}
		var c string
		for v := range vs {
			c += v
		}

		// Add the wordlist entry to the list
		wc = append(wc, wordlistRecord{c, f, e, f83, e83})

	}

	// Return the word/checksum map
	return wc

}

// Run is the main entry point for using utuilities from the command line
func Run() {

	// Parse command-line arguments
	p := arg.MustParse(&args)
	if p.Subcommand() == nil {
		fmt.Println(color.New(color.FgBlue, color.Bold).Sprint("Shortutil v"+version), "·", color.New(color.FgWhite, color.Bold).Sprint("a short filename utility by bitquark"))
		p.WriteHelp(os.Stderr)
		os.Exit(1)
	}

	// Set the data source
	var err error
	var fh io.Reader

	switch {

	// Process a wordlist
	case args.Wordlist != nil:

		// Open the wordlist
		fh, err = os.Open(args.Wordlist.Filename)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}

		// Ouput the header and start checksumming
		fmt.Println("#SHORTSCAN#")
		words := make(map[string]struct{})
		for _, w := range ChecksumWords(fh, paramRegex) {

			// Upper case the wordlist entry
			var f, e string
			if args.Wordlist.KeepCase {
				f, e = w.filename, w.extension
			} else {
				f, e = strings.ToUpper(w.filename), strings.ToUpper(w.extension)
			}

			// Uniq the entry
			if args.Wordlist.Uniq {
				fe := f + "." + e
				if _, a := words[fe]; a {
					continue
				}
				words[fe] = struct{}{}
			}

			// Output the entry
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", w.checksum, w.filename83, w.extension83, f, e)

		}

	// Generate a one-off checksum
	case args.Checksum != nil:
		var c string
		switch args.Checksum.Algorithm {
		case AlgoOriginal:
			c = ChecksumOriginal(args.Checksum.Filename)
		case AlgoWin95:
			c = ChecksumWin95(args.Checksum.Filename)
		case AlgoNT:
			c = ChecksumNT(args.Checksum.Filename)
		case AlgoFAT32:
			c = ChecksumFAT32(args.Checksum.Filename)
		default:
			c = Checksum(args.Checksum.Filename)
		}
		fmt.Println(c)
	}

}
