package main

import (
	"os"
	"io"
	"log"
	"fmt"
	"flag"
	"time"
	"sync"
	"bufio"
	"errors"
	"strings"
	"strconv"
	nurl "net/url"
	"net/http"
	"os/signal"
	"crypto/tls"
	"text/tabwriter"
)

// =======================================
// wordlist generation structs and methods
// =======================================
type Wordlist struct {
	chunks [][]string
	numberOfChunks int
	totalWords int
}

// read lines from a file into []string
func (w *Wordlist) read(path string) ([]string, error) {
	var lines []string
	file, err := os.Open(path)
	if err != nil {
		return lines, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lines = append(lines, line)
	}

	return lines, nil
}

// remove duplicate values from []string
func (w *Wordlist) unique(wordlist []string) []string {
	keys := make(map[string]bool)
	uniques := []string{}
	for _, word := range wordlist {
		if !keys[word] {
			keys[word] = true
			uniques = append(uniques, word)
		}
	}

	return uniques
}

// split []string into [][]string according to int
func (w *Wordlist) chunk(wordlist []string, numberOfChunks int) [][]string {
	if numberOfChunks == 1 {
		return [][]string{wordlist}
	}

	var chunks [][]string
	for i := 0; i < numberOfChunks; i++ {
		start := (i * len(wordlist)) / numberOfChunks
		stop  := ((i + 1) * len(wordlist)) / numberOfChunks
		chunks = append(chunks, wordlist[start:stop])
	}

	return chunks
}

// read lines from file into current wordlist without duplicates
func (w *Wordlist) Load(path string) error {
	var wordlist []string // join [][]string into []string
	for _, chunk := range w.chunks {
		for _, word := range chunk {
			wordlist = append(wordlist, word)
		}
	}

	words, err := w.read(path)
	if err != nil {
		return err
	}

	for _, word := range words {
		wordlist = append(wordlist, word)
	}

	wordlist = w.unique(wordlist)
	w.totalWords = len(wordlist)
	w.chunks = w.chunk(wordlist, w.numberOfChunks)
	return nil
}

// append extensions to each word in the current wordlist
func (w *Wordlist) Extend(extensions []string) {
	var wordlist []string
	for _, chunk := range w.chunks {
		for _, word := range chunk {
			for _, ext := range extensions {
				wordlist = append(wordlist, word + "." + ext)
			}

			// dont forget to include the original word
			wordlist = append(wordlist, word)
		}
	}

	wordlist = w.unique(wordlist)
	w.totalWords = len(wordlist)
	w.chunks = w.chunk(wordlist, w.numberOfChunks)
	return 
}

// ==================================
// content fuzzer structs and methods
// ==================================

// Fuzzer consists of a worker pool and manager routine
// worker routines:
// 1. are assigned a chunk of the wordlist
// 2. take URL input from a channel
// 3. perform and evaluate HTTP responses
//
// manager routine:
// 1. starts and stops the workers
// 2. sends URL input to a channel
// 3. removes URLs from the list
// 4. coordinates progress bar

// struct to house Fuzzer data and methods
// includes thread safety measures
// https://gobyexample.com/waitgroups
// https://medium.com/bootdotdev/golang-mutexes-what-is-rwmutex-for-5360ab082626
type Fuzzer struct {
	urls []string
	wordlist Wordlist
	threads int
	timeout int // seconds
	delay int // milliseconds
	output string
	handle *os.File
	positiveCodes []int
	negativeCodes []int
	ignoredSizes []int
	recursive bool
	useragent string
	method string
	headers map[string]string
	cookies map[string]string
	tlsVerify bool
	basicAuth bool
	basicAuthUsername string
	basicAuthPassword string
	proxy func(*http.Request) (*nurl.URL, error)
	showProgress bool
	client http.Client
	wg sync.WaitGroup
	mu sync.RWMutex
	totalURLs int
	requestsSent int
	progressMu sync.RWMutex
}

type Result struct {
	url      string
	word     string
	size     int
	response *http.Response
}

// ====================================
// fuzzer methods to handle HTTP probes
// ====================================

// add slash to the end of a given string if needed
func (f *Fuzzer) addSlash(s string) string {
	if s == "" {
		return "/"
	} else if string(s[len(s)-1]) == "/" {
		return s
	} else {
		return s + "/"
	}
}

// build HTTP request
func (f *Fuzzer) buildRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(f.method, url, nil)
	if err != nil {
		return nil, err
	}

	if f.basicAuth {
		req.SetBasicAuth(f.basicAuthUsername, f.basicAuthPassword)
	}

	if f.useragent != "" {
		req.Header.Set("User-Agent", f.useragent)
	}

	for name, value := range f.headers {
		req.Header.Set(name, value)
	}

	for name, value := range f.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	return req, nil
}

// probe given URL + word against target webserver
func (f *Fuzzer) probe(url, word string) (Result, error) {
	// add to f.requestsSent safely
	f.progressMu.Lock()
	f.requestsSent++
	f.progressMu.Unlock()

	var result Result
	req, err := f.buildRequest(url + word)
	if err != nil {
		return result, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return result, err
	}

	// response body must be properly closed
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	resp.Body.Close()

	result = Result{
		url: url,
		word: word,
		size: len(body),
		response: resp,
	}
	return result, nil
}

// check if status code matches positive/negative code lists
func (f *Fuzzer) checkStatusCode(result Result) bool {
	// negative codes take precedence over positive codes
	for _, i := range(f.negativeCodes) {
		if result.response.StatusCode == i {
			return false
		}
	}

	for _, i := range(f.positiveCodes) {
		if result.response.StatusCode == i {
			return true
		}
	}

	return false
}

// check if content length matches ignored sizes list
func (f *Fuzzer) checkSize(result Result) bool {
	for _, i := range(f.ignoredSizes) {
		if result.size == i {
			return true
		}
	}

	return false
}

// check if Location header matches current word
// Location header used to detect directories
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Location
func (f *Fuzzer) checkLocationHeader(result Result) bool {
	locationHeader := result.response.Header.Get("Location")
	if locationHeader == "" {
		return false
	}

	locationSplit := strings.Split(locationHeader, "/")
	if len(locationSplit) < 2 {
                return false
        }
	
	location := locationSplit[len(locationSplit)-2] // second to last element
	if f.addSlash(location) == f.addSlash(result.word) {
		return true
	} else {
		return false
	}
}

// check if directory is listable
// creates disposable HTTP client to follow redirects
func (f *Fuzzer) checkListable(result Result) (bool, error) {
	transport := &http.Transport{
			TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
			},
			Proxy: f.proxy,
	}

	client := http.Client{
			Timeout:        time.Duration(f.timeout) * time.Second,
			Transport:      transport,
	}

	req, err := f.buildRequest(result.url + result.word)
	if err != nil {
			return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
			return false, err
	}

	// response body must be properly closed
	body, err := io.ReadAll(resp.Body)
	if err != nil {
			return false, err
	}
	defer resp.Body.Close()

	bodyStr := string(body)
	if strings.Contains(bodyStr, "Parent Directory") || strings.Contains(bodyStr, "Up To ") || strings.Contains(bodyStr, "Directory Listing For") {
			return true, nil
	} else {
			return false, nil
	}
}

// call check functions and log findings
func (f *Fuzzer) evaluate(result Result) {
	if !f.checkStatusCode(result) || f.checkSize(result) {
		return
	}

	if !f.checkLocationHeader(result) {
		log.Printf("[+] [CODE:%d] [SIZE:%d] %s%s", result.response.StatusCode, result.size, result.url, result.word)
		return
	}

	listable, err := f.checkListable(result)
	if err != nil {
		log.Printf("[!] [ERROR] %s", err.Error())
		return
	}

	if listable {
		log.Printf("[+] [CODE:%d] [SIZE:%d] %s%s <-- LISTABLE DIRECTORY", result.response.StatusCode, result.size, result.url, result.word)
		return
	} else {
		log.Printf("[+] [CODE:%d] [SIZE:%d] %s%s <-- DIRECTORY", result.response.StatusCode, result.size, result.url, result.word)
	}

	if f.recursive {
		// append to f.urls and add to f.totalURLs safely
		f.mu.Lock()
		f.urls = append(f.urls, f.addSlash(result.url + result.word))
		f.mu.Unlock()

		f.progressMu.Lock()
		f.totalURLs++
		f.progressMu.Unlock()
	}

	return
}

// ============================================
// fuzzer methods to handle workers and manager
// ============================================

// progress meter displays percentage of requests completed
func (f *Fuzzer) progress(done chan bool) {
	defer f.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	var totalURLs     int
	var requestsSent  int
	var totalRequests int

	for {
		select {
		case <- done:
			fmt.Printf("Progress: %d / %d (100.00%%)\n", totalRequests, totalRequests)
			return
		case <- ticker.C:
			// read f.totalURLs and f.requestsSent safely
			f.progressMu.RLock()
			totalURLs = f.totalURLs
			requestsSent = f.requestsSent
			f.progressMu.RUnlock()

			totalRequests = totalURLs * f.wordlist.totalWords
			percentComplete := (float32(requestsSent) * float32(100)) / float32(totalRequests)
			fmt.Printf("Progress: %d / %d (%.2f%%)\r", requestsSent, totalRequests, percentComplete)
		}
	}
}

// check remaining URLs while maintaining thread safety
func (f *Fuzzer) remainder() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.urls)
}

// read URL from channel and iterate over a chunk of the wordlist
// called multiple times to form worker pool
func (f *Fuzzer) search(urls chan string, chunk []string) {
	defer f.wg.Done()
	for {
		url := <- urls
		if f.remainder() == 0 {
			return
		}

		url = f.addSlash(url)
		for _, i := range chunk {
			result, err := f.probe(url, i)
			if err != nil {
				log.Printf("[!] [ERROR] %s", err.Error())
				continue
			}

			f.evaluate(result)
			time.Sleep(time.Duration(f.delay) * time.Millisecond)
		}

		f.wg.Done()
	}
}

// start, stop, and delegate jobs to worker pool
func (f *Fuzzer) Start() error {
	defer f.handle.Close()

	// log startup
	log.Printf("[+] Launching search...")
	log.Printf("[+] %s\n", time.Now().String())
	log.Printf("[+] URLs: %v\n", f.urls)
	log.Printf("[+] Total words: %d\n", f.wordlist.totalWords)
	log.Printf("[+] Threads: %d\n", f.threads)
	log.Printf("[+] Timeout: %d\n", f.timeout)
	
	if f.delay != 0 {
		log.Printf("[+] Delay: %d\n", f.delay)
	}

	if f.output != "" {
		log.Printf("[+] Log: %s\n", f.output)
	}

	log.Printf("[+] Positive codes: %v\n", f.positiveCodes)
	log.Printf("[+] Negative codes: %v\n", f.negativeCodes)

	if len(f.ignoredSizes) > 0 {
		log.Printf("[+] Ignored sizes: %v\n", f.ignoredSizes)
	}

	if f.recursive {
		log.Printf("[+] Recursion: enabled\n")
	}

	if f.useragent != "" {
		log.Printf("[+] User-agent: %s\n", f.useragent)
	}

	log.Printf("[+] Method: %s\n", f.method)

	if len(f.headers) > 0 {
		log.Printf("[+] Headers: %v\n", f.headers)
	}

	if len(f.cookies) > 0 {
		log.Printf("[+] Cookies: %v\n", f.cookies)
	}

	if f.tlsVerify {
		log.Printf("[+] TLS validation: disabled\n")
	}

	if f.basicAuth {
		log.Printf("[+] Basic auth creds: \"%s\" : \"%s\"", f.basicAuthUsername, f.basicAuthPassword)
	}

	if f.proxy != nil {
		proxy, _ := f.proxy(nil)
		log.Printf("[+] Proxy: %s\n", proxy)
	}

	// start progress meter
	progressDone := make(chan bool)
	if f.showProgress {
		go f.progress(progressDone)
	}

	// create worker pool
	urls := make(chan string, f.threads)
	for i := 0; i < f.threads; i++ {
		go f.search(urls, f.wordlist.chunks[i])
	}

	for {
		if f.remainder() == 0 {
			break
		}

		f.mu.RLock()
		url := f.urls[0]
		f.mu.RUnlock()

		fmt.Printf(strings.Repeat(" ", 50) + "\r")
		log.Printf("\n---- Entering directory: %s ----", url)
		f.wg.Add(f.threads)
		for i := 0; i < f.threads; i++ {
			urls <- url
		}
		f.wg.Wait()

		f.mu.Lock()
		f.urls = f.urls[1:]
		f.mu.Unlock()
	}

	// collect worker pool
	f.wg.Add(f.threads)
	close(urls)
	f.wg.Wait()

	if f.showProgress {
		// collect progress routine
		f.wg.Add(1)
		progressDone <- true
		f.wg.Wait()
		close(progressDone)
	}

	log.Printf("\n")
	return nil
}

// ===========================================
// structs and methods to form builder pattern
// ===========================================

type FuzzerBuilder struct {
	fuzzer Fuzzer
}

func NewFuzzerBuilder() *FuzzerBuilder {
	return &FuzzerBuilder{}
}

func (b *FuzzerBuilder) SetURL(url string) *FuzzerBuilder {
	b.fuzzer.urls = []string{url}
	return b
}

func (b *FuzzerBuilder) SetWordlist(filepaths, extensions []string) (*FuzzerBuilder, error) {
	b.fuzzer.wordlist.numberOfChunks = b.fuzzer.threads
	b.fuzzer.totalURLs = len(b.fuzzer.urls)

	for _, file := range filepaths {
		err := b.fuzzer.wordlist.Load(file)
		if err != nil {
			return b, errors.New("failed to read one or more wordlists")
		}
	}

	if len(extensions) > 0 {
		b.fuzzer.wordlist.Extend(extensions)
	}

	return b, nil
}

func (b *FuzzerBuilder) SetThreads(threads int) *FuzzerBuilder {
	b.fuzzer.threads = threads
	return b
}

func (b *FuzzerBuilder) SetTimeout(timeout int) *FuzzerBuilder {
	b.fuzzer.timeout = timeout
	return b
}

func (b *FuzzerBuilder) SetDelay(delay int) *FuzzerBuilder {
	b.fuzzer.delay = delay
	return b
}

func (b *FuzzerBuilder) SetOutput(output string) *FuzzerBuilder {
	b.fuzzer.output = output
	return b
}

func (b *FuzzerBuilder) SetPositiveCodes(positiveCodes []int) *FuzzerBuilder {
	b.fuzzer.positiveCodes = positiveCodes
	return b
}

func (b *FuzzerBuilder) SetNegativeCodes(negativeCodes []int) *FuzzerBuilder {
	b.fuzzer.negativeCodes = negativeCodes
	return b
}

func (b *FuzzerBuilder) SetIgnoredSizes(ignoredSizes []int) *FuzzerBuilder {
	b.fuzzer.ignoredSizes = ignoredSizes
	return b
}

func (b *FuzzerBuilder) SetRecursive(recursive bool) *FuzzerBuilder {
	b.fuzzer.recursive = recursive
	return b
}

func (b *FuzzerBuilder) SetUseragent(useragent string) *FuzzerBuilder {
	b.fuzzer.useragent = useragent
	return b
}

func (b *FuzzerBuilder) SetMethod(method string) *FuzzerBuilder {
	b.fuzzer.method = method
	return b
}

func (b *FuzzerBuilder) SetHeaders(headers map[string]string) *FuzzerBuilder {
	b.fuzzer.headers = headers
	return b
}

func (b *FuzzerBuilder) SetCookies(cookies map[string]string) *FuzzerBuilder {
	b.fuzzer.cookies = cookies
	return b
}

func (b *FuzzerBuilder) SetTLSVerify(tlsVerify bool) *FuzzerBuilder {
	b.fuzzer.tlsVerify = tlsVerify
	return b
}

func (b *FuzzerBuilder) SetBasicAuthUsername(username string) *FuzzerBuilder {
	b.fuzzer.basicAuthUsername = username
	b.fuzzer.basicAuth = true
	return b
}

func (b *FuzzerBuilder) SetBasicAuthPassword(password string) *FuzzerBuilder {
	b.fuzzer.basicAuthPassword = password
	b.fuzzer.basicAuth = true
	return b
}

func (b *FuzzerBuilder) SetProxy(proxy func(*http.Request) (*nurl.URL, error)) *FuzzerBuilder {
	b.fuzzer.proxy = proxy
	return b
}

func (b *FuzzerBuilder) SetProgress(progress bool) *FuzzerBuilder {
	b.fuzzer.showProgress = progress
	return b
}

func (b *FuzzerBuilder) Build() (Fuzzer, error) {
	log.SetFlags(0)
	if b.fuzzer.output != "" {
		file, err := os.OpenFile(b.fuzzer.output, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0755)
		if err != nil {
			return b.fuzzer, err
		}

		b.fuzzer.handle = file
		log.SetOutput(io.MultiWriter(os.Stdout, file))
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: b.fuzzer.tlsVerify,
		},
		MaxIdleConns: b.fuzzer.threads,
		MaxIdleConnsPerHost: b.fuzzer.threads,
		MaxConnsPerHost: b.fuzzer.threads,
		Proxy: b.fuzzer.proxy,
	}

	client := http.Client{
		Timeout:        time.Duration(b.fuzzer.timeout) * time.Second,
		Transport:      transport,
		CheckRedirect:  func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	b.fuzzer.client = client
	b.fuzzer.wordlist.numberOfChunks = b.fuzzer.threads
	b.fuzzer.totalURLs = len(b.fuzzer.urls)
	return b.fuzzer, nil
}

// ==========================================
// functions and vars to help parse arguments
// ==========================================

// arrays created to track multiple uses of a single flag
type flagEntryArray []string
func (i *flagEntryArray) String() string {return ""}
func (i *flagEntryArray) Set(value string) error {*i = append(*i, value); return nil}
var headerFlagEntries flagEntryArray
var cookieFlagEntries flagEntryArray
var wordlistFlagEntries flagEntryArray

// custom help text function
// tabwriter used for pretty help output
// https://pkg.go.dev/text/tabwriter
func help() {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', tabwriter.AlignRight)

	fmt.Printf("Usage: %s [FLAGS]\n\n", os.Args[0])
	fmt.Printf("phinder - web content discovery tool\n\n")
	fmt.Fprintln(w, "  -h, --help\tDisplay this help page\t")
	w.Flush()

	fmt.Println("\nREQUIRED: ")
	fmt.Fprintln(w, "  --url string\tURL to initiate search against (e.g. \"http://127.0.0.1\")\t")
	fmt.Fprintln(w, "  -w, --wordlist string\tPath(s) to wordlist(s) (e.g. \"-w /path/to/list1.txt -w /path/to/list2.txt\")\t")
	w.Flush()

	fmt.Println("\nOPTIONAL:")
	fmt.Fprintln(w, "  -x string\tFile extensions to apply to wordlist (e.g. \"php,html,txt\")")
	fmt.Fprintln(w, "  -t int\tNumber of worker threads to spawn (default: 1)")
	fmt.Fprintln(w, "  --timeout int\tTimeout duration in seconds (default: 10)")
	fmt.Fprintln(w, "  --delay int\tDelay duration in milliseconds (default: 0)")
	fmt.Fprintln(w, "  -o string\tLog file to append search results")
	fmt.Fprintln(w, "  --positive-codes string\tPositive HTTP response status codes (e.g. \"200, 301, 302\")")
	fmt.Fprintln(w, "  --negative-codes string\tNegative HTTP response status codes, overrides positive codes")
	fmt.Fprintln(w, "  --ignore-sizes string\tIgnore responses with a given content length (e.g. \"274, 202, 386\")")
	fmt.Fprintln(w, "  -r\tEnable recursive searching")
	fmt.Fprintln(w, "  --useragent string\tUser-agent string for HTTP requests (default: Go-http-client/[version])")
	fmt.Fprintln(w, "  -m string\tHTTP method to use for requests (default: GET)\t")
	fmt.Fprintln(w, "  -H, --header string\tAdditional HTTP request headers (e.g. \"-H Header1:Value1 -H Header2:Value2\")")
	fmt.Fprintln(w, "  -C, --cookie string\tAdditional HTTP cookies (e.g. \"-C Cookie1:Value1 -C Cookie2:Value2\")")
	fmt.Fprintln(w, "  -k\tDisable TLS validation")
	fmt.Fprintln(w, "  --basic-username string\tUsername for HTTP basic authentication")
	fmt.Fprintln(w, "  --basic-password string\tPassword for HTTP basic authentication")
	fmt.Fprintln(w, "  --proxy string\tHTTP/HTTPS/SOCKS5 proxy to send requests through (e.g. \"http://127.0.0.1:8080\")")
	fmt.Fprintln(w, "  --proxy-username string\tUsername for proxy authentication")
	fmt.Fprintln(w, "  --proxy-password string\tPassword for proxy authentication")
	fmt.Fprintln(w, "  -q\tDisable progress meter")
	w.Flush()
	os.Exit(0)
}

// check if a given command line argument was provided
func flagExists(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	
	return found
}

// check if a given string exists in a given []string
func stringExists(name string, slice []string) bool {
	for _, value := range slice {
		if value == name {
			return true
		}
	}

	return false
}

// split comma separated string into trimmed []string
func parseString(s string) []string {
	slice := strings.Split(s, ",")
	for i, value := range slice {
		slice[i] = strings.TrimSpace(value)
	}

	return slice
}

// convert []string to []int
func parseIntegers(s []string) ([]int, error) {
	integers := make([]int, len(s))
	for i, value := range s {
		num, err := strconv.Atoi(value)
		if err == nil {
			integers[i] = num
		} else {
			return integers, err
		}
	}

	return integers, nil
}

// create, parse, and validate command line arguments
// pass validated arguments to builder and launch fuzzer
func main() {
	// handle CTRL+C
	SIGINT := make(chan os.Signal, 1)
	signal.Notify(SIGINT, os.Interrupt)
	go func(){
		for _ = range SIGINT {
			fmt.Println("\n^C")
			os.Exit(0)
		}
	}()

	// set custom help text function
	flag.Usage = help
	if len(os.Args) == 1 {
		flag.Usage()
	}

	// set flags and parse into pointers
	urlPtr           := flag.String("url", "", "")
	flag.Var(&wordlistFlagEntries, "wordlist", "")
	flag.Var(&wordlistFlagEntries, "w", "")
	extensionsPtr    := flag.String("x", "", "")
	threadsPtr       := flag.String("t", "1", "")
	timeoutPtr       := flag.String("timeout", "10", "")
	delayPtr         := flag.String("delay", "0", "")
	outputPtr        := flag.String("o", "", "")
	positivePtr      := flag.String("positive-codes", "200, 204, 301, 302, 307, 401, 403", "")
	negativePtr      := flag.String("negative-codes", "404", "")
	sizesPtr         := flag.String("ignore-sizes", "", "")
	_                 = flag.Bool("r", false, "")
	useragentPtr     := flag.String("useragent", "", "")
	methodPtr        := flag.String("m", "GET", "")
	flag.Var(&headerFlagEntries, "header", "")
	flag.Var(&headerFlagEntries, "H", "")
	flag.Var(&cookieFlagEntries, "cookie", "")
	flag.Var(&cookieFlagEntries, "C", "")
	_                 = flag.Bool("k", false, "")
	basicUsernamePtr := flag.String("basic-username", "", "")
	basicPasswordPtr := flag.String("basic-password", "", "")
	proxyPtr         := flag.String("proxy", "", "")
	proxyUsernamePtr := flag.String("proxy-username", "", "")
	proxyPasswordPtr := flag.String("proxy-password", "", "")
	_                 = flag.Bool("q", false, "")
	flag.Parse()
	builder := NewFuzzerBuilder()

	// validate and pass URL argument
	if !flagExists("url") {
		fmt.Println("[!] [ERROR] A URL is required")
		os.Exit(1)
	}

	url := *urlPtr
	_, err := nurl.ParseRequestURI(url)
	if err != nil {
		fmt.Println("[!] [ERROR] Invalid URL value")
		os.Exit(1)
	} else {
		builder = builder.SetURL(url)
	}

	// validate and pass threads argument
	// threads needs to be passed first
	threads, err := strconv.Atoi(*threadsPtr)
	if err != nil || threads <= 0 {
		fmt.Println("[!] [ERROR] Invalid thread count value")
		os.Exit(1)
	} else {
		builder = builder.SetThreads(threads)
	}

	// wordlist and extensions arguments get passed together
	// validate wordlists argument
	if !flagExists("wordlist") && !flagExists("w") {
		fmt.Println("[!] [ERROR] At least one wordlist is required")
		os.Exit(1)
	}

	wordlists := wordlistFlagEntries
	for _, file := range wordlists {
		_, err := os.Stat(file)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("[!] [ERROR] One or more wordlists does not exist")
			os.Exit(1)
		}

		_, err = os.Open(file)
		if err != nil {
			fmt.Println("[!] [ERROR] Failed to open handle to one or more wordlists")
			os.Exit(1)
		}
	}

	// store extensions argument, no real validation needed
	var extensions []string
	if *extensionsPtr != "" {
		extensions = parseString(*extensionsPtr)
	}

	// pass wordlist and extensions
	// this one may throw an error
	builder, err = builder.SetWordlist(wordlists, extensions)
	if err != nil {
		fmt.Println("[!] [ERROR] Failed to generate wordlist")
		os.Exit(1)
	}

	// validate and pass timeout argument
	timeout, err := strconv.Atoi(*timeoutPtr)
	if err != nil || timeout <= 0 {
		fmt.Println("[!] [ERROR] Invalid timeout value")
		os.Exit(1)
	} else {
		builder = builder.SetTimeout(timeout)
	}

	// validate and pass delay argument
	delay, err := strconv.Atoi(*delayPtr)
	if err != nil || delay < 0 {
		fmt.Println("[!] [ERROR] Invalid delay value")
		os.Exit(1)
	} else {
		builder = builder.SetDelay(delay)
	}

	// validate and pass output file argument
	if flagExists("o") {
		file, err := os.OpenFile(*outputPtr, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0755)
		if err != nil {
			fmt.Println("[!] [ERROR] Failed to open handle to output file")
			os.Exit(1)
		}

		err = file.Close()
		if err != nil {
			fmt.Println("[!] [ERROR] Failed to close handle to output file")
			os.Exit(1)
		}

		builder = builder.SetOutput(*outputPtr)
	}

	// validate and set positive and negative status code arguments
	positiveCodeStrings := parseString(*positivePtr)
	positiveCodes, err := parseIntegers(positiveCodeStrings)
	if err != nil {
		fmt.Println("[!] [ERROR] Invalid positive status code value")
		os.Exit(1)
	} else {
		builder = builder.SetPositiveCodes(positiveCodes)
	}

	negativeCodeStrings := parseString(*negativePtr)
	negativeCodes, err := parseIntegers(negativeCodeStrings)
	if err != nil {
		fmt.Println("[!] [ERROR] Invalid negative status code value")
		os.Exit(1)
	} else {
		builder = builder.SetNegativeCodes(negativeCodes)
	}

	// validate and set ignored content lengths
	if flagExists("ignore-sizes") {
		ignoredSizesString := parseString(*sizesPtr)
		ignoredSizes, err := parseIntegers(ignoredSizesString)
		if err != nil {
			fmt.Println("[!] [ERROR] Invalid ignored size value")
			os.Exit(1)
		} else {
			builder = builder.SetIgnoredSizes(ignoredSizes)
		}
	}

	// pass recursive search flag, no real validation needed
	if flagExists("r") {
		builder = builder.SetRecursive(true)
	}

	// pass useragent argument, no real validation needed
	if flagExists("useragent") {
		builder = builder.SetUseragent(*useragentPtr)
	}

	// validate and pass method argument
	method := strings.TrimSpace(*methodPtr)
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
	if !stringExists(method, methods) {
		fmt.Println("[!] [ERROR] Invalid HTTP method value")
		os.Exit(1)
	} else {
		builder.SetMethod(method)
	}

	// validate and pass HTTP header arguments
	if flagExists("header") || flagExists("H") {
		headers := make(map[string]string)
		for _, h := range headerFlagEntries {
			header := strings.Split(h, ":")
			if len(header) != 2 {
				fmt.Println("[!] [ERROR] Invalid HTTP header value")
				os.Exit(1)
			}

			name  := strings.TrimSpace(header[0])
			value := strings.TrimSpace(header[1])
			headers[name] = value
		}

		builder = builder.SetHeaders(headers)
	}

	// validate and pass HTTP cookie arguments
	if flagExists("cookie") || flagExists("C") {
		cookies := make(map[string]string)
		for _, c := range cookieFlagEntries {
			cookie := strings.Split(c, ":")
			if len(cookie) != 2 {
				fmt.Println("[!] [ERROR] Invalid HTTP cookie value")
				os.Exit(1)
			}

			name  := strings.TrimSpace(cookie[0])
			value := strings.TrimSpace(cookie[1])
			cookies[name] = value
		}

		builder = builder.SetCookies(cookies)
	}

	if flagExists("k") {
		builder = builder.SetTLSVerify(true)
	}

	// pass username argument, no real validation needed
	if flagExists("basic-username") {
		builder = builder.SetBasicAuthUsername(*basicUsernamePtr)
	}

	// pass password argument, no real validation needed
	if flagExists("basic-password") {
		builder = builder.SetBasicAuthPassword(*basicPasswordPtr)
	}

	// validate and pass proxy arguments, including username and password
	if flagExists("proxy") {
		p, err := nurl.Parse(*proxyPtr)
		if err != nil {
			fmt.Println("[!] [ERROR] Invalid proxy value")
			os.Exit(1)
		}

		if flagExists("proxy-username") || flagExists("proxy-password") {
			p.User = nurl.UserPassword(*proxyUsernamePtr, *proxyPasswordPtr)
		}

		proxy := http.ProxyURL(p)
		builder = builder.SetProxy(proxy)
	}

	if !flagExists("q") {
		builder = builder.SetProgress(true)
	}

	f, err := builder.Build()
	if err != nil {
		fmt.Println("[!] [ERROR] Failed to build fuzzer")
		fmt.Println(err)
		os.Exit(1)
	}

	start_time := time.Now()
	err = f.Start()
	if err != nil {
		fmt.Println("[!] ERROR: Failed to start fuzzer")
		os.Exit(1)
	}

	// stop this madness!
	stop_time := time.Now()
	fmt.Println("[*] Search complete")
	fmt.Printf("[*] Search duration: %s\n", stop_time.Sub(start_time))
}
