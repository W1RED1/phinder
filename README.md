# phinder
Phind philes phast!  
  
**WARNINGS**:
* Improperly combining inputs can lead to false negatives
* This program can generate a large amount of network noise

You know what you're doing, right? ;)

## What?
Web content discovery tool  
Used to find web pages, directories, API endpoints, etc. on a target web server

## Why?
I got tired of deciding between the speed of [gobuster](https://github.com/OJ/gobuster) and the recursive searching of [dirb](https://salsa.debian.org/pkg-security-team/dirb)

## How?
Download a pre-compiled binary or download the source code and compile as follows:  
```
GOOS=linux GOARCH=amd64 go build -o phinder phinder.go
GOOS=linux GOARCH=386 go build -o phinder32 phinder.go
GOOS=windows GOARCH=amd64 go build -o phinder.exe phinder.go
GOOS=windows GOARCH=386 go build -o phinder32.exe phinder.go
```

# Usage
Help page available via the usual `-h` and `--help`
```
┌──(kali㉿kali)-[~]
└─$ ./phinder -h                                                                                  
Usage: ./phinder [FLAGS]

phinder - web content discovery tool

  -h, --help    Display this help page

REQUIRED: 
  --url string                  URL to initiate search against (e.g. "http://127.0.0.1")
  -w, --wordlist string         Path(s) to wordlist(s) (e.g. "-w /path/to/list1.txt -w /path/to/list2.txt")

OPTIONAL:
  -x string                     File extensions to apply to wordlist (e.g. "php,html,txt")
  -t int                        Number of worker threads to spawn (default: 1)
  --timeout int                 Timeout duration in seconds (default: 10)
  --delay int                   Delay duration in milliseconds (default: 0)
  -o string                     Log file to append search results
  --positive-codes string       Positive HTTP response status codes (e.g. "200, 301, 302")
  --negative-codes string       Negative HTTP reponse status codes, overrides positive codes
  --ignore-sizes string         Ignore responses with a given content length (e.g. "274, 202, 386")
  -r                            Enable recursive searching
  --useragent string            User-agent string for HTTP requests (default: Go-http-client/[version])
  -m string                     HTTP method to use for requests (default: GET)
  -H, --header string           Additional HTTP request headers (e.g. "-H Header1:Value1 -H Header2:Value2")
  -C, --cookie string           Additional HTTP cookies (e.g. "-C Cookie1:Value1 -C Cookie2:Value2")
  -k                            Disable TLS validation
  --basic-username string       Username for HTTP basic authentication
  --basic-password string       Password for HTTP basic authentication
  --proxy string                HTTP/HTTPS/SOCKS5 proxy to send requests through (e.g. "http://127.0.0.1:8080")
  --proxy-username string       Username for proxy authentication
  --proxy-password string       Password for proxy authentication
  -q                            Disable progress meter
```
