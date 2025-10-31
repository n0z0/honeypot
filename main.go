//go:build windows

package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

var (
	logPath = flag.String("path", `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`, "pfirewall.log path")
	poll    = flag.Duration("poll", 200*time.Millisecond, "poll interval")
)

var fields map[string]int // nama kolom -> index

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[*] SYN tail start file=%q", *logPath)

	var off int64
	for {
		added, lines, err := readNew(*logPath, &off)
		if err != nil {
			log.Printf("[ERR] read: %v", err)
			time.Sleep(*poll)
			continue
		}
		if added == 0 {
			time.Sleep(*poll)
			continue
		}
		for _, ln := range lines {
			if ln == "" {
				continue
			}
			// Header & metadata
			if strings.HasPrefix(ln, "#") {
				if strings.HasPrefix(ln, "#Fields:") {
					parseHeader(ln)
					log.Printf("[INFO] fields parsed")
				}
				continue
			}
			if fields == nil {
				continue // belum ada header
			}

			col := strings.Fields(ln)
			if up(get(col, "protocol")) != "TCP" {
				continue
			}
			// SYN jika tcpsyn=1 ATAU tcpflags memuat 'S'
			isSYN := get(col, "tcpsyn") == "1" || strings.Contains(up(get(col, "tcpflags")), "S")
			if !isSYN {
				continue
			}
			// Ambil info penting
			action := up(get(col, "action")) // ALLOW/DROP/BLOCK
			srcIP := get(col, "src-ip")
			srcPt := get(col, "src-port")
			dstIP := get(col, "dst-ip")
			dstPt := get(col, "dst-port")

			log.Printf("[SYN] %s %s:%s -> %s:%s", action, srcIP, srcPt, dstIP, dstPt)
		}
	}
}

func readNew(path string, off *int64) (int64, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, nil, err
	}
	size := st.Size()
	// rotasi/mengecil: reset ke awal
	if size < *off {
		*off = 0
	}
	if size == *off {
		return 0, nil, nil
	}
	if _, err := f.Seek(*off, io.SeekStart); err != nil {
		return 0, nil, err
	}
	var lines []string
	r := bufio.NewReader(f)
	for {
		s, err := r.ReadString('\n')
		if s != "" {
			lines = append(lines, strings.TrimRight(s, "\r\n"))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, nil, err
		}
	}
	pos, _ := f.Seek(0, io.SeekCurrent)
	added := pos - *off
	*off = pos
	return added, lines, nil
}

func parseHeader(h string) {
	fs := strings.Fields(strings.TrimPrefix(h, "#Fields:"))
	fields = make(map[string]int, len(fs))
	for i, name := range fs {
		fields[strings.ToLower(strings.TrimSpace(name))] = i
	}
}

func get(cols []string, name string) string {
	if fields == nil {
		return ""
	}
	if i, ok := fields[strings.ToLower(name)]; ok && i >= 0 && i < len(cols) {
		return cols[i]
	}
	return ""
}

func up(s string) string { return strings.ToUpper(s) }
