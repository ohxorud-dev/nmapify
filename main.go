package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Println("Args shouldn't be empty")
		os.Exit(1)
	}

	hasStatsEvery := false
	for _, arg := range args {
		if strings.HasPrefix(arg, "--stats-every") {
			hasStatsEvery = true
			break
		}
	}

	nmapArgs := make([]string, 0, len(args)+1)
	if !hasStatsEvery {
		nmapArgs = append(nmapArgs, "--stats-every=1s")
	}
	nmapArgs = append(nmapArgs, args...)

	cmd := exec.Command("nmap", nmapArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError creating stdout pipe: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError creating stderr pipe: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	err = cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError starting nmap: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	statusUpdateChan := make(chan StatusUpdate, 10)
	done := make(chan bool, 2)

	go processOutput(stdout, false, statusUpdateChan, done)
	go processOutput(stderr, true, statusUpdateChan, done)

	go displayStatusUpdates(statusUpdateChan)

	<-done
	<-done

	err = cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Fprintf(os.Stderr, "%sError waiting for nmap: %v%s\n", colorRed, err, colorReset)
			os.Exit(1)
		}
	}
}

type StatusUpdate struct {
	Type        string
	StatsInfo   string
	Percent     float64
	ETC         string
	Remaining   string
	Output      string
	IsStderr    bool
	WarningLine bool
	OpenPort    bool
	PortInfo    PortInfo
}

type PortInfo struct {
	Port     string
	Protocol string
	Service  string
}

func processOutput(r io.Reader, isStderr bool, statusChan chan<- StatusUpdate, done chan<- bool) {
	scanner := bufio.NewScanner(r)

	timingRegex := regexp.MustCompile(`About (\d+\.\d+)% done; ETC: (\d+:\d+) \((.+) remaining\)`)

	statsRegex := regexp.MustCompile(`Stats: (.+)`)

	warningRegex := regexp.MustCompile(`(?i)warning|caution`)
	openPortRegex := regexp.MustCompile(`(\d+)/(tcp|udp)(?:\s+|\t+)open(?:\s+|\t+)(.+)`)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Starting Nmap") {
			continue
		}

		if strings.Contains(line, "Stats:") {
			statsMatches := statsRegex.FindStringSubmatch(line)
			if len(statsMatches) > 1 {
				statusChan <- StatusUpdate{
					Type:      "stats",
					StatsInfo: statsMatches[1],
				}
			}
			continue
		}

		if strings.Contains(line, "Timing:") {
			matches := timingRegex.FindStringSubmatch(line)
			if len(matches) > 3 {
				percent, etc, remaining := matches[1], matches[2], matches[3]
				percentFloat := 0.0
				fmt.Sscanf(percent, "%f", &percentFloat)

				statusChan <- StatusUpdate{
					Type:      "timing",
					Percent:   percentFloat,
					ETC:       etc,
					Remaining: remaining,
				}
			}
			continue
		}

		update := StatusUpdate{
			Type:        "output",
			Output:      line,
			IsStderr:    isStderr,
			WarningLine: warningRegex.MatchString(line),
		}

		if matches := openPortRegex.FindStringSubmatch(line); len(matches) > 3 {
			update.OpenPort = true
			update.PortInfo = PortInfo{
				Port:     matches[1],
				Protocol: matches[2],
				Service:  matches[3],
			}
		}

		statusChan <- update
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%sError reading output: %v%s\n", colorRed, err, colorReset)
	}

	done <- true
}

func displayStatusUpdates(statusChan <-chan StatusUpdate) {
	var lastStats string
	var lastPercent float64
	var lastETC string
	var lastRemaining string

	clearLine := "\r\033[K"

	for update := range statusChan {
		switch update.Type {
		case "stats":
			lastStats = update.StatsInfo
			displayStatusBar(clearLine, lastStats, lastPercent, lastETC, lastRemaining)

		case "timing":
			lastPercent = update.Percent
			lastETC = update.ETC
			lastRemaining = update.Remaining
			displayStatusBar(clearLine, lastStats, lastPercent, lastETC, lastRemaining)

		case "output":
			fmt.Print(clearLine)

			if update.WarningLine {
				fmt.Printf("%s%s%s\n", colorYellow, update.Output, colorReset)
			} else if update.OpenPort {
				fmt.Printf("%s%s/%s%s open %s%s%s\n",
					colorGreen, update.PortInfo.Port, update.PortInfo.Protocol, colorReset,
					colorBold, update.PortInfo.Service, colorReset)
			} else if update.IsStderr {
				fmt.Printf("%s%s%s\n", colorRed, update.Output, colorReset)
			} else {
				fmt.Println(update.Output)
			}

			displayStatusBar(clearLine, lastStats, lastPercent, lastETC, lastRemaining)
		}
	}
}

func displayStatusBar(clearLine, stats string, percent float64, etc, remaining string) {
	if stats == "" && percent == 0 {
		return
	}

	progressBar := createColorProgressBar(percent)

	statusLine := clearLine

	if percent > 0 {
		statusLine += fmt.Sprintf("%s %s%.2f%%%s",
			progressBar, colorGreen, percent, colorReset)

		if etc != "" && remaining != "" {
			statusLine += fmt.Sprintf(" ETC: %s%s%s (%s%s%s remaining)",
				colorYellow, etc, colorReset,
				colorCyan, remaining, colorReset)
		}
	}

	if stats != "" {
		if percent > 0 {
			statusLine += " | "
		}
		statusLine += fmt.Sprintf("%sStats: %s%s", colorBlue, stats, colorReset)
	}

	fmt.Print(statusLine + "\r")
}

func createColorProgressBar(percent float64) string {
	const barWidth = 20
	progress := int((percent / 100.0) * float64(barWidth))

	progressBar := "["
	for i := 0; i < barWidth; i++ {
		if i < progress {
			progressBar += colorGreen + "=" + colorReset
		} else if i == progress {
			progressBar += colorYellow + ">" + colorReset
		} else {
			progressBar += " "
		}
	}
	progressBar += "]"

	return progressBar
}
