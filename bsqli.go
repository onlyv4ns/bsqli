package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"
)

type Result struct {
    Success        bool
    URLWithPayload string
    ResponseTime   float64
    ErrorMessage   string
}

func performRequest(url string, payload string, cookie string) Result {
    urlWithPayload := strings.Replace(url, "*", payload, -1)
    startTime := time.Now()

    client := &http.Client{}
    req, err := http.NewRequest("GET", urlWithPayload, nil)
    if err != nil {
        return Result{Success: false, URLWithPayload: urlWithPayload, ResponseTime: time.Since(startTime).Seconds(), ErrorMessage: err.Error()}
    }

    if cookie != "" {
        req.AddCookie(&http.Cookie{Name: "cookie", Value: cookie})
    }

    resp, err := client.Do(req)
    if err != nil {
        return Result{Success: false, URLWithPayload: urlWithPayload, ResponseTime: time.Since(startTime).Seconds(), ErrorMessage: err.Error()}
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
        return Result{Success: true, URLWithPayload: urlWithPayload, ResponseTime: time.Since(startTime).Seconds()}
    }
    return Result{Success: false, URLWithPayload: urlWithPayload, ResponseTime: time.Since(startTime).Seconds(), ErrorMessage: fmt.Sprintf("HTTP Status: %d", resp.StatusCode)}
}

func processPayloads(url string, payloads []string, cookie string, outputFile string, wg *sync.WaitGroup) {
    defer wg.Done()

    for _, payload := range payloads {
        var payloadsToTest []string
        if strings.Contains(url, "*") {
            for _, p := range strings.Split(payload, ",") {
                payloadsToTest = append(payloadsToTest, strings.Replace(url, "*", p, -1))
            }
        } else {
            payloadsToTest = append(payloadsToTest, url+payload)
        }

        for _, testPayload := range payloadsToTest {
            result := performRequest(testPayload, "", cookie)
            resultLine := ""
            if result.ResponseTime >= 10 {
                resultLine = fmt.Sprintf("✓ SQLi Found! URL: %s - Response Time: %.2f seconds", result.URLWithPayload, result.ResponseTime)
                fmt.Printf("\033[92m%s\033[0m\n", resultLine)
            } else {
                resultLine = fmt.Sprintf("✗ Not Vulnerable. URL: %s - Response Time: %.2f seconds", result.URLWithPayload, result.ResponseTime)
                fmt.Printf("\033[91m%s\033[0m\n", resultLine)
            }
            if outputFile != "" {
                file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                if err != nil {
                    log.Fatal(err)
                }
                _, err = file.WriteString(resultLine + "\n")
                if err != nil {
                    log.Fatal(err)
                }
                file.Close()
            }
        }
    }
}

func main() {
    urlPtr := flag.String("url", "", "Single URL to scan.")
    listPtr := flag.String("list", "", "Text file containing a list of URLs to scan.")
    payloadsPtr := flag.String("payloads", "", "Text file containing the payloads to append to the URLs.")
    cookiePtr := flag.String("cookie", "", "Cookie to include in the GET request.")
    threadsPtr := flag.Int("threads", 0, "Number of concurrent threads (0-10).")
    outputPtr := flag.String("output", "", "File to save vulnerable results.")
    flag.Parse()

    if *payloadsPtr == "" {
        log.Fatal("Payloads file is required")
    }

    var urls []string
    if *urlPtr != "" {
        urls = append(urls, *urlPtr)
    } else if *listPtr != "" {
        file, err := os.Open(*listPtr)
        if err != nil {
            log.Fatal(err)
        }
        defer file.Close()
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            urls = append(urls, scanner.Text())
        }
        if err := scanner.Err(); err != nil {
            log.Fatal(err)
        }
    } else {
        log.Fatal("Either URL or list file must be provided")
    }

    file, err := os.Open(*payloadsPtr)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    var payloads []string
    for scanner.Scan() {
        payloads = append(payloads, scanner.Text())
    }
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    fmt.Println(" ______               __ __ ")
    fmt.Println("|   __ \\-----.-----.|  |__|")
    fmt.Println("|   __ <|__ --|  _  ||  |  |")
    fmt.Println("|______/|_____|__   ||__|__|")
    fmt.Println("                 |__|        ")
    fmt.Println("made by Coffinxp :)")

    var wg sync.WaitGroup
    maxThreads := 1
    if *threadsPtr > 0 && *threadsPtr <= 10 {
        maxThreads = *threadsPtr
    }

    sem := make(chan struct{}, maxThreads)

    for _, url := range urls {
        wg.Add(1)
        go func(url string) {
            defer wg.Done()
            for i := 0; i < maxThreads; i++ {
                sem <- struct{}{}
                go func() {
                    defer func() { <-sem }()
                    processPayloads(url, payloads, *cookiePtr, *outputPtr, &wg)
                }()
            }
        }(url)
    }

    wg.Wait()
}
