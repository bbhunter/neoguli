package main

import (
    "fmt"
    "os/exec"
    "strings"
    "os"
    "bufio"
    "sync"
    "io"
    "log"
)

func main() {
  file, err := os.Open("scope.txt")
  check(err)
  defer file.Close()
  scanner := bufio.NewScanner(file)

  domainsListCh := make(chan string)
  go func() {
    for scanner.Scan() {
      domainsListCh <- scanner.Text()   
      } 
  close(domainsListCh)
  }()

  wgRecon := &sync.WaitGroup{}

  wgRecon.Add(1)
  recon(domainsListCh, wgRecon)
  wgRecon.Wait() 
}


func isUp(domain string, alive chan<- string, wg *sync.WaitGroup) {
    defer wg.Done()
    cmd := "/usr/bin/curl"
    args := []string{"--write-out", "%{http_code}", "--silent", "--output", "/dev/null", "-m", "5", "https://" + domain}
    out, _ := exec.Command(cmd, args...).Output()
    if (string(out) != "000") {
        fmt.Println("[SCAN][WEB][STATUS] Target: " + domain + " is up")
        alive <- domain
      } else {
          fmt.Println("[SCAN][WEB][STATUS] Target: " + domain + " is unreachable")
    }
}

func webEnum(domain string, wg *sync.WaitGroup) {      
    defer wg.Done()
    os.MkdirAll(domain, os.ModePerm);
    cmd := "/tools/gobuster"
    args := []string{"-u", "https://" + domain, "-w", "/tools/SecLists/Discovery/Web-Content/raft-large-words.txt", "-t", "100", "-e", "-o", domain + "/gobuster." + domain + ".txt"}  
    //cmd := "/tools/dirsearch"
    //args := []string{"-u", "https://" + domain, "-e", "php,asp,aspx,cgi,sh,py,pl,rb,html,txt,jar,zip,sql,jsp", "-t", "10", "--random-user-agents", "-r", "-x", "--plain-text-report=" + domain + "/dirsearch." + domain + ".txt"} 
    fmt.Println("[SCAN][WEB][GOBUSTER] Started | Target: " + domain)

    logfile, err := os.OpenFile("gobuster.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("Error opening file: %v", err)
    }
    defer logfile.Close()
    mwriter := io.MultiWriter(logfile)
    cmdd := exec.Command(cmd, args...)
    cmdd.Stderr = mwriter
    cmdd.Stdout = mwriter
    err = cmdd.Run()
    if err != nil {
        panic(err)
    }

    fmt.Println("[SCAN][WEB][GOBUSTER] Finished | Target: " + domain)
}

func aMass(wildcard string, wg *sync.WaitGroup) chan string {
    defer wg.Done() 
    wildcard = strings.Trim(wildcard, "*.")
    os.MkdirAll(wildcard, os.ModePerm);
    cmd := "/tools/amass"
    args := []string{"-d", wildcard, "-o", wildcard + "/domains." + wildcard + ".txt"}
    fmt.Println("[SCAN][DNS][AMASS] Started | Target: " + wildcard)

    logfile, err := os.OpenFile("amass.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("Error opening file: %v", err)
    }
    defer logfile.Close()
    mwriter := io.MultiWriter(logfile)
    cmdd := exec.Command(cmd, args...)
    cmdd.Stderr = mwriter
    cmdd.Stdout = mwriter
    err = cmdd.Run()
    if err != nil {
        panic(err)
    }

//    exec.Command(cmd, args...).Run()
    f, err := os.Open(wildcard + "/domains." + wildcard + ".txt")
    check(err)
    defer f.Close()
  //  fmt.Println("reading amass file")
    c := make(chan string, 10)
    s := bufio.NewScanner(f)  
    for s.Scan() {
        c <- s.Text()
    }
    close(c)
    fmt.Println("[SCAN][DNS][AMASS] Finished | Target: " + wildcard)
    return c
}

func wayBack(url string, wg *sync.WaitGroup) {
    defer wg.Done()
    os.MkdirAll(url, os.ModePerm);
    cmd := "/tools/waybackurls"
    args := []string{"https://" + url} 
    fmt.Println("[SCAN][WEB][WAYBACK] Started | Target: " + url)

    logfile, err := os.OpenFile(url + "/wayback." + url + ".txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("Error opening file: %v", err)
    }
    defer logfile.Close()
    mwriter := io.MultiWriter(logfile)
    cmdd := exec.Command(cmd, args...)
    cmdd.Stderr = mwriter
    cmdd.Stdout = mwriter
    err = cmdd.Run()
    if err != nil {
        panic(err)
    }
    fmt.Println("[SCAN][WEB][WAYBACK] Finished | Target: " + url)
}

func recon(domains chan string, wg *sync.WaitGroup) {
    defer wg.Done()

    wgAlive := &sync.WaitGroup{} // wait group to close aliveCh
    wgBuster := &sync.WaitGroup{} //
    wgSublist := &sync.WaitGroup{} 
    wgWayBack := &sync.WaitGroup{}
    aliveCh := make(chan string)

    for domain := range domains {
      if strings.HasPrefix(domain, "*.") {
        wgSublist.Add(1)
        go func(d string) {
          subDomainListCh := aMass(d, wgSublist)
          wg.Add(1)
          go recon(subDomainListCh, wg)
        }(domain)
      } else {
          wgAlive.Add(1)
          go isUp(domain, aliveCh, wgAlive)
      }
    }

    go func() {
        wgAlive.Wait()
        close(aliveCh)
    }()

    for aliveDomain := range aliveCh {
      wgBuster.Add(1)
      go webEnum(aliveDomain, wgBuster)
      wgWayBack.Add(1)
      go wayBack(aliveDomain, wgWayBack)
    }

    wgSublist.Wait()
    wgBuster.Wait()
    wgWayBack.Wait()
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}
