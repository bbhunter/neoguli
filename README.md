# neoguli
Recon routine in Go

## Why
I have been curious about Go recently and wanted to give it a try. I have experienced `parallel` commands in bash and `subprocessed` in Python for asynchronous tasks and was eager to try my hand at Go routines and channels.

I thought that a good exercise was my (still very young) recon routine.

## Usage

Create a `scope.txt` file with a list of your target URLs. 
For wildcard domains, prefix a `*` before the domain. For example, a line with `*.foo.io` will attempt to find every subdomains and recursively run the scans on those.

## Notes
- I welcome every advice on how to make this piece of code better
- I welcome every advice on how to make my automated recon routine better

## TODO
- Integrate tools directly with their libraries
- Automate finding js scripts and scraping them to find urls and secrets

## Mentions
- Gobuster: https://github.com/OJ/gobuster
- Dirsearch: https://github.com/maurosoria/dirsearch
- Amass: https://github.com/OWASP/Amass
- Waybackurls: https://github.com/tomnomnom/waybackurls

