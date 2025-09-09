# Verichains NPM Vulnerability Scanner

A **Node.js-based recursive scanner** for detecting vulnerable or malicious NPM package versions across multiple projects in a directory tree.  
Developed in response to the recent [NPM supply chain attack](https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the), which compromised several widely used packages such as `chalk`, `debug`, `strip-ansi`, and more.

This tool was built by Verichains to help developers and organizations quickly scan their projects for affected NPM packages.

---

## 🚨 Background

A supply chain attack compromised the NPM account of maintainer `qix`, resulting in the publication of malicious versions of several widely used packages.

Together, the affected libraries account for over one billion weekly downloads, highlighting the unprecedented scale of the threat to the JavaScript ecosystem. 

Notable weekly download counts:

* ansi-styles (371M), 
* debug (357M)
* chalk (300M)
* supports-color (287M)
* strip-ansi (261M)
* ansi-regex (243M)
* wrap-ansi (198M)
* color-convert (193M)
* color-name (191M)

The injected payload functioned as a crypto-clipper, designed to steal funds by replacing wallet addresses in network requests and hijacking cryptocurrency transactions.

Given their integration into thousands of CLI tools, frameworks, and backend services, the compromise introduced a significant security risk and is considered one of the most severe supply chain incidents in the NPM ecosystem.

**Affected packages include (not exhaustive):**

The following packages and versions have been identified as compromised:

- backslash@0.2.1
- chalk@5.6.1
- chalk-template@1.1.1
- color-convert@3.1.1
- color-name@2.0.1
- color-string@2.1.1
- wrap-ansi@9.0.1
- supports-hyperlinks@4.1.1
- strip-ansi@7.1.1
- slice-ansi@7.1.1
- simple-swizzle@0.2.3
- is-arrayish@0.3.3
- error-ex@1.3.3
- has-ansi@6.0.1
- ansi-regex@6.2.1
- ansi-styles@6.2.2
- supports-color@10.2.1
- proto-tinker-wc@1.8.7
- debug@4.4.2

**References:**
- [We just found malicious code in the npm ecosystem](https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the)  
- [npm Author Qix Compromised via Phishing Email in Major Supply Chain Attack](https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack) 
- [(RESOLVED) Version 4.4.2 published to npm is compromised](https://github.com/debug-js/debug/issues/1005#issuecomment-3266868187)


## 🔍 Features

- Recursively scans all subdirectories for NPM projects
- Identifies **known compromised package versions** from the incident.
- Outputs a clear report of affected packages and their paths.
- Fast and lightweight, no external dependencies beyond Node.js standard modules.


## 📦 Usage

Clone this repository:

```bash
$ git clone https://github.com/verichains/npm-scanner.git
$ cd npm-scanner
$ node scan.js ./my-projects

Starting vulnerability scan in: ./my-projects
Looking for vulnerable packages: backslash@0.2.1, chalk@5.6.1, chalk-template@1.1.1, color-convert@3.1.1, color-name@2.0.1, color-string@2.1.1, wrap-ansi@9.0.1, supports-hyperlinks@4.1.1, strip-ansi@7.1.1, slice-ansi@7.1.1, simple-swizzle@0.2.3, is-arrayish@0.3.3, error-ex@1.3.3, has-ansi@6.0.1, ansi-regex@6.2.1, ansi-styles@6.2.2, supports-color@10.2.1, proto-tinker-wc@1.8.7, debug@4.4.2

Found npm project: ./my-projects
Found 1 npm projects

Scanning: ./my-projects

============================================================
VULNERABILITY SCAN RESULTS
============================================================

Scanned Projects: 1
Vulnerable Projects: 1
Errors: 0

----------------------------------------
VULNERABLE PROJECTS:
----------------------------------------

1. my-projects (./my-projects)
   ⚠️  debug@4.4.2 (direct dependency)
```