# Verichains NPM Vulnerability Scanner

A **Node.js-based recursive scanner** for detecting vulnerable or malicious NPM package versions across multiple projects in a directory tree.

This tool was built by Verichains in response to the recent [NPM supply chain attack](https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the), which compromised widely used packages such as `chalk`, `debug`, `strip-ansi`, to help developers and organizations quickly scan their projects for affected NPM packages.

---

## 🚨 Background

A supply chain attack compromised the NPM account of maintainer `qix`, resulting in the publication of malicious versions of several widely used packages.

The injected payload functioned as a crypto-clipper, designed to steal funds by replacing wallet addresses in network requests and hijacking cryptocurrency transactions.

Given their integration into thousands of CLI tools, frameworks, and backend services, the compromise is regarded as one of the most concerning supply chain incidents in the NPM ecosystem, with the affected libraries collectively receiving over two billion weekly downloads.

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


**Affected packages include (not exhaustive):**

The following packages and versions have been identified as compromised:

- ansi-styles@6.2.2
- debug@4.4.2
- chalk@5.6.1
- strip-ansi@7.1.1
- supports-color@10.2.1
- ansi-regex@6.2.1
- wrap-ansi@9.0.1
- slice-ansi@7.1.1
- is-arrayish@0.3.3
- color-convert@3.1.1
- color-name@2.0.1
- color-string@2.1.1
- simple-swizzle@0.2.3
- error-ex@1.3.3
- has-ansi@6.0.1
- supports-hyperlinks@4.1.1
- chalk-template@1.1.1
- backslash@0.2.1
- color@5.0.1
- @duckdb/node-api@1.3.3
- @duckdb/node-bindings@1.3.3
- duckdb@1.3.3
- @duckdb/duckdb-wasm@1.29.2
- prebid.js@10.9.2
- proto-tinker-wc@0.1.87

**References:**
- [We just found malicious code in the npm ecosystem](https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the)  
- [npm Author Qix Compromised via Phishing Email in Major Supply Chain Attack](https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack) 
- [(RESOLVED) Version 4.4.2 published to npm is compromised](https://github.com/debug-js/debug/issues/1005#issuecomment-3266868187)


## 🔍 Tool Features

- Recursively scans all subdirectories for NPM projects
- Identifies **known compromised package versions** from the incident.
- Outputs a clear report of affected packages and their paths.
- Fast and lightweight, no external dependencies beyond Node.js standard modules.
- Support semver and wildcard syntax for vulnerable package versions. Example:

```json
{
  "aes-js": [">=4.0.0-beta.1"],
  "@adraffy/ens-normalize": ["^1.10.0"],
  "wallet-evm": "*", // match all versions
}
```

## 📦 Usage

Clone this repository:

```bash
$ git clone https://github.com/Gear4music/npm-scanner.git
$ cd npm-scanner
$ yarn install
$ node scan.js ./my-projects
```

## Example output

```bash
$ node scan.js ../my-projects

Starting vulnerability scan in: /home/user/test/my-projects
Looking for vulnerable packages

Found npm project: /home/user/test/my-projects
Found 1 npm projects

Scanning: /home/user/test/my-projects

============================================================
VULNERABILITY SCAN RESULTS
============================================================

Scanned Projects: 1
Vulnerable Projects: 1
Errors: 0

----------------------------------------
VULNERABLE PROJECTS:
----------------------------------------

1. my-projects (/home/user/test/my-projects)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > has-property-descriptors > es-define-property > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > has-property-descriptors > es-define-property > gopd > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > call-bind > es-define-property > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > call-bind > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > call-bind > set-function-length > define-data-property > es-define-property > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > call-bind > set-function-length > define-data-property > gopd > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > call-bind > set-function-length > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > call-bind > set-function-length > gopd > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > get-intrinsic)
   ⚠️  get-intrinsic@1.2.4 (via: body-parser > qs > side-channel > get-intrinsic > call-bind > get-intrinsic)
   ⚠️  supports-color@8.1.1 (via: concurrently > supports-color)
   ⚠️  etag@1.8.1 (via: express > etag)
   ⚠️  etag@1.8.1 (via: express > send > etag)
   ⚠️  etag@1.8.1 (via: express > serve-static > send > etag)
   ⚠️  portfinder@1.0.32 (via: http-server > portfinder)
```

*Note: This is sample output with example packages only and does not represent real malicious packages.* 
