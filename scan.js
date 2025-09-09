#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const VULNERABLE_PACKAGES = {
  'backslash': ['0.2.1'],
  'chalk': ['5.6.1'],
  'chalk-template': ['1.1.1'],
  'color-convert': ['3.1.1'],
  'color-name': ['2.0.1'],
  'color-string': ['2.1.1'],
  'wrap-ansi': ['9.0.1'],
  'supports-hyperlinks': ['4.1.1'],
  'strip-ansi': ['7.1.1'],
  'slice-ansi': ['7.1.1'],
  'simple-swizzle': ['0.2.3'],
  'is-arrayish': ['0.3.3'],
  'error-ex': ['1.3.3'],
  'has-ansi': ['6.0.1'],
  'ansi-regex': ['6.2.1'],
  'ansi-styles': ['6.2.2'],
  'supports-color': ['10.2.1'],
  'proto-tinker-wc': ['1.8.7'],
  'debug': ['4.4.2']
};

class NpmVulnerabilityScanner {
  constructor(rootDirectory) {
    this.rootDirectory = path.resolve(rootDirectory);
    this.results = {
      scannedProjects: 0,
      vulnerableProjects: [],
      errors: []
    };
  }

  /**
   * Find all npm projects (directories containing package.json) recursively
   */
  findNpmProjects(dir = this.rootDirectory) {
    const projects = [];
    
    try {
      const items = fs.readdirSync(dir);
      
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          // Skip node_modules directories to avoid false positives
          if (item === 'node_modules') {
            continue;
          }
          
          // Check if this directory contains package.json
          const packageJsonPath = path.join(fullPath, 'package.json');
          if (fs.existsSync(packageJsonPath)) {
            projects.push(fullPath);
            console.log("Found npm project:", fullPath);
          }
          
          // Recursively search subdirectories
          projects.push(...this.findNpmProjects(fullPath));
        }
      }
    } catch (error) {
      this.results.errors.push({
        type: 'directory_scan',
        path: dir,
        message: error.message
      });
    }
    
    return projects;
  }

  /**
   * Execute npm ls --json debug chalk for a project and parse the output
   */
  getNpmDependencies(projectPath) {
    try {
      // Change to project directory and run npm ls --json debug chalk
      const packageNames = Object.keys(VULNERABLE_PACKAGES).join(' ');
      const command = `npm ls --json ${packageNames}`;
      const output = execSync(command, {
        cwd: projectPath,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe']
      });
      
      return JSON.parse(output);
    } catch (error) {
      // npm ls returns non-zero exit code when there are issues, but still outputs JSON
      if (error.stdout) {
        try {
          return JSON.parse(error.stdout);
        } catch (parseError) {
          throw new Error(`Failed to parse npm ls output: ${parseError.message}`);
        }
      }
      throw error;
    }
  }

  /**
   * Check if a package version matches any vulnerable versions
   */
  isVulnerableVersion(packageName, version) {
    if (!VULNERABLE_PACKAGES[packageName]) {
      return false;
    }
    
    // Remove any version prefixes (^, ~, etc.) for exact comparison
    const cleanVersion = version.replace(/^[\^~>=<]+/, '');
    return VULNERABLE_PACKAGES[packageName].includes(cleanVersion);
  }

  /**
   * Scan dependencies for vulnerable packages (including nested dependencies)
   */
  scanDependencies(dependencies, projectPath, dependencyPath = []) {
    const vulnerabilities = [];
    
    if (!dependencies) {
      return vulnerabilities;
    }
    
    for (const [packageName, packageInfo] of Object.entries(dependencies)) {
      if (packageInfo && packageInfo.version) {
        const currentPath = [...dependencyPath, packageName];
        
        // Check if this package is vulnerable
        if (this.isVulnerableVersion(packageName, packageInfo.version)) {
          vulnerabilities.push({
            package: packageName,
            version: packageInfo.version,
            path: projectPath,
            dependencyPath: currentPath.join(' > ')
          });
        }
        
        // Recursively check nested dependencies
        if (packageInfo.dependencies) {
          vulnerabilities.push(...this.scanDependencies(packageInfo.dependencies, projectPath, currentPath));
        }
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Scan a single npm project
   */
  async scanProject(projectPath) {
    try {
      console.log(`Scanning: ${projectPath}`);
      
      const npmData = this.getNpmDependencies(projectPath);
      const vulnerabilities = [];
      
      // Check dependencies
      if (npmData.dependencies) {
        vulnerabilities.push(...this.scanDependencies(npmData.dependencies, projectPath));
      }
      
      // Check devDependencies
      if (npmData.devDependencies) {
        vulnerabilities.push(...this.scanDependencies(npmData.devDependencies, projectPath));
      }
      
      if (vulnerabilities.length > 0) {
        this.results.vulnerableProjects.push({
          path: projectPath,
          packageName: npmData.name || 'unknown',
          vulnerabilities: vulnerabilities
        });
      }
      
      this.results.scannedProjects++;
      
    } catch (error) {
      this.results.errors.push({
        type: 'npm_scan',
        path: projectPath,
        message: error.message
      });
    }
  }

  /**
   * Main scan function
   */
  async scan() {
    console.log(`Starting vulnerability scan in: ${this.rootDirectory}`);
    console.log(`Looking for vulnerable packages: ${Object.entries(VULNERABLE_PACKAGES).map(([key, value]) => `${key}@${value.join(', ')}`).join(', ')}`);
    console.log('');
    
    const projects = this.findNpmProjects();
    console.log(`Found ${projects.length} npm projects`);
    console.log('');
    
    for (const project of projects) {
      await this.scanProject(project);
    }
    
    this.printResults();
  }

  /**
   * Print scan results
   */
  printResults() {
    console.log('\n' + '='.repeat(60));
    console.log('VULNERABILITY SCAN RESULTS');
    console.log('='.repeat(60));
    
    console.log(`\nScanned Projects: ${this.results.scannedProjects}`);
    console.log(`Vulnerable Projects: ${this.results.vulnerableProjects.length}`);
    console.log(`Errors: ${this.results.errors.length}`);
    
    if (this.results.vulnerableProjects.length > 0) {
      console.log('\n' + '-'.repeat(40));
      console.log('VULNERABLE PROJECTS:');
      console.log('-'.repeat(40));
      
      this.results.vulnerableProjects.forEach((project, index) => {
        console.log(`\n${index + 1}. ${project.packageName} (${project.path})`);
        project.vulnerabilities.forEach(vuln => {
          if (vuln.dependencyPath && vuln.dependencyPath.includes(' > ')) {
            console.log(`   ⚠️  ${vuln.package}@${vuln.version} (via: ${vuln.dependencyPath})`);
          } else {
            console.log(`   ⚠️  ${vuln.package}@${vuln.version} (direct dependency)`);
          }
        });
      });
    }
    
    if (this.results.errors.length > 0) {
      console.log('\n' + '-'.repeat(40));
      console.log('ERRORS:');
      console.log('-'.repeat(40));
      
      this.results.errors.forEach((error, index) => {
        console.log(`\n${index + 1}. ${error.type} - ${error.path}`);
        console.log(`   Error: ${error.message}`);
      });
    }
    
    if (this.results.vulnerableProjects.length === 0 && this.results.errors.length === 0) {
      console.log('\n✅ No vulnerable packages found!');
    }
  }
}

// Main execution
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Usage: node npm-vulnerability-scanner.js <root-directory>');
    console.log('Example: node npm-vulnerability-scanner.js ./my-projects');
    process.exit(1);
  }
  
  const rootDirectory = args[0];
  
  if (!fs.existsSync(rootDirectory)) {
    console.error(`Error: Directory '${rootDirectory}' does not exist`);
    process.exit(1);
  }
  
  const scanner = new NpmVulnerabilityScanner(rootDirectory);
  await scanner.scan();
}

// Run the scanner
if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error.message);
    process.exit(1);
  });
}

module.exports = NpmVulnerabilityScanner;
