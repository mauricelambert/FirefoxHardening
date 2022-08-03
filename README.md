# Firefox Hardening

## Description

A CIS based Hardening for Mozilla Firefox browser.

 - 100% of the rules in the CIS benchmark are implemented for Windows and Linux (32 and 64 bits, version ESR or not)
 - There are 6 level 2 rules (with potential impact) marked in the scripts
 - Easy to use (2 solutions)
     - Run script (PowerShell for Windows, Perl for Linux)
     - Place the reference files, containing the configurations, in the firefox directories (these files are found in the github version)
 - A keepass configruation (the web content can't deactivate copy/paste events)
 - Privacy configurations (tracking protection, URL bar "smart" options...)
 - Optimization (cache in RAM instead of disk)
 - Simplify the use of tabs (don't close Firefox with the last tab)
 - Dark theme for Firefox interface (no impact on the Web content)

## Requirements

 - Firefox
 - Root/Administrator permissions

### Linux

 - Perl

### Windows

 - Powershell

## Usages

### Windows

```bash
powershell .\FirefoxHardening.ps1
```

### Linux

```bash
sudo perl FirefoxHardening.pl
```

## Links

 - [CIS](https://www.cisecurity.org/benchmark/mozilla_firefox)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
