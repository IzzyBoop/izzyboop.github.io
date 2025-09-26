---
title: Grab Your Chainsaw, We're Going Hunting
categories:
  - Tools
tags:
  - blog
  - chainsaw
  - logs
  - tooling
  - analysis
  - hunting
  - chainsaw usage
  - log analysis
date: 2023-11-12
description: Using Chainsaw for Effective Threat Analysis
author: izzyboop
image:
    path: /assets/img/Chainsaw/chainsaw.jpg
---
>This page was initially posted on [Medium](https://medium.com/@izzyboop/grab-your-chainsaw-were-going-hunting-50a5c82cef5d)
{: .prompt-info }

## Introduction
A `Chainsaw` can be a useful tool, but it’s important to approach it with caution and follow safety guidelines. Before using a chainsaw, always wear safety gear like a helmet with face shield or safety gog- hold on. What?… Ohhhhhh. Sorry, wrong chainsaw. Moving on.

[Chainsaw](https://github.com/WithSecureLabs/chainsaw) is a wonderful tool to “rapidly search and hunt through windows forensic artifacts.” Imagine you got ransomware popping off in your org, or you got an alert in your EDR about some suspicious lateral movement, you’re likely going to dig through `EVTX logs` at some point during your investigation.

If you’re familiar with digging through event logs, you’re also familiar with the pain it can inflict on the `mind` and the `soul`.

> _“The spirit is willing, but the flesh is spongy and bruised” — The Great Warrior Poet, **Zapp Brannigan**._

Whether it’s painful because you have several hundred thousand logs or because the default event viewer can be a laggy mess, it rings true that a better method would be enthusiastically welcomed by `The Council`. In comes Chainsaw, stage left.

---

## Chainsaw Setup

The first thing I would like to specify is that the chainsaw version I will be using is `v2.8.0`. The newer versions changed up some of the flags and functionality so if you are using an older version, for example `v1.1.7` 👀 then you may want to grab the newer version.

You can follow [this link](https://github.com/WithSecureLabs/chainsaw/releases/tag/v2.8.0) to grab version `v2.8.0`.

![image](/assets/img/Chainsaw/github-page.webp){: .shadow .rounded-10 }

Grab the version that coincides with the system you are using, in my case I will grab `chainsaw_x86_64-apple-darwin.zip` as I am on a Mac but no worries, if you are on a windows or linux system, the general process is incredibly similar. `apple-darwin` for mac, `pc-windows-msvc` for windows, and `unknown-linux-gnu` or `unknown-linux-musl` for linux systems.

- So to start off, download the version from above that coincides with your system.
- Unzip the `.zip` and place the directory in a place you will remember as it does not get installed, it is simply a `.exe` we call on from the terminal. This rings true for all systems. I’ve placed mine on my desktop in `~/Desktop/Tools/chainsaw`{: .filepath} but you can put this anywhere you like. You can even add the `chainsaw.exe` to `PATH` but as that’s different on every system and isn’t the point of this doc, I’ll let you figure that one out with your `google-fu`.

![image](/assets/img/Chainsaw/image2.webp){: .shadow .rounded-10 }

- Boom, you’re done. That’s the “installation.”

## Okay, but, how do? (Chainsaw Usage)

Let’s start off with looking at the chainsaw help documents. In terminal (or powershell), navigate to the same directory that the chainsaw executable is in. (If you don’t know how, look up the `cd` command). Let’s start with looking at a raw `./chainsaw -h` (note on windows systems the _slashy-bois_ go the other way and you may or may not have to specify `.exe` in your command. For example: `.\chainsaw.exe -h`)

![image](/assets/img/Chainsaw/image3.webp){: .shadow .rounded-10 }
_and I oop!_

Wait a minute! Did you get the above message because you’re on a mac? Let’s Fix that the easy way. From the directory that the chainsaw executable is in run this command:

```bash
xattr -d com.apple.quarantine chainsaw
```

You can also just disable Gatekeeper if you're a psychopath:

```bash
#Disable Gatekeeper
sudo spctl - master-disable

#Check Status
sudo spctl - status

#Re-enable Gatekeeper
sudo spctl - master-enable
```

> I would not advise you to disable Gatekeeper, use the `xattr` commandlet instead.
{: .prompt-warning }

Now let’s try that again. `./chainsaw -h`

![image](/assets/img/Chainsaw/manpage.webp){: .shadow .rounded-10 }

This help page shows us that we have four “flags” (options). `-h` for help and `-V` for versioning information, `--num-threads` to limit the number of cpu threads used, and `--no-banner` to hide the Chainsaw banner. (You can use `-q` for that as well).

We also see that we have six `Commands` that we can use. We will be primarily focusing on `search` and `hunt` in this doc.

`hunt` : hunt through ‘artefacts’ (I am 100% convinced that’s not how you spell that) using detection rules for threat detection.

![image](/assets/img/Chainsaw/image4.webp){: .shadow .rounded-10 }
_I can hear my UK colleagues screeching now_

`search` : to search through forensic artifacts for keywords.

---

### Using Chainsaw’s Search Function

Chainsaw’s `search` function, as stated above, allows us to intelligently sift through forensic artifacts, primarily `.evtx` logs, for keywords, regex patterns, etc.

Let’s start off by grabbing the man page for chainsaw search with `./chainsaw search --help` or `./chainsaw search -h`.

![image](/assets/img/Chainsaw/image5.webp){: .shadow .rounded-10 }

We can see several options at our disposal but there are a few I want to focus on below.

I’d like us to jump in with some practical command examples and explain them as we go. 

**We can start with:**

```bash
./chainsaw search -e "mimikatz" -i log.evtx
```

This command is using chainsaw’s `search` function with `-e` to look for the string `mimikatz` within `log.evtx` and is utilizing the `-i` flag to make it case-insensitive. This flag is necessary to capture any instances of `MimiKatz` or `MiMiKaTz`. If you do want to only find specific capitalizations, simply omit the `-i` flag.

**Next, what if we want to focus on a specific EventID?**

```bash
./chainsaw search -t 'Event.System.EventID: =4104' log.evtx
```

This command is using the `-t` flag to use a `Tau expression`. This is necessary to search for EventID’s in Chainsaw V2+. The expression in this case `Event.System.EventID: =4104` is searching for any instances of EventID 4104 within `log.evtx`. We can use this to find any event ID that may show up within the log you are searching like `4624` within `security.evtx` or `21` within sysmon’s `operational.evtx`.

**How about some `REGEX`?**

```bash
./chainsaw search -e "DC[0-9].domain.local" log.evtx --json
```

This command uses two new concepts. It is using the `-e` flag for a string search but introduces regex into the search. `DC[0-9]` will find any instance of DC0 all the way through to DC9 at the beginning of `.domain.local` and searches for it in `log.evtx` then exports the results as JSON using `--json`. This way we can get results for any of the 9 domain controllers that may show in the logs. 

> If you want a bigger introduction to `REGEX` I suggest [regexone.com](https://regexone.com) as a free course, but that is out of scope for this document.
{: .prompt-info }

**Anotha’ one:** _(DJ Khaled gif)_

```bash
./chainsaw search log.evtx -q -t 'Event.System.EventID: =4624' -e "[USER SID]" -i --timestamp Event.System.TimeCreated_attributes.SystemTime --from YYYY-MM-DDTHH:MM:ss --to YYYY-MM-DDTHH:MM:ss 
| grep -iE 'ipAddress|LogonType|WorkStationName|SystemTime' 
| sort 
| uniq -c 
| sort -nr
```

This one is from a colleague of mine that I adapted to Chainsaw V2 that I use almost daily. Can you work through it and tell what it does? Take a moment before reading on. 

_insert Jeopardy music track here_

This query searches `log.evtx` for any login events `4624` from a specific user `SID` between two timestamps then pipes it to `grep`, `sort`, and `uniq`, to format the data to be short and concise. It also utilizes `-q` which is for quiet. This removes the Chainsaw ASCII art banner. Some example output of the above command:

![image](/assets/img/Chainsaw/image6.webp){: .shadow .rounded-10 }

The numbers in the left column show how often the specific entry to the right was seen within the logs. For example this shows that `49` events had an `IpAddress` of `192.168.0.188`. Depending on the investigation, this could give us a hint about where a threat actor was moving laterally from. This screenshot could also help to show us that our search was still far too wide and that we should narrow our search down a bit but this isn’t an investigation theory doc. Moving on.

**Let’s do one more. An easy one.**

```bash
./chainsaw search -e "mimikatz" -i log.evtx --json -o export.json
```

This one added one option to the end. `-o` is our output flag. If you want to output the results to a file to process with other tools or outside the command line we can use `-o` then the name of the output file to achieve this.

One more small concept I would like to make clear about Chainsaw is that it can search through multiple log files at once. You would do this by simply targeting the current working directory `./` on mac/linux and `.\` on windows. You can then search ALL logs for an instance of a username or IP address, or you can start to target the logs by filtering down to EventID’s instead of having to change your search path. Here’s an example:

```bash
./chainsaw search -t 'Event.System.EventID: =1149' ./
```

The above example is searching the entire directory `./` which could contain 1 log or even 17 log files. The way we differentiate which log we are looking in is by the EventID. In this case we are looking for `1149` so we can imply that somewhere in our folder we have the `RemoteConnectionManager` EVTX log and are looking for successful RDP sign ins.

```bash
./chainsaw search -t 'Event.System.EventID: =21' ./
```

The next example above is targeting EventID `21`. Now we could assume a few things from this one. We are looking for successful logins within the `LocalSessionManager` log or we could even be looking within the sysmon `operational` log. If we have both of these logs present you will likely want more filtering, or to remove a log from the directory temporarily otherwise you’ll get two different sources of information in your results.

From here we can combine several concepts we’ve seen above to make our results better like filtering down to a specific time range, adding a string or regex search, and piping the results into `grep`, `sort`, and/or `uniq` to format the results in a way that works better for us.

Let’s move on to `hunt`.

---

### Using Chainsaw’s Hunt Function

Chainsaw’s `hunt` function is very useful in applying `sigma` rules to hunt through logs to find sus activity without you having to manually dig through the logs yourself.

Let’s start off with Chainsaw’s man page. `./chainsaw hunt -h`

![image](/assets/img/Chainsaw/image7.webp){: .shadow .rounded-10 }

There are a lot of options here and a fair deal of them are pretty self explanatory so we will just jump to what I normally use for hunting.

```bash
./chainsaw hunt logs.evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

![image](/assets/img/Chainsaw/image8.webp){: .shadow .rounded-10 }

As we can see in this example, Chainsaw found some user logoff events with eventID’s and the target machine but no real context. Chainsaw’s `hunt` feature will not fill in context for you. It is important to consider how you can use `hunt` in conjunction with other tools and techniques to fill in the context.

Let’s try this again but this time ill target the `EVTX-ATTACK-SAMPLES` provided by chainsaw and output the results to a CSV.

```bash
./chainsaw hunt EVTX-ATTACK-SAMPLES/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --csv --output results
```

![image](/assets/img/Chainsaw/image9.webp){: .shadow .rounded-10 }

![image](/assets/img/Chainsaw/image10.webp){: .shadow .rounded-10 }

This time we got results from `278` different artifact files exported out to a CSV for easier viewing and processing. The results from this hunt include, according to the sigma rules, `password policy enumeration`, `brute force attempts`, and several other possibly-malicious events.

Just like in the `search` function, you can search by timestamp as well to make your hunting easier while giving you only what you need.

```bash
/chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --from "2019-03-17T19:09:39" --to "2019-03-17T19:09:50"
```

You can also filter down to only a specific severity level.

```bash
./chainsaw hunt -r rules/ evtx_attack_samples -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --level critical
```

Keep in mind, these severities are based on the sigma rules being applied and can cause some events to go undetected if you are not mindful in your hunt.

If I can leave you with one thing about Chainsaw’s `hunt` feature, don’t let it be your only source of truth in an investigation. If you run a hunt and find nothing, that does not mean nothing happened, it simply means the sigma rules didn’t find it. Always use a mixture of `search`, `hunt`, other tooling, and a curious mind to power your investigations.