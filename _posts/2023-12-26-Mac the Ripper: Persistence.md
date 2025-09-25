---
title: Mac the Ripper - Persistence
categories: 
    - MacOS
    - Persistence
tags:
  - blog
  - macos
  - persistence
  - analysis
date: 2023-12-26
description: Exploring Common MacOS Persistence Mechanisms
author: izzyboop
image:
    path: /assets/img/Mac the Ripper/cover.webp
---
>This page was initially posted on [Medium](https://medium.com/@izzyboop/mac-the-ripper-persistence-01b2bb1dbc08)
{: .prompt-info }

## Introduction

It has come to my attention that within the enterprise space, macs are here to stay. It has also come to my attention that it is time for me to begrudgingly accept this fact. Part of being a good member of the cybersecurity community is understanding the attack landscape, the landscape that now includes macs and has for quite some time. If it pleases `The Council` then it pleases me.

Enough soapboxing, let’s get to it.

Whether it’s an `AsyncRAT`, a `cryptominer`, or yet another version of `Amos` in a trenchcoat, several families of malware have one thing in common: the need for persistence on a company endpoint.

Most workers in the cybersecurity space are more than comfortable with common persistence mechanisms in a windows environment, whether it be `services`, `scheduled tasks`, `registry keys`, the `user startup folder`, or any number of other methods (here’s looking at you, `IFEO Debuggers`).

What mechanisms do we have on a Mac? Do any of the Windows methods have a Mac equivalent? Let’s explore a few.[^1]

---

## Persistence Mechanisms

### LaunchAgents

This one here is probably the most common method of persistence on macOS. LaunchAgents only exist within interactive user sessions, execute when a user logs in, and do not launch at startup. If a user or threat actor wants to have a script execute at startup, they will have to use another method.

LaunchAgents require no permissions to install, making them the easiest form of persistence to install on a mac system. They are by far the most common type of persistence used by developers, both benign and malicious.

Ever since macOS 10.11, malware is allegedly locked out of the `/system/` location if `System Integrity Protection` remains on and has not been bypassed.

![image](/assets/img/Mac the Ripper/image1.gif)

Anything inside the `/system/` location should be signed by Apple. The other two locations below will have `LaunchAgents` from other developers.

`LaunchAgents` exist as `.plist` files. They can either specify a file to execute or can contain their own commands to execute. An example of a `.plist` file:

![image](/assets/img/Mac the Ripper/image2.webp)

**Where to look:**

```bash
~/Library/LaunchAgents/

/System/Library/LaunchAgents/

/Library/LaunchAgents/
```

---

### LaunchDaemons

LaunchDaemons exist at the computer and system level and are supposed to be reserved for persistence mechanisms that do not interact with the user. This would be perfect for malware but LaunchDaemons also require administrator privileges to be written. This doesn’t mean all that much because in a mac environment users are used to having to enter their credentials to move forward with executions. The bar may be raised, but not very high.

LaunchDaemons exist as `.plist` files just like LaunchAgents but are executed upon system startup.

One thing to keep in mind is that with the proper permissions, threat actors can modify the arguments of a legitimate `.plist` file. For this reason you are not just looking for `.plist` files with suspicious names. It is possible for a legitimate `.plist` to have malicious code.

**Where to look:**

```bash
/System/Library/LaunchDaemons/

/Library/LaunchDaemons/
```

---

### Profiles

Profiles are a great way for organizations to manage machines in their environment. They allow administrators to determine various settings to use on a user’s machine like browser settings, VPN settings, etc. Profiles can however be used maliciously.

Profiles can be distributed via email or downloaded from a website like any other malicious file.

**Where to look:**

```bash
System Preferences > Profiles

/Library/Managed Preferences
```

---

### Login / Logout Hooks

Login and Logout Hooks are much less likely to be seen but are still an absolutely viable way of running a persistence mechanism on MacOS. They contain a set of key/value pairs and can be configured to execute a script at login or logout.

**Where to look:**

```bash
/Library/Preferences/com.apple.loginwindow.plist
```

The following command will return current login and logout hooks:

```bash
sudo defaults read com.apple.loginwindow
```

This command should return no results, if there are any results then they are worthy of investigation. 

We can create a login hook and point it at our own custom script with the following command:

```bash
sudo defaults write /Library/Preferences/com.apple.loginwindow LoginHook /path/to/scrip
```

---

### Login Items

Login items are generally used to start a user’s preferred browser or other software they want to launch on login. The login items are generally difficult for the end user to properly enumerate so some adware and PUPs use them for persistence.

An admin can parse the below file, if it exists, for persistence.

**Where to look:**

```bash
~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
```

---

### Cron

Cron jobs are generally an older method of persistence not seen often but malware developers have not let them go to the wayside just yet. Ever since 10.15 Catalina, user interaction is needed to install a cronjob, but we all know that isn’t that big of a hurdle to get over.

A note from crontab’s main page (Thanks [Stuart](https://www.huntress.com/authors/stuart-ashenbrenner)):

>(Darwin note: Although cron(8) and crontab(5) are officially supported under Darwin, their functionality has been absorbed into launchd(8), which provides a more flexible way of automatically executing commands. See launchctl(1) for more information.)

**Where to look:**

```bash
/usr/lib/cron/jobs

/usr/lib/cron/tabs

/var/at/tabs
```

---

### Periodic Scripts

Periodic scripts are similar to Cron jobs and are generally written on a daily, weekly, or monthly schedule. These scripts are to be dropped into one of the below locations and will execute on the schedule indicated by its parent folder.

![image](/assets/img/Mac the Ripper/image3.webp)

**Where to look:**

```bash
/etc/periodic/daily

/etc/periodic/weekly

/etc/periodic/monthly
```

Also, be sure to check both `/etc/defaults/periodic.conf` and `/etc/periodic.conf` for system and local overrides to the default `periodic` configuration.

---

### Overrides

Overrides are exactly what they sound like. They are designed to override values within `LaunchDaemon` or `LaunchAgent`. If the `Disabled` value on a `.plist` is set to `True` but is then set to `False` in the overrides, it will still load next time the `.plist` would be triggered.

**Where to look:**

```bash
/var/db/launchd.db/com.apple.launchd/overrides.plist
```

---

### Conclusion

As we can see above, there are many many way to persist in a MacOS environment. There are several that are currently used and many that are more obsolete. The point of this document is to stress that persistence mechanisms are and always will be evolving. Analysts and researchers need to ensure they are keeping up on current trends to stay steps ahead of Threat Actors.

### Some Further Reading

1. [Insistence on Persistence Huntress Blog](https://www.huntress.com/blog/insistence-on-persistence?source=post_page-----01b2bb1dbc08---------------------------------------)

--- 

### Footnotes

[^1]: read as: a bunch.