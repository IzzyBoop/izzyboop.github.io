---
title: Analyzing a Malicious Advanced IP Scanner Google Ad Redirection
categories: 
    - Malvertising
    - Advanced IP Scanner
tags:
  - blog
  - advanced ip scanner
  - malvertising
  - trojanized tools
  - analysis
  - google ads
date: 2024-03-04
description: Titles are Hard
author: izzyboop
image:
    path: /assets/img/AdvIpScan/cover.webp
---
>This page was initially posted on [Medium](https://medium.com/@izzyboop/analyzing-a-malicious-advance-ip-scanner-google-ad-redirection-124d7c9a0d87) then turned into a [Huntress Blog](https://www.huntress.com/blog/analyzing-a-malicious-advanced-ip-scanner-google-ad-redirection). This blog serves as the latest version. I would also like to thank my colleague Jai Minton for digging into this with me. [Check out his blog.](https://www.jaiminton.com/)
{: .prompt-info }

So you found yourself responding to an alert about one of your employees downloading a malicious version of [Advanced IP Scanner](https://www.advanced-ip-scanner.com/)? This has become fairly common, as system admins and IT technicians want to download the tool to use legitimately within their environment. But threat actors have been hosting very convincing malicious versions that are being discovered through malvertising (e.g., “malicious advertising” like Google Ads). Now, suppose you want to take a deeper dive and grab the file for yourself, yet you find yourself dealing with some issues, namely:

1. The employee deleted the downloaded file
2. The URL they clicked redirects to the REAL Advance IP Scanner website
3. Trying to get the ad to pop up in google searches so you can grab it yourself just isn’t working. (Can’t even get hacked when you’re trying to.)

I was recently dealing with this exact scenario, and the method I chose to use was to trick the site into thinking I was coming from a Google ad click. I chose this method mainly because it seemed like my only way to grab the initial file at the time. The original file was no longer in place on the user’s machine, but I still wanted to analyze it. When I navigated to the malicious URL, however, I discovered the website was redirecting me to the real Advanced IP Scanner website, so I decided to trick it! (I’ll illustrate later how this wasn’t even necessary, and I thought way too hard about it.)

The site we’re dealing with in this scenario is `hxxps://advanced[.]ip-scanner[.]co` (Please don’t, and if you do, don’t blame me lol).

Let’s just… go to the site! What’s the worst that could happen!?

In my case, I get redirected to the real website:

![image](/assets/img/AdvIpScan/1.webp){: .shadow .rounded-10 }
_Note the URL, the fake website looks visually the same._

Okay, well, what if I try to google it? Maybe I can get the ad to show?

![image](/assets/img/AdvIpScan/2.webp){: .shadow .rounded-10 }

![image](/assets/img/AdvIpScan/3.webp){: .shadow .rounded-10 }

Nope, in this case I get the legitimate site. (please note, previous malvertising campaigns were able to spoof the URL that was shown on the ad, but I confirmed this one by visiting the site.)

Alright, well that’s annoying. How can I trick the site into thinking I came from a google ad? Well my first thought was to see what happens when I click an ad on a real site.

In this case I opened up the browser’s developer pane with `F12`, clicked on the `network` tab, and went back to the legitimate advanced-ip-scanner.com via the ad-click.

![image](/assets/img/AdvIpScan/4.webp){: .shadow .rounded-10 }

After some aimless poking and prodding, I discovered the top result is the one we want to explore some more. So let’s click on this result and take a look at what we got.

If we scroll down to `Request Headers` we can see this line:

![image](/assets/img/AdvIpScan/5.webp){: .shadow .rounded-10 }

… I swear if that is all that’s needed I’m gonna snap. Okay let’s head over to `Postman` and give it a shot. In case you’re unfamiliar with it, [Postman](https://www.postman.com/) lets developers execute HTTP requests and test API responses. This way I can freely edit any headers or provide cookie data and see what kind of response I get from the website.

In postman I want to create a new `GET` request and I want to append a `Referer` header with the value `https://www.google.com/`.

![image](/assets/img/AdvIpScan/6.webp){: .shadow .rounded-10 }

This should work, right? … right? Let’s hit `Send`.

![image](/assets/img/AdvIpScan/7.webp){: .shadow .rounded-10 }

You son of a bitch. It worked. You’ll see some references in the screenshot to `advanced-ip-scanner.com` but that’s because the threat-actors straight up cloned the site. If we connect with and without the referrer, there are slight differences in the resulting pages.

So at this point I want to find the download. So I’m going to just `Ctrl+F` the word `download`.

![image](/assets/img/AdvIpScan/8.webp){: .shadow .rounded-10 }

Lo and behold! Let’s try to visit that directory.

![image](/assets/img/AdvIpScan/9.webp){: .shadow .rounded-10 }

Gotcha bitch.

Now before we investigate a bit, remember when I said this?

> “(We will illustrate later how this wasn’t even necessary and I thought way too hard…”

Well, turns out only the main page `advanced[.]ip-scanner[.]co` redirects if you have the incorrect referer. All I had to do was append `/download` and it would let me see the open directory with or without the referrer header. But, hey, hindsight is 20/20 or something.

Let’s poke around a bit. I find that `ipscanner.txt` to be interesting mainly due to the naming convention. `dl.php` and `dwnl.php` are likely related to downloading logic, and I’m unsure about `apps2co.php` at the moment, so I’ll look at the `ipscanner.txt` first. So let’s check that out

![image](/assets/img/AdvIpScan/10.webp){: .shadow .rounded-10 }

It might not be immediately obvious, but this is incredibly interesting to me because that looks like `Base64`. Let’s decode that. Off to Cyberchef! For anyone who’s unfamiliar, [CyberChef](https://gchq.github.io/CyberChef/) is a fantastic web-based tool for data analysis. It can help us uncompress, decode, and decrypt data, and it’s a wonderful “Swiss army knife” for cybersecurity professionals.

![image](/assets/img/AdvIpScan/11.webp){: .shadow .rounded-10 }

Okay, now THAT’S interesting. That is an executable. A quick and dirty way to tell this is an executable is that we can see “This program cannot be run in DOS mode.” near the top of the output. That’s a tell-tale sign of an .exe. 

We could download this a few different ways. We could click the save output button in cyberchef and save that as a .exe and we would have our malicious executable, but I want to illustrate another way.

I am going to download the raw base64 into my VM as a .txt file and use certutil to decode it using:

```posh
certutil -decode .\raw.txt decode.exe
```

![image](/assets/img/AdvIpScan/12.webp){: .shadow .rounded-10 }

> In the above screenshot, I’m simply running certutil against the `raw.txt` which contains the original Base64 and outputting it as `decoded.exe`. Certutil is often used exactly like this by threat actors to create an .exe from encoded data on a target system, so this will generally trigger most EDR products to create an alert. 
{: .prompt-warning }

Boom, we got it. I also did use `Get-FileHash` to compare this against the hash originally referenced in the alert that triggered all of this and it is the same.

Okay but what about the other links shown in the `/download` directory?

Well, as it turns out we are working too hard yet again lol.

![image](/assets/img/AdvIpScan/13.webp){: .shadow .rounded-10 }

If we clicked the `apps2co.php` link on this page, it serves up the decoded .exe and if I check that hash against the original hash from the alert and the hash of my decoded .exe we get the same hash.

At this point we will not be going any further because then this would turn into a blog on static and dynamic malware analysis and I'm not actually any good, so...

Investigation theory tells us to form contextual and answerable questions while investigating an alert. The question I asked myself that caused me to go down this rabbit hole was, “What does this file do?” To answer this question, my initial intention was to download the original malicious file so I could analyze its behavior. This would help me not only understand what the file is doing, but also help me dig deeper and ensure the host is clean. 

I hope you found reading this as enjoyable as it was for me to dig into it.

Cheers, champions! ^_^