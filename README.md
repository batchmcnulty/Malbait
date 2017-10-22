# Malbait
TCP/UDP Honeypot program implemented in Perl

README for malbait, 2/10/17

Welcome to malbait, your one-stop, simple perl honeypot!

QUICK START!
-
For commercial use, I recommend running this program in "-defaults" mode with Superuser privileges (sudo) on a small, cheap, permanently-on computer such as a Raspberry Pi or even an ancient Asus EEE-PC connected to the network you wish to defend. If any arseholes start sniffing around in your network, you'll soon find out. This is especially useful if you have a wireless network, though I also reccomend beefing up security generally if this is the case.
--------------------------------------------------------------------------------------------------------------


1) What malbait is
2) What malbait does
3) Transport protocol
4) Hacktime? Fuzz?
5) The HTTP server
6) Transblank
7) Noloop, no_multiplex and other exotica
8) Error and debugging messages
9) Log files
10) Future versions

--------------------------------------------------------------------------------------------------------------
1) What malbait is.

Malbait is a honeypot, or "malware bait" program. It is designed to waste the time of hackers and monitor hostile traffic on the internet (or your LAN). 

--------------------------------------------------------------------------------------------------------------

2) What malbait does

Malbait creates a series of fake servers on selected or default TCP and, if selected, UDP ports. If anyone or anything connects to them, their input will be recorded in the logfiles.

These run as background processes, so you will have to either switch off your computer or use the shell's "kill" (or, better still, "skill") command to get rid of them. You can monitor them with netstat. I reccomend:

  _sudo netstat -anp|grep perl

to see what's listening, and 

  _sudo skill -9 perl

to kill them off when you've had enough. 

**NB: If you use install.sh to install this program, you will have to run**

_sudo skill -9 malbait

**instead. though you can still monitor it with:** _sudo netstat -anp|grep perl

Alternatively you can just shut down the machine. Obviously don't use malbait while using perl for anything else! I reccomend a dedicated "bait" machine, either something small like a Raspberry Pi running the default ports, or a big computer running as many ports as you can listen on (preferably all of them).

Malbait defaults to TCP, but can support UDP on its own and both running side-by-side. 

It is VERY STRONGLY reccomended that you use this program in superuser mode, either by invoking gainroot (sudo gainroot) or by sudoing it (sudo malbait). You MUST have superuser permissions to open any of the first 1024 ports. 

It's invoked like this 

  _malbait -foo

if you run it without parameters it will spit out a lengthy text explaining usage further. If you want to get started "out of the box" run 

  _malbait -defaults

This will open its' default ports and create servers wherever possible. 

Malbait can create dummy servers for Telnet, FTP, SMTP, POP3, BGP, HTTP (not brilliantly), TR-69 (not brilliantly), imap, systat, echo, and the old ascii "time" server. By default these are opened on all of their default ports, but you can specify ports for them.

You can also open a range of ports, ie, 

  _malbait -ports:1-1024 

Will open ports 1-1024 (the "well-known" or "restricted" ports) and create fake servers where appropriate.

Use of malbait is only restricted by the amount of memory you have. The  -trans_proto:tcpudp  and  -ports: options gives you the power to watch every single port if you have a hardcore enough machine; or crash your computer if you don't. I find that my little Lenovo x200 notepad can handle about 6000 ports or so before it starts to go bonkers, but your mileage may vary. Want to see how powerful your new box REALLY is? Malbait can provide a benchmark - personally I'd love to see what happens on a machine running 

  _malbait -ports:1-65535 -trans_proto:tcpudp

on a very powerful computer - in my experience with just 10% of that, there's definitely more malicious UDP traffic out there (mainly dickheads trying to scam free phone calls it seems), and telnet is an absolute petri dish, but I'd love to see a survey of the uncharted territory beyond, if anyone has the horsepower (and the ability and balls / ovaries to completely disable their firewall!)

--------------------------------------------------------------------------------------------------------------
3) Transport protocols

If you try to open, say, an FTP server in UDP mode, ( malbait -proto:ftp -trans_proto:udp ) it'll open the default ports - but you won't get a pretend FTP server! UDP will only create servers for UDP compatible services, which are asciitime, systat, echo and the special "hacktime" and "fuzz" meta-protocols.

--------------------------------------------------------------------------------------------------------------

4) Hacktime? Fuzz? Wot you on about?

Hacktime is a bit of a joke inspired by the film "Kung Fury". It creates NTP time servers, both old-school and new-fashioned, and transmits either all 1s or all FFs, the idea being to emulate the rollover date for the Unix Millenium ("hacktime-2036") or a freshly booted system ("hacktime-1900"). Obviously the NTP server is a lot more complicated than that and it probably won't work, but it will definitely confuse any hackers who attack you thinking you are an NTP server!

Fuzz is just that - an attempt to mess with automated attacks by throwing random garbage at them. Again, this is experimental and I don't necceserily take it massively seriously, but I thought someone might find it useful so it stays in.

--------------------------------------------------------------------------------------------------------------

5) The HTTP server

The HTTP server looks for a file called "webpage.html". If it doesnt' find it, it generates a simple 404 page instead. Again, it's not brilliant- this programs more about helping you check out the exotic, random clients that try to connect to you rather than boring old web spiders. 

Note that if you open it in a Web browser you will see a lot of "HTTP/1.1 200 OK" strings below the content; this is because it's not meant to be opened in a Web browser, it's meant to keep potentially malicious webcrawling bots on the line for as long as possible.

Feel free to replace the default webpage.html with your own, of course - while you are welcome to use it, it is designed for demonstration purposes.

--------------------------------------------------------------------------------------------------------------

6) Transblank

The -transblank options allow you to override fake server creation. So if you invoke 

  _malbait.pl -port:23 -proto:transblank

or

  _malbait.pl -proto:telnet -transblank

malbait will transmit the closest thing to a blank response (a single, solitary carraige return) to clients instead of creating a "Telnet server".

--------------------------------------------------------------------------------------------------------------

7) -noloop, -no_multiplex and other exotica

Various options have been provided for lovers of computer exotica. 

-noloop: Doesn't loop, ie, kills each server after one connection. If it's a UDP server, kills it after the client has entered a "command".

-no_multiplexing: Stops the TCP server from multiplexing, ie, launching servers in a child process. 
Althogh you can save a lot of memory this way, it is NOT reccomended - nmap is known to crash Malbait's TCP servers, and having them in a child process means that malbait can recover from, and log, this and other malicious connection attempts. So if you use the "-no_multiplexing" option I GUARANTEE that you will end up with orphan temporary files spread all over your working folder / directory like a rash, and this will make you very sad; you will also lose servers permanently when they crash. TL;DR: Do not use this option.

-maxreq:nn Allows you to potentially spawn nn TCP servers at the same time, so you can (potentially) serve that many "clients" at once. Default is 2.

-noblocking: launches servers in "nonblocking" mode; there isn't much point to this, though it might make us less vulnerable to nmaps' fuckery if used in conjunction with -no_multiplexing. But why would you want to do that? Seriously, though, some clients prefer you to be nonblocking, so if you're having trouble, try using this option.

-timeout:nn Set the timeout for clients to nn seconds. Default is 30 - but if you're getting a lot of automated attacks, you might wanna lower this so you don't miss out on all the other malware connecting to your computer.

-report:filename.txt Allows you to name your own report files.

-recvbuffer:nn: Set an internal variable that buffers recv (recieved bytes) to value nn. Default is 1024, so if you want to guzzle more than 1k at a time (not an unreasonable desire), this is where you change it.

--------------------------------------------------------------------------------------------------------------

7) Error and debugging messages

The text output of malbait is a bit... messy at the moment. It's full of debugging messages and status information. You can safely ignore it unless you're a developer or a masochist. Actual error messages are recorded in the logfile.

--------------------------------------------------------------------------------------------------------------

8) Log files

Malbait creates three types of log files: A CSV file giving you an overview of all the clients that have connected to your machine, a text file with more detailed data and analysis, and temporary files (with names like TEMP-16537) which will be auto-deleted as malbait opens / closes ports and creates / destroys "servers".

Sorry about the temporary files, it was the only way to ensure that ALL traffic got captured, even when it tries to crash us! If you see any hanging around, don't do anything, just refresh the page and they'll probably dissapear.

--------------------------------------------------------------------------------------------------------------

9) Future versions

If people show interest in this program and send me emails / money / love letters / threats, I will support it with updates and new features - for instance, I can easily add ICMP support, and maybe better web client handling as well. I've had a great time writing this and I know I'd get a real kick out of supporting it! But if I don't hear from people, I will assume it's not that useful, and move on to other things. So if you want to see more great features, or wish I'd fix Annoying Bug X, *please* get in touch!

My email address is batchmcnulty@protonmail.com
The bitcoin address for this program (hint, hint) is 16P267RxgkLsEDVEKwLGsfnUCJ6bfgyWKR

Thanks for reading, and please, please send me your Satoshis!
