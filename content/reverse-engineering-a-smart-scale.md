+++
title = "Reverse engineering a smart scale"
date = 2024-02-24

[taxonomies]
tags = ["Bluetooth"]
categories = ["Hacking"]
+++

### Background
One thing I hate more than anything with devices these days are how
annoying they can be in terms of providing a simple functionality without
login, android has such a brilliant way of storing your data locally that
I think pretty much anything can be stored here without having to resort to 
email or god forbid one click login from fb, google, apple and what not.

<!-- more -->
So this story begin with me finally resorting to getting a weighing scale
to manage my health and while I was looking into it, I could not find any 
reasonable smart scales with no login or local login feature but I wanted 
a smart scale to see a pretty graph on my homeassistant dashboard to motivate
me into working out. Since I couldn't find one that's cheap with the features 
I wanted, I just bought the cheapest one that I could find on amazon. 
When life gives you proprietary things, just hack it into what you need it to be.

## Finding the frames

Like most of the cheap IoT things running on button cells, the scale that I got 
works on Bluetooth. There are various ways of intercepting bluetooth frames
depending on what sort of information you want to capture. If you need to capture frames 
being sent out by your device or received directly to your device, linux kernel has had
support for sniffing this since 2.4.6 which you can directly sniff using wireshark.
But unfortunately for us, the smart scale only works with mobile applications and 
from my guess requires some sort of pairing to work.
Another option would be to use something like ubertooth or using some microcontroller 
dev kits that do support bluetooth monitoring or setting the device in promiscuous mode.
Another option and the one I choose was using the device already in your pocket. 
Android has supported bluetooth sniffing from kitkat version which is pretty great 
when all you need to do is capture a few frames quickly.

To capture bluetooth frames, you need to go into your developer settings and enable 
bluetooth host controller interface  (hci) snoop or bluetooth hci logging, reboot the system
disconnect all other bluetooth devices near you if you can (both connected to phone or otherwise)
and then open the dreadful app. Since the app required internet and I connected to my debug wifi network
without any devices and logged into the app with some temporary email. Just as I stepped on the scale
I could see the app automatically update the screen which could only mean that the device doesn't require
pairing and is just based on bluetooth low-energy advertising mode to send packets everywhere whenever the 
device is stepped on. That saves us a great deal of effort in figuring out the pairing mode.
I stepped on the scale a few times and then closed bluetooth, disabled the hci snoop logging and attempted
to get the captured bluetooth frames to my laptop. My usual approach when I had used previously was just running 
```bash adb pull /sdcard/btsnoop_hci.log``` with usb debugging mode but it seems that google has stopped 
storing the logs there for pixel devices and I had to go to developer setting on my phone again, start
the bug report (full report not required just the interactive one is okay) and wait for the zip file
to be created and then copied file from the zip file at `FS/data/misc/bluetooth/logs/btsnoop_hci.log`
to my laptop.

Opening this file on wireshark revealed the many packets that were captured during the few minutes
that the logging was on. Luckily for us the weighing scale app had an info page which displayed the
bluetooth hardware mac address when it first received the advertisement packet and finding the packets 
from the packet dump was as simple as finding this macaddress in wireshark. This can be simplified 
by using the filter `bthci_evt.bd_addr == ab:cd:ef:ab:cd:ef` with appropriate macaddress for your device.

Each of the frames captured were 60 bytes but for us only the data block under the advertising data payload
is essential which is about 17 nibbles. 

## Decoding the hex

The next step is for us to identify what those binary encoded data mean. The hexdump of the packet looks like this
```bash
0000:   04 3e 39 0d 01 10 80 00 95 0b 06 01 fb 64 01 00
0010:   ff 7f cc 00 00 00 00 00 00 00 00 00 1f 02 01 06
0020:   06 09 49 46 5f 42 37 14 ff 00 01 02 03 11 64 fb
0030:   01 06 0b 95 01 19 28 00 c7 a1 c6 70

```
the part we need is just this 
```
02 03 11 64 fb 01 06 0b 95 01 19 28 00 c7 a1 c6 70
```

the next part was just finding patterns in other frames and trying to see what sort of information changed.
The last byte felt promising as it kept changing but after looking at it closely it was incrementing sequentially
from `c6 70` to `c7 71` and so on, which meant it could be some sort of internal timestamp or some internal id
for keeping track of measurement data so we can scratch the last byte off. We now have 15 nibbles left.
```bash
                                             XX XX
02 03 11 64 fb 01 06 0b 95 01 19 28 00 c7 a1 c6 70
                              ^^ ^^
# XX marked for no longer considered and ^^ marked for the current consideration
```   

The other thing that changed slightly were the byte 19 28. The lowest primitives that works well with weighing 
system would be unsigned short int which has a size of 2 bytes. So putting 0x1928 in the calculator got me 6440.
That's my weight multiplied by 100, I knew that the values that I was looking for might not be stored as ieee 754 floats
as many cheap microcontrollers don't support floating point but wasn't expecting it to stored like this, but it sort 
of makes sense after looking at it from the firmware engineer point of view.
Just to make sure this was weight and not some random bytes coincidentally adding up to my weight, I recaptured 
some more bluetooth frames, this time drinking increasing amount of water after every measurement. 
Turns out it was what I was looking for and the number steadily increased as I was expecting it. Confirming it 
again through the app I was sure this was what I was looking for. So I crossed it off and now we have 13 nibbles left.


```bash 
                              XX XX          XX XX
02 03 11 64 fb 01 06 0b 95 01 19 28 00 c7 a1 c6 70
^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^                                         
# XX marked for no longer considered and ^^ marked for the current consideration
```
The first part (of 9 nibbles) never changed and trying to brute force those in groups of 1 byte, 2 bytes and 4 bytes didn't get
any useful values either and I had to start going through the app again. Luckily, while trying to find the name of the 
device in their info section I found a value called serial number which turns out to be the same as the first 9 nibbles
with an additional nibble prefix. Going through the wireshark payload, I found out that the nibble prefix was actually the 
company id field so if I consider that and merge it with the first 9 nibbles from the payload I get the 5 bytes worth of 
entire serial number that the app shows. So we can safely cancel these out. Now we just have 4 nibbles left.

```bash 
XX XX XX XX XX XX XX XX XX    XX XX          XX XX
02 03 11 64 fb 01 06 0b 95 01 19 28 00 c7 a1 c6 70
                                    ^^ ^^ ^^    
# XX marked for no longer considered and ^^ marked for the current consideration
```

I tried looking at the three nibbles between the previous two values and found that it was switching between 
00 00 00 for many frames and back to 00 c7 a1. I was a bit confused but remembered the popup from the app
for not placing my feet on the metal discs on the scale. After doing a quick online search, I found out that the 
metal discs were two pairs of electrodes that were measuring Bioelectrical impedance analysis [[1]] by sending tiny 
current through the feet. Whenever I had not stepped on them properly the values were 0 so they must be some sort of 
Impedance values or calculated body water percentage. I will probably read a bit more about this and update this section
when I have found how it works later. 

[//]: # (TODO: Read the paper on BIA and find which of the formula relates to the scale that I have and check if the values could be impedance or resistance and reactance separately)

## Conclusion

This turned out to be an interesting evening exercise but I still haven't got the fancy graphs that I wanted
on my homeassistant dashboard whenever I check my weight. I have some ideas and I'll try it out later.


[//]: # (TODO: Write another blog post for capturing this data and adding to ha later)

### References
[1]: https://en.wikipedia.org/wiki/Bioelectrical_impedance_analysis
`[1]: https://en.wikipedia.org/wiki/Bioelectrical_impedance_analysis`

