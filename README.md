This repository contains two approaches for a userspace driver for the xbone wireless controller.

* `raw-frames` contains a Ruby script and a C implementation that send raw frames from userspace (don't get confused the all the `nl80211` stuff inside, it has nothing to do with `nl80211`). This is the solution that I got working to the point that I got the (previously paired) controller to connect to the WiFi chip in my laptop (after patching the driver to allow this) and send some seconds worth of input. This might be more stable on a WiFi dongle with proper support for raw frames / AP mode in 5 GHz. You need to switch the interface to monitor mode before using that code. This can be done with the aircrack-ng tools. The performance of the script is Ruby rather unstable. The C implementation performs better because it's much faster (especially regarding response time).

* `nl` contains a C skeleton of the implemenation which uses the `nl80211` kernel interface to talk to the WiFi driver. I never got further than this state because I have no WiFi dongle that supports AP mode in 5 GHz (while I managed to get the laptop wifi chip working after the patching driver, nl80211 probably involves the firmware which just refused to do that). I managed to get some snippets from the hostapd source code which is a real mess.