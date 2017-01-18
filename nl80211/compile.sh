#!/bin/sh

gcc -I. -I/usr/include/libnl3 -lnl-3 -lnl-genl-3 -o nl nl.c
