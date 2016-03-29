# README

## What is mndc

mndc is a frontend for some standard networktools like ping, dig or traceroute. A main feature is a linked view, so you can click hostnames, IPs or MACs and run the current selected tool on it.

Like running a dig on google.com, select ping and click any hostname or IP in the output tu run ping against it.

## Why

mndc is my pet project, mainly created to not loose all of my C++ fuu some years ago.  :)

## Build Instructions

### Requirements

* QtWidgets and QtNetwork > 5.0
* Atleast cmake 2.8.11

### Build

    mkdir build && cd $_ && cmake .. && make



