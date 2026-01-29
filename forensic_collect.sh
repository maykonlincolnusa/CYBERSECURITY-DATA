#!/bin/bash
hostname > /tmp/host-info.txt
uptime >> /tmp/host-info.txt
cp /var/log/syslog /tmp/