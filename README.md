# SusAF

Suspicious Activity Framework

## What is it?

It's a framework designed to automate detection of compromised accounts, through the use of canary credentials. 

## How does it work?

The basic principle is:

1. generate a canary credential (non-existent but plausible looking username and password) and submit it to a phishing site
2. monitor auth logs for any auth attempts using the canary credential
3. For any auth attempts, log the IP and save it as a "bad IP"
4. monitor auth logs for any auth activity from bad IPs. Alert on successful auth.

## When I looked at the code my eyes started to burn

I originally wrote this as a few horrible bash scripts. I've started to re-write it again in bash, mostly as psuedo code to demonstrate the principle. I will be devloping a version in python. 


