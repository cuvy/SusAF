#!/bin/bash

# Suspicious Activity Framework
# Hacky bash version

######################################################################
# commands
######################################################################
TEE="/usr/bin/tee"
GREP="/bin/grep"

######################################################################
## Global vars
######################################################################
WD=$(dirname $0)
CANARY_ACCOUNTS_FILE="$WD/data/canary_accounts_file.csv"
BAD_IPS_FILE="$WD/data/bad-ips.csv"
LOG_FILE="$WD/log/SusAF.log"
TRUE='true'
FALSE='false'
SCRIPTINFO="Script $0 running on $HOSTNAME:$PWD by $USER"

MODE=""
MODE_CANARY="canary"
MODE_BADIP="badip"
MODE_ADD="add"

######################################################################
# Logging functions
######################################################################
info()    { printf "$(date --iso-8601=seconds) [INFO]  $(basename $0) $@\n" | "$TEE" -a "$LOG_FILE" >&2 ; }
warning() { printf "$(date --iso-8601=seconds) [WARN]  $(basename $0) $@\n" | "$TEE" -a "$LOG_FILE" >&2 ; }
error()   { printf "$(date --iso-8601=seconds) [ERROR] $(basename $0) $@\n" | "$TEE" -a "$LOG_FILE" >&2 ; }
fatal() { printf "$(date --iso-8601=seconds) [FATAL] $(basename $0) $@\n" | "$TEE" -a "$LOG_FILE" >&2 ; exit 1 ; }


######################################################################
## data store file formats
######################################################################
# iso8601_timestamp,canary_username,url_submitted,comments
# url and comment fields are URL encoded to encode commas and not confuse the csv file processing

# bad ip file format
# iso-8601_timestamp,bad_ip,ASN,canary_account,comment
# comment is url encoded so as not to confuse csv file processing

######################################################################
# add a new bad ip
# parameters:
# 1. Bad IP
# 2. canary account which trigggered bad ip
# 3. comment (optional)
######################################################################
function add_bad_ip {
    if [ -z "$1" ] || [ -z "$2" ]  ; then
        warn "Error - did not supply bad ip and canary account"
        return -1
    else
        #TODO validate ip is valid 
        IP="$1"
        BAD_IP=$(echo "$IP" | "$GREP" -Po '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if is_public_ip "$IP" ; then
            local TS=$(date --iso-8601=seconds)
            local BAD_IP="$1"
            local ASN="notyetimplemented"
            local CANARY_ACCOUNT="$2"
            local COMMENT=$(urlencode "$3")

            local LINE="$TS,$BAD_IP,$ASN,$CANARY_ACCOUNT,$COMMENT"
            echo "$LINE" >> "$BAD_IPS_FILE"
            echo "successfully added bad ip entry: $LINE"
            return 0
        else
            FATAL("add_bad_ip(): BAD IP is in a reserved/private ip space")
        fi
    fi
}

######################################################################
# checks if an IP is a valid public IP (not RFC1918 or RFC5735 special use
# IP address) 
# returns:
#   0   if it is a public ip
#   1   if it is a RFC1918 IP
#   2   if it is RFC5735 special IP
######################################################################
function is_public_ip() {
    IP=$(echo "$1" | "$GREP" -Po '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if echo "$IP" | grep -P '^10\.' ; then return 1 ; fi        #   10.0.0.0/8
    if echo "$IP" | grep -P '^192\.168\.' ; then return 1 ; fi  # 192.168.0.0/16
    if echo "$IP" | grep -P '^172\.(1[6-9]|2\d|3[0-1])\.' ; then return 1 ; fi # 172.16.0.0/12
    if echo "$IP" | grep -P '^127\.' ; then return 2 ; fi                      # 127.0.0.0/16
    if echo "$IP" | grep -P '^169\.254\.' ; then return 2 ; fi  # 169.254.0.0/16 link local broadcast
    if echo "$IP" | grep -P '^224\.' ; then return 2 ; fi  # 224.0.0.0/4 multicast
    if echo "$IP" | grep -P '^0\.' ; then return 2 ; fi  # 0.0.0.0/8 
    # if it hasn't matched any of these, it should be ok (although we haven't 
    # validated that it is actually a valid IP address)
    return 0
    fi
}


######################################################################
# get bad IPs from bad ips files
# parameters:
# 1. age (optional - defaults to 28 days)
######################################################################
function get_bad_ips() {
    local AGE=28
    if [ ! -z "$1" ] ; then
        local AGE=$(echo "$1" | grep -Po '\d*')
    fi 
    local DATE_AFTER=$(date -d "-$AGE days" '+%Y-%m-%d')
    local BAD_IPS=$(cat "$BAD_IPS_FILE" | awk -F, -v var_age "$DATE_FROM"  '{if($1>var_age) {print $2}}' | sort -u | xargs)
    return "$BAD_IPS"
}


######################################################################
# add a new canary account 
# parameters: 
# 1. canary account username
# 2. url to be added
# 3. comment to be added
######################################################################
function add_canary_account() {
    if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] ; then
        echo "Error - did not supply canary, url and comment"
        return -1
    else
        local CA="$1"
        local URL=$(urlencode "$2")
        local COMMENT=$(urlencode "$3")
        local TS=$(date --iso-8601=seconds)
        local LINE="$TS,$CA,$URL,$COMMENT"

        echo "$LINE" >> "$CANARY_ACCOUNTS_FILE"
        echo "successfully added canary: $LINE"
        return 0
    fi
}


######################################################################
# get canary accounts
# parameter:
# 1. age (get canaries under age in days) 
######################################################################
function get_canaries() {
    local AGE=365
    if [ ! -z "$1" ] ; then
        local AGE=$(echo "$1" | grep -Po '\d*')
    fi 
    local DATE_AFTER=$(date -d "-$AGE days" '+%Y-%m-%d')
    local CANARIES=$(cat "$CANARY_ACCOUNTS_FILE" | awk -F, -v var_age "$DATE_FROM"  '{if($1>var_age) {print $2}}' | sort -u | xargs)
    return "$CANARIES"
}



######################################################################
# percent encoding functions string
######################################################################
function urldecode 
{ 
    echo -e $(echo "$1" | sed 'y/+/ /; s/%/\\x/g') ; 
    #echo "$1" | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' | xargs echo -e ; 
}
function urlencode 
{ 
    echo "$1" | sed 's/ /%20/g;s/!/%21/g;s/"/%22/g;s/#/%23/g;s/\$/%24/g;s/\&/%26/g;s/'\''/%27/g;s/(/%28/g;s/)/%29/g;s/:/%3A/g'
}


######################################################################
# check auth logs for activity from bad ips
# parameters
# 1. age (days)
######################################################################
function check_bad_ips() {
    # get bad ips for age
    # search auth logs for these bad ips
    # process results.
    # alert on successful auths
    # log all activity
    log_bad_ip_activity
}


######################################################################
# log bad ip activity in a useful format to a file
# log format:
# <iso-8601 ts>,<ip>,<account>,<auth_status>,??identifier to link to bad ip entry and canary entry??
######################################################################
function log_bad_ip_activity() {
    

}


######################################################################
# check auth logs for activity from canary accounts
# parameters
# 1. age
######################################################################
function check_auth_canaries() {
    # get canary accounts for age
    # search auth logs
    # add source ips for any found auths to bad ips
    # log all found activity
    log_canary_activity 
}


######################################################################
# log auth canary activity in a useful format to a file
# log format:
# <iso-8601 ts>,<ip>,<canary_account>,<user-agent>
######################################################################
function log_canary_activity() {



}



# parse args
# command format is:
# SusAF.sh <mode> <command> <args>
#
# eg 
# SusAF.sh canary check -age 365

if [ $# -eq 0 ] ; then
    print_help
    exit 1
fi

case "$1" in 
    canary)
        MODE="$MODE_CANARY"
        ;;
    badip)
        MODE="$MODE_BADIP"
        ;;
    --help|-h)
        print_help
        exit 0
        ;;
    add)
        MODE="$MODE_ADD"
        ;;
    *)
        echo "Unknown command $1"
        print_help
        exit 1
        ;;
esac
shift







