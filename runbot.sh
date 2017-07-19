#!/bin/sh

ROOT=$(readlink -f $(dirname $(readlink -f $0)))
CONFDIR=$ROOT/etc

. $CONFDIR/env.sh
cd $ROOT
exec rtmbot -c $CONFDIR/rtmbot.conf
