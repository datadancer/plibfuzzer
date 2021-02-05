#!/bin/sh
PWD=$(pwd)
cd `dirname $0`
commit_ts=`git log -1 --format="%ct"`
commit_time=`date -d@$commit_ts +"%Y-%m-%d %H:%M:%S"`
current_time=`date +"%Y-%m-%d %H:%M:%S"`
git_version=`git log -1 --format="%h"`
sed -i s/LATEST_VERSION/"$git_version commit: $commit_time build: $current_time"/g FuzzerVersion.h
cd $PWD
