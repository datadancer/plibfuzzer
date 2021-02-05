#!/bin/sh

commit_ts=`git log -1 --format="%ct"`
commit_time=`date -d@$commit_ts +"%Y-%m-%d %H:%M:%S"`
current_time=`date +"%Y-%m-%d %H:%M:%S"`
git_version=`git log -1 --format="%h"`
sed -i s/e3c38f2011882589b2c213865876a3703d5b7cd1/"$git_version commit: $commit_time build: $current_time"/g FuzzerVersion.h

LIBFUZZER_SRC_DIR=$(dirname $0)
CXX="${CXX:-clang}"
for f in $LIBFUZZER_SRC_DIR/*.cpp; do
  $CXX -g -O2 -fno-omit-frame-pointer -std=c++11 $f -c &
done
wait
rm -f plibFuzzer.a
ar ru plibFuzzer.a Fuzzer*.o
rm -f Fuzzer*.o

