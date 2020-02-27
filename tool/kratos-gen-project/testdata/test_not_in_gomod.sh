#!/usr/bin/env bash
set -e

<<<<<<< HEAD
rm -rf /tmp/test-kratos
mkdir /tmp/test-kratos
kratos new a -d /tmp/test-kratos
cd /tmp/test-kratos/a/cmd && go build
=======
dir=/tmp/test-kratos
rm -rf $dir
mkdir $dir

cd $dir
rm -rf ./a
kratos new a
cd ./a/cmd && go build
>>>>>>> upstream/master
if [ $? -ne 0 ]; then
  echo "Failed: all"
  exit 1
else
  rm -rf ../../a
fi
<<<<<<< HEAD
kratos new b -d /tmp/test-kratos --grpc
cd /tmp/test-kratos/b/cmd && go build
if [ $? -ne 0 ]; then
=======

cd $dir
rm -rf ./b
kratos new b --grpc
cd ./b/cmd && go build
if [ $? -ne 0 ];then
>>>>>>> upstream/master
  echo "Failed: --grpc"
  exit 1
else
  rm -rf ../../b
fi
<<<<<<< HEAD
kratos new c -d /tmp/test-kratos --http
cd /tmp/test-kratos/c/cmd && go build
=======

cd $dir
rm -rf ./c
kratos new c --http
cd ./c/cmd && go build
>>>>>>> upstream/master
if [ $? -ne 0 ]; then
  echo "Failed: --http"
  exit 1
else
  rm -rf ../../c
fi

rm -rf $dir
