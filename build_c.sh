 #!/bin/bash

BASEPATH=$(pwd)

echo $BASEPATH
mkdir $BASEPATH/build



echo "build C for Centos 7 x86 System"

docker rm -f buildC
docker run -ti --name buildC -v $BASEPATH:/c/code -v $BASEPATH/build:/c/output ailen/buildc:centos-7x64
docker rm -f buildC


echo "build C for Ubuntu 17 x86 System"

docker rm -f buildC
docker run -ti --name buildC -v $BASEPATH:/c/code -v $BASEPATH/build:/c/output ailen/buildc:ubuntu-17x64
docker rm -f buildC