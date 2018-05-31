
docker build --no-cache -t ailen/buildc:centos-7x64 centos7x64/

docker build --no-cache -t ailen/buildc:ubuntu-17x64 ubuntu17x64/

docker push ailen/buildc:centos-7x64

docker push ailen/buildc:ubuntu-17x64
