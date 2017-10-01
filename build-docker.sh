#!/bin/bash
set -o xtrace

dir=`pwd`
echo "$dir"

build_image=coturnbuild
dockerargs="--privileged -v ${dir}:/root/coturn -w /root/coturn"
container_env=' -e "INSIDECONTAINER=-incontainer=true"'
docker="docker run --rm -it ${dockerargs} ${container_env} ${build_image}"

docker build -f Dockerfile.build -t ${build_image} .

${docker} bash -c "./configure && make"

