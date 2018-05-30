FROM ubuntu:latest

MAINTAINER ChijieMa <chijiema@gmail.com>

ENV LANG=C.UTF-8

RUN apt -y update \
 && apt -y upgrade


## CBuild ##

ENV JIN="-I /opt/jdk/include -I /opt/jdk/include/linux"
ENV OUTPATH=/c/output
ENV CODE=/c/code/brewchain-crypto/crypto;/c/code/ethereum-crypto/crypto;/c/code/bitcoin-crypto/crypto;/c/code/iota-crypto/crypto;/c/code/sm-crypto/crypto

COPY cbuild.sh /c/build.sh
RUN chmod +x /c/build.sh

## CBuild ##

## GCC ##
RUN apt -y install gcc make
## GCC ##

## JAVA ######

ENV JAVA_HOME=/opt/jdk
ENV PATH=${PATH}:${JAVA_HOME}/bin:${JAVA_HOME}/jre/bin \
    CLASSPATH=.:${JAVA_HOME}/lib/dt.jar:${JAVA_HOME}/lib/tools.jar

RUN echo "\n## Java add " >> /etc/profile \
  && echo "export JAVA_HOME=/opt/jdk" >> /etc/profile \
  && echo "export PATH=${PATH}:${JAVA_HOME}/bin:${JAVA_HOME}/jre/bin" >> /etc/profile \
  && echo "export CLASSPATH=.:${JAVA_HOME}/lib/dt.jar:${JAVA_HOME}/lib/tools.jar" >> /etc/profile \
  && echo "" >> /etc/profile

COPY jdk-7u80-linux-x64.tar.gz /tmp/jdk.tar.gz

RUN mkdir -p ${JAVA_HOME} \
 && tar zxvf /tmp/jdk.tar.gz -C ${JAVA_HOME} --strip-components=1

RUN rm -rf ${JAVA_HOME}/*src.zip \
           ${JAVA_HOME}/lib/missioncontrol \
           ${JAVA_HOME}/lib/visualvm \
           ${JAVA_HOME}/lib/*javafx* \
           ${JAVA_HOME}/jre/lib/plugin.jar \
           ${JAVA_HOME}/jre/lib/ext/jfxrt.jar \
           ${JAVA_HOME}/jre/bin/javaws \
           ${JAVA_HOME}/jre/lib/javaws.jar \
           ${JAVA_HOME}/jre/lib/desktop \
           ${JAVA_HOME}/jre/plugin \
           ${JAVA_HOME}/jre/lib/deploy* \
           ${JAVA_HOME}/jre/lib/*javafx* \
           ${JAVA_HOME}/jre/lib/*jfx* \
           ${JAVA_HOME}/jre/lib/amd64/libdecora_sse.so \
           ${JAVA_HOME}/jre/lib/amd64/libprism_*.so \
           ${JAVA_HOME}/jre/lib/amd64/libfxplugins.so \
           ${JAVA_HOME}/jre/lib/amd64/libglass.so \
           ${JAVA_HOME}/jre/lib/amd64/libgstreamer-lite.so \
           ${JAVA_HOME}/jre/lib/amd64/libjavafx*.so \
           ${JAVA_HOME}/jre/lib/amd64/libjfx*.so \
           ${JAVA_HOME}/jre/lib/security/README.txt

## JAVA ######

RUN rm -rf /tmp/*

CMD ["/bin/bash","./c/build.sh"]
