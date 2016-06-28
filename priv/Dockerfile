FROM ubuntu:xenial

ARG OTP_VERSION=local
ENV OTP_VERSION ${OTP_VERSION}

RUN apt-get update && \
    apt-get -y install curl && \
    curl -O https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb && \
    dpkg -i erlang-solutions_1.0_all.deb && \
    apt-get update && \
    apt-get -y install esl-erlang=1:${OTP_VERSION} git make clang-3.8
 
RUN mkdir /build
WORKDIR /build