FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y build-essential libncurses-dev libreadline-dev libssl-dev libgmp-dev

WORKDIR /app