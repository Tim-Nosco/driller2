FROM angr/angr

RUN apt update && apt install -y clang libc6-dev libc6-dev-i386 gcc-multilib g++-multilib python-pip
RUN pip install xlsxwriter pycrypto

USER angr

COPY . /job

ARG TARGET=CGC_Hangman_Game
WORKDIR /job

ENTRYPOINT bash