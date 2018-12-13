#!/bin/bash
for i in corpus/*
do
	echo $i; xxd $i; LD_LIBRARY_PATH=./lib ./CGC_Hangman_Game < $i; echo -e "\n====================="
done

