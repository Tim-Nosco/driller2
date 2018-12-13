all: build
	docker run -it --rm -v /dev/shm:/dev/shm driller2 -v DEBUG -i /job/target/corpus/0 -l /job/target/lib /job/target/CGC_Hangman_Game
	cp /dev/shm/corpus/* ./target/corpus

log: build
	docker run -i -w /job/target --rm --entrypoint /job/target/test.sh driller2 | tee log.txt

build: clean
	docker build -t driller2 .

clean:
	~/docker_clean.sh || true

test: build
	docker run -it --privileged --rm -v ${PWD}:/job --entrypoint bash driller2
