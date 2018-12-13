all: build
	rm -rf /dev/shm/corpus
	docker run -it --rm -v /dev/shm:/dev/shm driller2
	cp /dev/shm/corpus/* ./target/corpus

build: clean
	docker build -t driller2 .

clean:
	~/docker_clean.sh || true

test: build
	docker run -it --privileged --rm -v ${PWD}:/job --entrypoint bash driller2
