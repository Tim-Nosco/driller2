all: build
	docker run -it --rm driller2

build: clean
	docker build -t driller2 .

clean:
	~/docker_clean.sh || true

test: build
	docker run -it --rm -v ${PWD}:/job driller2