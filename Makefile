all: clean
	docker build -t driller2 .
	docker run -it --rm driller2

clean:
	~/docker_clean.sh || true

test: clean
	docker run -it --rm -v ${PWD}:/job driller2