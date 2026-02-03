IMAGE_NAME = wisefood/postgres-rw
IMAGE_TAG = latest

.PHONY: build
build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: push
push:
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: run
run:
	docker run -d --name postgres-nutrients -e POSTGRES_PASSWORD=postgres -p 5432:5432 $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: stop
stop:
	docker stop postgres-nutrients || true
	docker rm postgres-nutrients || true

.PHONY: clean
clean: stop
	docker rmi $(IMAGE_NAME):$(IMAGE_TAG) || true
