FROM golang:1.24-alpine

RUN go install github.com/air-verse/air@latest

ARG workdir

WORKDIR /app/${workdir}

CMD ["air"]
