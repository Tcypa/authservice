FROM golang:latest AS builder

WORKDIR /authservice

COPY go.mod go.sum ./

RUN go mod download

ENV postgresURL=postgres://user:pass@db:5432/auth
ENV secret=veryverysecretsecret
ENV WebhookURL=WebhookURL:1234

COPY . .



RUN go build -o authservice ./main.go

EXPOSE 8080
CMD [ "./authservice" ]