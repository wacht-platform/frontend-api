FROM golang:1.23.4-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o ./api-server ./main.go


FROM alpine:latest AS runner
WORKDIR /app
COPY --from=builder /app/api-server .
EXPOSE 3000
ENTRYPOINT ["./api-server"]
