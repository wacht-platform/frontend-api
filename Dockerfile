FROM golang:1.24.2-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o ./api-server ./main.go


FROM alpine:latest AS runner
WORKDIR /app
COPY --from=builder /app/api-server .
EXPOSE 3000
ENTRYPOINT ["./api-server"]
