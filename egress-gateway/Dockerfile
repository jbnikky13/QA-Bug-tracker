FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/egress-gateway .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/egress-gateway /egress-gateway
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/egress-gateway"]
