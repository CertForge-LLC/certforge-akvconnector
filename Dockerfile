FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.Version=${VERSION}" -o /certforge-akvconnector .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /certforge-akvconnector /certforge-akvconnector
ENTRYPOINT ["/certforge-akvconnector"]
