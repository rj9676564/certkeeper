FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w \
    -X github.com/rj9676564/certkeeper/internal/version.Version=${VERSION} \
    -X github.com/rj9676564/certkeeper/internal/version.Commit=${COMMIT} \
    -X github.com/rj9676564/certkeeper/internal/version.Date=${DATE}" \
    -o /out/certkeeper ./cmd/certkeeper

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata docker-cli
COPY --from=build /out/certkeeper /usr/local/bin/certkeeper
ENTRYPOINT ["certkeeper"]
CMD ["daemon", "--config", "/config/config.yaml"]
