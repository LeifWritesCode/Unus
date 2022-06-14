FROM golang:alpine

# need gcc for go-sqlite3
RUN apk add --no-cache gcc musl-dev

# create staging directory
WORKDIR /app

# copy in only what we need to fetch dependences
COPY go.mod .
COPY go.sum .

# fetch dependencies of unus
RUN go mod download

# now import everything else
COPY . .

# build unus
RUN go build ./cmd/unus

# expose our http port
EXPOSE 8080

# start unus
CMD ["./unus"]
