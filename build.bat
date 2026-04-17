@echo off

set app=backpipe

go mod init %app%
go mod tidy

set "LDFLAGS=-s -w -buildid= -checklinkname=0"
set "BUILD_FLAGS=-buildvcs=false -trimpath"

SET GOOS=windows
SET GOARCH=amd64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%.exe

SET GOOS=linux
SET GOARCH=amd64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%
