# Description
This project can to read hardware information from a Windows/MacOS/Linux device

# How To Build
## To Windows
```bash
GOOS=windows GOARCH=amd64 go build -o dist/device-info.exe device_info.go
```

## To Linux
```bash
GOOS=linux GOARCH=amd64 go build -o dist/linux-device-info device_info.go
```

## To Mac
```bash
GOOS=darwin GOARCH=amd64 go build -o dist/device-info device_info.go
```