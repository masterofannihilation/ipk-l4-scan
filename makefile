all: build

build:
	dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o ./

clean:
	dotnet clean

.PHONY: all build clean