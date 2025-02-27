all: build

build:
	dotnet publish ipk-l4-scan.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o ./

clean:
	rm -r ipk-l4-scan bin obj *.pdb
	dotnet clean

.PHONY: all build clean