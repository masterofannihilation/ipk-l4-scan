all: build

build:
	dotnet publish ipk-l4-scan.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o ./

clean:
	rm -r ipk-l4-scan bin obj *.pdb
	dotnet clean

zip:
	zip -r xhatal02.zip * -x "obj/*" "bin/*" "*.pdb" "doc/"

send:
	scp xhatal02.zip xhatal02@merlin.fit.vutbr.cz:/homes/eva/xh/xhatal02

.PHONY: all build clean
