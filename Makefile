all: build

build:
	dotnet publish ipk-l4-scan.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o ./

clean:
	rm -r ipk-l4-scan bin obj *.pdb
	dotnet clean

zip:
	zip -r ipk-l4-scan.zip * -x "obj/*" "bin/*" "*.pdb" "doc/"

send:
	scp ipk-l4-scan.zip xhatal02@merlin.fit.vutbr.cz:/homes/eva/xh/xhatal02

.PHONY: all build clean
