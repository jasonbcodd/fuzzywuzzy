all: hang safe segv harness_32 harness_64

harness_32: src/fuzzer/harness/harness.c src/fuzzer/harness/harness.h src/fuzzer/harness/hooks.c src/fuzzer/harness/hooks.h src/fuzzer/harness/socket.c src/fuzzer/harness/socket.h src/fuzzer/harness/hooks.def.h
	gcc -std=c23 -O3 -m32 -fPIC -shared -Wl,--no-undefined -rdynamic src/fuzzer/harness/harness.c src/fuzzer/harness/hooks.c src/fuzzer/harness/socket.c -o src/fuzzer/harness/harness_32.so -ldl

harness_64: src/fuzzer/harness/harness.c src/fuzzer/harness/harness.h src/fuzzer/harness/hooks.c src/fuzzer/harness/hooks.h src/fuzzer/harness/socket.c src/fuzzer/harness/socket.h src/fuzzer/harness/hooks.def.h
	gcc -std=c23 -O3 -fPIC -shared -Wl,--no-undefined -rdynamic src/fuzzer/harness/harness.c src/fuzzer/harness/hooks.c src/fuzzer/harness/socket.c -o src/fuzzer/harness/harness_64.so -ldl

hang: tests/binaries/hang/hang.c
	gcc -z execstack -fno-pie -fno-stack-protector -z norelro -m32 -g -o tests/binaries/hang/hang tests/binaries/hang/hang.c

safe: tests/binaries/safe/safe.c
	gcc -z execstack -fno-pie -fno-stack-protector -z norelro -m32 -g -o tests/binaries/safe/safe tests/binaries/safe/safe.c

segv: tests/binaries/segv/segv.c
	gcc -z execstack -fno-pie -fno-stack-protector -z norelro -m32 -g -o tests/binaries/segv/segv tests/binaries/segv/segv.c

scripts: pyproject.toml
	uv pip install -e .

