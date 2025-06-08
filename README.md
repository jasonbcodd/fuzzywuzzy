# fuzzywuzzy
[![Tests](https://github.com/GeorgeMuscat/fuzzywuzzy/actions/workflows/test.yml/badge.svg)](https://github.com/GeorgeMuscat/fuzzywuzzy/actions/workflows/test.yml)

## Setup
- Install Python 3.12:
    - MacOS: `brew install python@3.12`
    - Linux: *figure it out*
- Install 32-bit support, including for `libc` and `gcc` (for building test binaries):
```bash
sudo dpkg --add-architecture i386
sudo apt-get -y update
sudo apt-get install -y libc6:i386 gcc-multilib g++-multilib
```
- Install packages: `uv install`

## Poetry Commands
- Install: `uv install`
- Run command in venv: `uv run`

## Running Tests
To run all tests, run `pytest` (inside a Poetry shell, `uv run pytest` outside).

