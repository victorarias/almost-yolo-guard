#!/bin/bash
set -e

cd "$(dirname "$0")/../src"

echo "Building almost-yolo-guard..."
go build -o ../bin/almost-yolo-guard

echo "almost-yolo-guard built successfully"
echo "Log location: ~/.config/almost-yolo-guard/decisions.log"
