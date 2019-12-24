set -ex && mkdir -p build/release/bin
set -ex && docker create --name worktips-daemon-container worktips-daemon-image
set -ex && docker cp worktips-daemon-container:/usr/local/bin/ build/release/
set -ex && docker rm worktips-daemon-container
