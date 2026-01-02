# shellcheck disable=SC2148
# Build the image for the FriendlyElec NanoPi R3S-LTS Board
export BOARD="nanopi-r3s-lts"
# Use the current branch of armbian
export BRANCH="current"
# Use the noble/ubuntu "flavour" of armbian
export RELEASE="noble"
# Use a minimal/server build
export BUILD_MINIMAL="yes"
# Don't make changes to the linux kernel
export KERNEL_CONFIGURE="no"
# Only make a shallow copy of the kernel (https://docs.armbian.com/Developer-Guide_Welcome/#kernel-git-trees-shallow-vs-full)
export KERNEL_GIT="shallow"
# Pin the kernel to version 6.12.41
export KERNELBRANCH="tag:v6.12.41"