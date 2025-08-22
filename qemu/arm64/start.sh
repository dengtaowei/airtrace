# 生成1G的空镜像文件
dd if=/dev/zero of=rootfs.img bs=1M count=1024
# 设定镜像文件系统格式
mkfs.ext4 rootfs.img
# 挂在镜像到一个空文件夹
mkdir fs
sudo mount -t ext4 rootfs.img fs
# 把rootfs内容拷贝到镜像文件夹fs
cp -r rootfs/* fs/.
# 搞定了，卸载镜像
sudo umount fs


qemu-system-aarch64 -machine virt,virtualization=true,gic-version=3 \
    -nographic -m size=1024M -cpu cortex-a57 -smp 4 \
    -kernel arch/arm64/boot/Image -hda rootfs.img -append "root=/dev/vda"