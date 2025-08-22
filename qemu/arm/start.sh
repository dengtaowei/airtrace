qemu-system-arm \
	-M vexpress-a9 \
	-m 512M -kernel ./zImage \
	-dtb ./vexpress-v2p-ca9.dtb \
	-nographic \
	-append "root=/dev/mmcblk0 rw console=ttyAMA0 rootwait rootfstype=ext4" \
	-sd ./rootfs.ext4



ip addr add 10.0.2.15/24 dev eth0
ip link set eth0 up
ip route add default via 10.0.2.2

mount -t nfs -o nolock 192.168.1.17:/home/anlan/Desktop/nfs_share /mnt



anlan@anlan:~/Desktop/airtrace/qemu/arm$ dd if=/dev/zero of=rootfs.ext4 bs=1M count=32
anlan@anlan:~/Desktop/airtrace/qemu/arm$ mkfs.ext4 rootfs.ext4
anlan@anlan:~/Desktop/airtrace/qemu/arm$ sudo mount -t ext4 rootfs.ext4 /mnt -o loop
anlan@anlan:~/Desktop/airtrace/qemu/arm$ sudo cp -r perf/rootfs/* /mnt
anlan@anlan:~/Desktop/airtrace/qemu/arm$ sudo umount mnt



make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- modules_install INSTALL_MOD_PATH=/home/anlan/Desktop/airtrace/3rdparty/kheaders/armtmp