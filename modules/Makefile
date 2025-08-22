obj-m := drv_simulator.o
KDIR := ../kheaders/arm
# KDIR := /lib/modules/6.6.23/build
# KDIR := /home/anlan/Desktop/perf/linux-6.6.23/
PWD := $(shell pwd)

export ARCH = arm
export CROSS_COMPILE = arm-linux-gnueabi-

# CC = arm-linux-gnueabi-gcc

all:
	make -C $(KDIR) M=$(PWD) modules
	cp ./drv_simulator.ko ~/Desktop/nfs_share

clean:
	make -C $(KDIR) M=$(PWD) clean