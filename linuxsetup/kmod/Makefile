obj-m += kmod.o

kmod-y += source/main.o
kmod-y += source/region.o
kmod-y += source/sysregs.o
kmod-y += source/uncore-pmu.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
