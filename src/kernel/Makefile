obj-m += flexpath.o
flexpath-y := netfilter.o path_selector.o packet_modifier.o main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
