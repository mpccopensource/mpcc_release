KBUILD_EXTRA_SYMBOLS := /usr/src/linux-headers-$(shell uname -r)/Module.symvers
obj-m += tcp_mpcc.o tcp_mpcc_loss.o mptcp_pacing_sched.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
