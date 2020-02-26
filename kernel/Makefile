obj-m := strongbox.o
CC = gcc -Wall -std=c11
PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
test:
	-sudo rmmod strongbox.ko
	sudo insmod strongbox.ko