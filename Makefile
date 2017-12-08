.NOTPARALLEL:
# A Makefile to rules the CMakeListses that rule the Makefiles that rule the Compiler drivers that rule the compiler pipeline

BUILD_TYPE = Debug
DEBUG_LVL ?= 0xC0000000L # only warnings/errors

.PHONY: oplk_stack oplk_stack_release oplk_stack_debug demo_mn demo_cn pcap_stack kernel_stack

define make_and_install
make -C $(dir $@)
make -C $(dir $@) install
endef

oplk_stack: oplk_stack_release oplk_stack_debug

oplk_stack_release: stack/build/linux/release/Makefile
	@echo :: Building OPLK Release Stack
	make_and_install

oplk_stack_debug: stack/build/linux/debug/Makefile
	@echo :: Building OPLK Debug Stack
	make_and_install

pcap_edrv: drivers/linux/drv_daemon_pcap/build/Makefile
	@echo :: Building PCAP Userspace daemon
	make_and_install

kernel_edrv: drivers/linux/drv_kernelmod_edrv/build/Makefile
	@echo :: Building Linux Edrv Kernel Module
	make_and_install

demo_mn: apps/demo_mn_console/build/linux/Makefile
	@echo :: Building Demo MN (console)
	make_and_install

demo_cn: apps/demo_cn_console/build/linux/Makefile
	@echo :: Building Demo CN (console)
	make_and_install

drivers/linux/drv_kernelmod_edrv/build:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $<)
	cmake -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ..

drivers/linux/drv_daemon_pcap/build/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $<) && cmake -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ..
%/release/Makefile:
	@echo :: Configuring for Release...
	dirname $< | xargs mkdir -p
	cd $(dir $<) && cmake -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=Release ../../..
%/debug/Makefile:
	@echo :: Configuring for Debug...
	dirname $< | xargs mkdir -p
	cd $(dir $<) && cmake -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=Debug ../../..
%/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $<) && cmake -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ../..

.PHONY: clean
clean:
	make -C stack/build/linux/release clean
	make -C stack/build/linux/debug clean
	make -C drivers/linux/drv_daemon_pcap/build clean
	make -C drivers/linux/drv_kernelmod_edrv/build clean
	make -C apps/demo_mn_console/build/linux clean
	make -C apps/demo_cn_console/build/linux clean

.PHONY: distclean
distclean:
	rm -rf stack/build/linux/release/*
	rm -rf stack/build/linux/debug/*
	rm -rf drivers/linux/drv_daemon_pcap/build/*
	rm -rf drivers/linux/drv_kernelmod_edrv/build/*
	rm -rf apps/demo_mn_console/build/linux/*
	rm -rf apps/demo_cn_console/build/linux/*
