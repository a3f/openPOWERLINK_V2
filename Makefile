# A Makefile to rules the $(CMAKE)Listses that rule the Makefiles that rule the Compiler drivers that rule the compiler pipeline

BUILD_TYPE = Debug
DEBUG_LVL ?= 0xC0000000L # only warnings/errors
CMAKE     ?= cmake
CCMAKE    ?= ccmake

.PHONY: oplk_stack oplk_stack_release oplk_stack_debug demo_mn demo_cn pcap_stack kernel_stack

define make_and_install
make -C $(dir $<)
make -C $(dir $<) install
endef

oplk: oplk_stack kernel_edrv demo_cn

oplk_stack: oplk_stack_release oplk_stack_debug

oplk_stack_release: stack/build/linux/release/Makefile
	@echo :: Building OPLK Release Stack
	$(make_and_install)

oplk_stack_debug: stack/build/linux/debug/Makefile
	@echo :: Building OPLK Debug Stack
	$(make_and_install)

pcap_edrv: drivers/linux/drv_daemon_pcap/build/Makefile
	@echo :: Building PCAP Userspace daemon
	$(make_and_install)

kernel_edrv: drivers/linux/drv_kernelmod_edrv/build/Makefile
	@echo :: Building Linux Edrv Kernel Module
	$(make_and_install)

demo_mn: apps/demo_mn_console/build/linux/Makefile
	@echo ":: Building Demo MN (console)"
	$(make_and_install)

demo_cn: apps/demo_cn_console/build/linux/Makefile
	@echo ":: Building Demo CN (console)"
	$(make_and_install)


select_drivers:
	cd drivers/linux/drv_kernelmod_edrv/build && ccmake -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ..
drivers/linux/drv_kernelmod_edrv/build/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $@) && $(CMAKE) -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ..
drivers/linux/drv_daemon_pcap/build/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $@) && $(CMAKE) -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ..
%/release/Makefile:
	@echo :: Configuring for Release...
	mkdir -p $(dir $@)
	cd $(dir $@) && $(CMAKE) -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=Release ../../..
%/debug/Makefile:
	@echo :: Configuring for Debug...
	mkdir -p $(dir $@)
	cd $(dir $@) && $(CMAKE) -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=Debug ../../..
%/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $@) && $(CMAKE) -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ../..

.PHONY: clean
clean:
	rm -rf bin/linux
	make -C stack/build/linux/release clean || true
	make -C stack/build/linux/debug clean || true
	make -C drivers/linux/drv_daemon_pcap/build clean || true
	make -C drivers/linux/drv_kernelmod_edrv/build clean || true
	make -C apps/demo_mn_console/build/linux clean || true
	make -C apps/demo_cn_console/build/linux clean || true

.PHONY: distclean
distclean:
	rm -rf stack/build/linux/release/*
	rm -rf stack/build/linux/debug/*
	rm -rf drivers/linux/drv_daemon_pcap/build/*
	rm -rf drivers/linux/drv_kernelmod_edrv/build/*
	rm -rf apps/demo_mn_console/build/linux/*
	rm -rf apps/demo_cn_console/build/linux/*
