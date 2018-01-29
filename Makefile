# A Makefile to rules the $(CMAKE)Listses that rule the Makefiles that rule the Compiler drivers that rule the compiler pipeline

-include local-testing.mk # to override some opts here

BUILD_TYPE = Debug
DEBUG_LVL ?= 0xC0000000L # only warnings/errors
CMAKE     ?= cmake
CCMAKE    ?= ccmake
SLAVE_IF  ?= enp0s8
ARCH      ?= x86_64
QDISC     ?= 0
NETPOLL   ?= 1

MODOPTS   := slave_interface=$(SLAVE_IF) use_qdisc=$(QDISC) use_netpoll=$(NETPOLL) $(MODOPTS)

.PHONY: oplk oplk_stack oplk_stack_release oplk_stack_debug pcp_edrv kernel_edrv demo_mn demo_cn pcap_stack kernel_stack test_rpi test_bridge select_drivers configure_demo_mn

define make_and_install
$(MAKE) -C $(dir $<)
$(MAKE) -C $(dir $<) install
endef

oplk: oplk_stack kernel_edrv demo_mn

set_freq: bin/linux/$(ARCH)/demo_mn_console/mnobd.cdc
	@perl -e 'open FH,"+<$<"; binmode(FH); seek(FH,92,0); print FH pack("S", 1000*<>)'
get_freq: bin/linux/$(ARCH)/demo_mn_console/mnobd.cdc
	@perl -e 'open FH,"$<"; binmode(FH); seek(FH,92,0); read FH, $$_, 2; printf "%gms\n", 0.001*unpack "S", $$_'

unload: bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkunload oplksmsc95xxmn.ko || echo Nothing to unload
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkunload oplk82573mn.ko || echo Nothing to unload
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkunload oplkgeneric_bridgemn.ko || echo Nothing to unload
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkunload oplkgeneric_rawsockmn.ko || echo Nothing to unload

test_rpi: bin/linux/$(ARCH)/demo_mn_console/demo_mn_console bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv/oplksmsc95xxmn.ko
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkload oplksmsc95xxmn.ko
	cd bin/linux/$(ARCH)/demo_mn_console && sudo ./demo_mn_console

test_stock: bin/linux/$(ARCH)/demo_mn_console/demo_mn_console bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv/oplk82573mn.ko
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkunload oplk82573mn.ko || echo Nothing to unload
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkload oplk82573mn.ko
	cd bin/linux/$(ARCH)/demo_mn_console && sudo ./demo_mn_console

test_bridge: bin/linux/$(ARCH)/demo_mn_console/demo_mn_console bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv/oplkgeneric_bridgemn.ko
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkunload oplkgeneric_bridgemn.ko || echo Nothing to unload
	sudo ifconfig $(SLAVE_IF) down
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkload oplkgeneric_bridgemn.ko $(MODOPTS)
	cd bin/linux/$(ARCH)/demo_mn_console && sudo ./demo_mn_console

test_rawsock: bin/linux/$(ARCH)/demo_mn_console/demo_mn_console bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv/oplkgeneric_rawsockmn.ko
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkunload oplkgeneric_rawsockmn.ko || echo Nothing to unload
	cd bin/linux/$(ARCH)/oplkdrv_kernelmodule_edrv && sudo ./plkload oplkgeneric_rawsockmn.ko $(MODOPTS)
	cd bin/linux/$(ARCH)/demo_mn_console && sudo ./demo_mn_console

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

configure_demo_mn:
	cd apps/demo_mn_console/build/linux && ccmake -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ../..

drivers/linux/drv_kernelmod_edrv/build/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $@) && $(CMAKE) -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ..
drivers/linux/drv_daemon_pcap/build/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $@) && $(CMAKE) -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ..
apps/demo_mn_console/build/linux/Makefile:
	@echo :: Configuring for ${BUILD_TYPE}...
	cd $(dir $@) && $(CMAKE) -DCFG_OPLK_MN=TRUE -DCFG_DEBUG_LVL=${DEBUG_LVL} -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCFG_BUILD_KERNEL_STACK="Linux Kernel Module" ../..

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
	$(MAKE) -C stack/build/linux/release clean || true
	$(MAKE) -C stack/build/linux/debug clean || true
	$(MAKE) -C drivers/linux/drv_daemon_pcap/build clean || true
	$(MAKE) -C drivers/linux/drv_kernelmod_edrv/build clean || true
	$(MAKE) -C apps/demo_mn_console/build/linux clean || true
	$(MAKE) -C apps/demo_cn_console/build/linux clean || true

.PHONY: distclean
distclean:
	rm -rf stack/build/linux/release/*
	rm -rf stack/build/linux/debug/*
	rm -rf drivers/linux/drv_daemon_pcap/build/*
	rm -rf drivers/linux/drv_kernelmod_edrv/build/*
	rm -rf apps/demo_mn_console/build/linux/*
	rm -rf apps/demo_cn_console/build/linux/*
