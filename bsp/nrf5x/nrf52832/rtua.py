
def GetCPPPATH(BSP_ROOT, RTT_ROOT):
	CPPPATH=[
		RTT_ROOT + "/bsp/nrf5x/libraries/cmsis/include",
		RTT_ROOT + "/bsp/nrf5x/libraries/drivers",
		RTT_ROOT + "/bsp/nrf5x/nrf52832",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/applications",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/board",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/packages/littlefs-latest",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/packages/nrfx-latest",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/packages/nrfx-latest/drivers",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/packages/nrfx-latest/drivers/include",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/packages/nrfx-latest/drivers/src",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/packages/nrfx-latest/hal",
		RTT_ROOT + "/bsp/nrf5x/nrf52832/packages/nrfx-latest/mdk",
		RTT_ROOT + "/components/dfs/include",
		RTT_ROOT + "/components/drivers/include",
		RTT_ROOT + "/components/fal/inc",
		RTT_ROOT + "/components/finsh",
		RTT_ROOT + "/components/libc/compilers/common",
		RTT_ROOT + "/components/libc/compilers/newlib",
		RTT_ROOT + "/components/libc/posix/io/poll",
		RTT_ROOT + "/components/libc/posix/io/stdio",
		RTT_ROOT + "/components/libc/posix/ipc",
		RTT_ROOT + "/components/libc/posix/libdl",
		RTT_ROOT + "/components/utilities/ymodem",
		RTT_ROOT + "/include",
		RTT_ROOT + "/libcpu/arm/common",
		RTT_ROOT + "/libcpu/arm/cortex-m4",
	]

	return CPPPATH

def GetCPPDEFINES():
	CPPDEFINES=['LFS_CONFIG=lfs_config.h', '_POSIX_C_SOURCE=1', 'NRF52832_XXAA', '__RTTHREAD__', 'RT_USING_NEWLIB', 'USE_APP_CONFIG']
	return CPPDEFINES

