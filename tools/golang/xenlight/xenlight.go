/*
 * Copyright (C) 2016 George W. Dunlap, Citrix Systems UK Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */
package xenlight

/*
#cgo LDFLAGS: -lxenlight -lyajl -lxentoollog
#include <stdlib.h>
#include <libxl.h>
*/
import "C"

/*
 * Other flags that may be needed at some point:
 *  -lnl-route-3 -lnl-3
 *
 * To get back to static linking:
 * #cgo LDFLAGS: -lxenlight -lyajl_s -lxengnttab -lxenstore -lxenguest -lxentoollog -lxenevtchn -lxenctrl -lblktapctl -lxenforeignmemory -lxencall -lz -luuid -lutil
 */

import (
	"fmt"
	"unsafe"
)

/*
 * Errors
 */

type Error int

const (
	ErrorNonspecific                  = Error(-C.ERROR_NONSPECIFIC)
	ErrorVersion                      = Error(-C.ERROR_VERSION)
	ErrorFail                         = Error(-C.ERROR_FAIL)
	ErrorNi                           = Error(-C.ERROR_NI)
	ErrorNomem                        = Error(-C.ERROR_NOMEM)
	ErrorInval                        = Error(-C.ERROR_INVAL)
	ErrorBadfail                      = Error(-C.ERROR_BADFAIL)
	ErrorGuestTimedout                = Error(-C.ERROR_GUEST_TIMEDOUT)
	ErrorTimedout                     = Error(-C.ERROR_TIMEDOUT)
	ErrorNoparavirt                   = Error(-C.ERROR_NOPARAVIRT)
	ErrorNotReady                     = Error(-C.ERROR_NOT_READY)
	ErrorOseventRegFail               = Error(-C.ERROR_OSEVENT_REG_FAIL)
	ErrorBufferfull                   = Error(-C.ERROR_BUFFERFULL)
	ErrorUnknownChild                 = Error(-C.ERROR_UNKNOWN_CHILD)
	ErrorLockFail                     = Error(-C.ERROR_LOCK_FAIL)
	ErrorJsonConfigEmpty              = Error(-C.ERROR_JSON_CONFIG_EMPTY)
	ErrorDeviceExists                 = Error(-C.ERROR_DEVICE_EXISTS)
	ErrorCheckpointDevopsDoesNotMatch = Error(-C.ERROR_CHECKPOINT_DEVOPS_DOES_NOT_MATCH)
	ErrorCheckpointDeviceNotSupported = Error(-C.ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED)
	ErrorVnumaConfigInvalid           = Error(-C.ERROR_VNUMA_CONFIG_INVALID)
	ErrorDomainNotfound               = Error(-C.ERROR_DOMAIN_NOTFOUND)
	ErrorAborted                      = Error(-C.ERROR_ABORTED)
	ErrorNotfound                     = Error(-C.ERROR_NOTFOUND)
	ErrorDomainDestroyed              = Error(-C.ERROR_DOMAIN_DESTROYED)
	ErrorFeatureRemoved               = Error(-C.ERROR_FEATURE_REMOVED)
)

var errors = [...]string{
	ErrorNonspecific:                  "Non-specific error",
	ErrorVersion:                      "Wrong version",
	ErrorFail:                         "Failed",
	ErrorNi:                           "Not Implemented",
	ErrorNomem:                        "No memory",
	ErrorInval:                        "Invalid argument",
	ErrorBadfail:                      "Bad Fail",
	ErrorGuestTimedout:                "Guest timed out",
	ErrorTimedout:                     "Timed out",
	ErrorNoparavirt:                   "No Paravirtualization",
	ErrorNotReady:                     "Not ready",
	ErrorOseventRegFail:               "OS event registration failed",
	ErrorBufferfull:                   "Buffer full",
	ErrorUnknownChild:                 "Unknown child",
	ErrorLockFail:                     "Lock failed",
	ErrorJsonConfigEmpty:              "JSON config empty",
	ErrorDeviceExists:                 "Device exists",
	ErrorCheckpointDevopsDoesNotMatch: "Checkpoint devops does not match",
	ErrorCheckpointDeviceNotSupported: "Checkpoint device not supported",
	ErrorVnumaConfigInvalid:           "VNUMA config invalid",
	ErrorDomainNotfound:               "Domain not found",
	ErrorAborted:                      "Aborted",
	ErrorNotfound:                     "Not found",
	ErrorDomainDestroyed:              "Domain destroyed",
	ErrorFeatureRemoved:               "Feature removed",
}

func (e Error) Error() string {
	if 0 < int(e) && int(e) < len(errors) {
		s := errors[e]
		if s != "" {
			return s
		}
	}
	return fmt.Sprintf("libxl error: %d", -e)

}

/*
 * Types: Builtins
 */

type Context struct {
	ctx    *C.libxl_ctx
	logger *C.xentoollog_logger_stdiostream
}

type Hwcap []C.uint32_t

func (chwcap C.libxl_hwcap) CToGo() (ghwcap Hwcap) {
	// Alloc a Go slice for the bytes
	size := 8
	ghwcap = make([]C.uint32_t, size)

	// Make a slice pointing to the C array
	mapslice := (*[1 << 30]C.uint32_t)(unsafe.Pointer(&chwcap[0]))[:size:size]

	// And copy the C array into the Go array
	copy(ghwcap, mapslice)

	return
}

/*
 * Types: IDL
 *
 * FIXME: Generate these automatically from the IDL
 */

type Physinfo struct {
	ThreadsPerCore    uint32
	CoresPerSocket    uint32
	MaxCpuId          uint32
	NrCpus            uint32
	CpuKhz            uint32
	TotalPages        uint64
	FreePages         uint64
	ScrubPages        uint64
	OutstandingPages  uint64
	SharingFreedPages uint64
	SharingUsedFrames uint64
	NrNodes           uint32
	HwCap             Hwcap
	CapHvm            bool
	CapHvmDirectio    bool
}

func (cphys *C.libxl_physinfo) toGo() (physinfo *Physinfo) {

	physinfo = &Physinfo{}
	physinfo.ThreadsPerCore = uint32(cphys.threads_per_core)
	physinfo.CoresPerSocket = uint32(cphys.cores_per_socket)
	physinfo.MaxCpuId = uint32(cphys.max_cpu_id)
	physinfo.NrCpus = uint32(cphys.nr_cpus)
	physinfo.CpuKhz = uint32(cphys.cpu_khz)
	physinfo.TotalPages = uint64(cphys.total_pages)
	physinfo.FreePages = uint64(cphys.free_pages)
	physinfo.ScrubPages = uint64(cphys.scrub_pages)
	physinfo.ScrubPages = uint64(cphys.scrub_pages)
	physinfo.SharingFreedPages = uint64(cphys.sharing_freed_pages)
	physinfo.SharingUsedFrames = uint64(cphys.sharing_used_frames)
	physinfo.NrNodes = uint32(cphys.nr_nodes)
	physinfo.HwCap = cphys.hw_cap.CToGo()
	physinfo.CapHvm = bool(cphys.cap_hvm)
	physinfo.CapHvmDirectio = bool(cphys.cap_hvm_directio)

	return
}

type VersionInfo struct {
	XenVersionMajor int
	XenVersionMinor int
	XenVersionExtra string
	Compiler        string
	CompileBy       string
	CompileDomain   string
	CompileDate     string
	Capabilities    string
	Changeset       string
	VirtStart       uint64
	Pagesize        int
	Commandline     string
	BuildId         string
}

func (cinfo *C.libxl_version_info) toGo() (info *VersionInfo) {
	info = &VersionInfo{}
	info.XenVersionMajor = int(cinfo.xen_version_major)
	info.XenVersionMinor = int(cinfo.xen_version_minor)
	info.XenVersionExtra = C.GoString(cinfo.xen_version_extra)
	info.Compiler = C.GoString(cinfo.compiler)
	info.CompileBy = C.GoString(cinfo.compile_by)
	info.CompileDomain = C.GoString(cinfo.compile_domain)
	info.CompileDate = C.GoString(cinfo.compile_date)
	info.Capabilities = C.GoString(cinfo.capabilities)
	info.Changeset = C.GoString(cinfo.changeset)
	info.VirtStart = uint64(cinfo.virt_start)
	info.Pagesize = int(cinfo.pagesize)
	info.Commandline = C.GoString(cinfo.commandline)
	info.BuildId = C.GoString(cinfo.build_id)

	return
}

/*
 * Context
 */
var Ctx Context

func (Ctx *Context) IsOpen() bool {
	return Ctx.ctx != nil
}

func (Ctx *Context) Open() (err error) {
	if Ctx.ctx != nil {
		return
	}

	Ctx.logger = C.xtl_createlogger_stdiostream(C.stderr, C.XTL_ERROR, 0)
	if Ctx.logger == nil {
		err = fmt.Errorf("Cannot open stdiostream")
		return
	}

	ret := C.libxl_ctx_alloc(&Ctx.ctx, C.LIBXL_VERSION,
		0, unsafe.Pointer(Ctx.logger))

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

func (Ctx *Context) Close() (err error) {
	ret := C.libxl_ctx_free(Ctx.ctx)
	Ctx.ctx = nil

	if ret != 0 {
		err = Error(-ret)
	}
	C.xtl_logger_destroy(unsafe.Pointer(Ctx.logger))
	return
}

func (Ctx *Context) CheckOpen() (err error) {
	if Ctx.ctx == nil {
		err = fmt.Errorf("Context not opened")
	}
	return
}

//int libxl_get_max_cpus(libxl_ctx *ctx);
func (Ctx *Context) GetMaxCpus() (maxCpus int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_get_max_cpus(Ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	maxCpus = int(ret)
	return
}

//int libxl_get_online_cpus(libxl_ctx *ctx);
func (Ctx *Context) GetOnlineCpus() (onCpus int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_get_online_cpus(Ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	onCpus = int(ret)
	return
}

//int libxl_get_max_nodes(libxl_ctx *ctx);
func (Ctx *Context) GetMaxNodes() (maxNodes int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}
	ret := C.libxl_get_max_nodes(Ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	maxNodes = int(ret)
	return
}

//int libxl_get_free_memory(libxl_ctx *ctx, uint64_t *memkb);
func (Ctx *Context) GetFreeMemory() (memkb uint64, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}
	var cmem C.uint64_t
	ret := C.libxl_get_free_memory(Ctx.ctx, &cmem)

	if ret < 0 {
		err = Error(-ret)
		return
	}

	memkb = uint64(cmem)
	return

}

//int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo)
func (Ctx *Context) GetPhysinfo() (physinfo *Physinfo, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}
	var cphys C.libxl_physinfo
	C.libxl_physinfo_init(&cphys)
	defer C.libxl_physinfo_dispose(&cphys)

	ret := C.libxl_get_physinfo(Ctx.ctx, &cphys)

	if ret < 0 {
		err = Error(ret)
		return
	}
	physinfo = cphys.toGo()

	return
}

//const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx);
func (Ctx *Context) GetVersionInfo() (info *VersionInfo, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	var cinfo *C.libxl_version_info

	cinfo = C.libxl_get_version_info(Ctx.ctx)

	info = cinfo.toGo()

	return
}
