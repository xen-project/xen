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
