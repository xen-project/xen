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
		err = fmt.Errorf("Error: %d", -ret)
	}
	return
}

func (Ctx *Context) Close() (err error) {
	ret := C.libxl_ctx_free(Ctx.ctx)
	Ctx.ctx = nil

	if ret != 0 {
		err = fmt.Errorf("Error: %d", -ret)
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
