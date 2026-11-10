package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation
#import <Foundation/Foundation.h>
#include <stdlib.h>

// Newline-separated [NSLocale preferredLanguages] ("ru-UZ", "en-US"…):
// what the user set in System Settings → General → Language & Region,
// including a per-app override. GUI apps get no LANG to read instead.
static char *ingressPreferredLanguages(void) {
	@autoreleasepool {
		NSString *s = [[NSLocale preferredLanguages] componentsJoinedByString:@"\n"];
		return strdup([s UTF8String]);
	}
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

func systemLanguages() []string {
	c := C.ingressPreferredLanguages()
	defer C.free(unsafe.Pointer(c))
	return append(strings.Split(C.GoString(c), "\n"), envLanguages()...)
}
