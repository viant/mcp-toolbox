package service

import (
	"reflect"

	"github.com/tebeka/selenium"
)

// isNilWebDriver guards against "typed nil" interfaces (e.g. a nil *Remote stored in a WebDriver interface).
func isNilWebDriver(driver selenium.WebDriver) bool {
	if driver == nil {
		return true
	}
	v := reflect.ValueOf(driver)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
