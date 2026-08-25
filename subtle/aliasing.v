module subtle

// NOTE: require unsafe in future
// any_overlap reports whether x and y share memory at any (not necessarily
// corresponding) index. The memory beyond the slice length is ignored.
pub fn any_overlap(x []u8, y []u8) bool {
	// NOTE: Remember to come back to this (joe-c)
	return x.len > 0 && y.len > 0 && // &x.data[0] <= &y.data[y.len-1] &&
	// &y.data[0] <= &x.data[x.len-1]
	unsafe { &x[0] <= &y[y.len - 1] && &y[0] <= &x[x.len - 1] }
}

// inexact_overlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
pub fn inexact_overlap(x []u8, y []u8) bool {
	if x.len == 0 || y.len == 0 || unsafe { &x[0] == &y[0] } {
		return false
	}

	return any_overlap(x, y)
}
