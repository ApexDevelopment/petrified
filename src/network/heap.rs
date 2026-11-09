//! A port of Go's `container/heap`, so queue ordering follows the same algorithm.

pub(crate) trait HeapInterface {
	fn len(&self) -> usize;
	fn less(&self, i: usize, j: usize) -> bool;
	fn swap(&mut self, i: usize, j: usize);
	/// Removes the last element.
	fn pop_last(&mut self);
}

pub(crate) fn fix<H: HeapInterface>(h: &mut H, i: usize) {
	if !down(h, i, h.len()) {
		up(h, i);
	}
}

pub(crate) fn remove<H: HeapInterface>(h: &mut H, i: usize) {
	let n = h.len() - 1;
	if n != i {
		h.swap(i, n);
		if !down(h, i, n) {
			up(h, i);
		}
	}
	h.pop_last();
}

fn up<H: HeapInterface>(h: &mut H, mut j: usize) {
	while j > 0 {
		let i = (j - 1) / 2;
		if !h.less(j, i) {
			break;
		}
		h.swap(i, j);
		j = i;
	}
}

fn down<H: HeapInterface>(h: &mut H, i0: usize, n: usize) -> bool {
	let mut i = i0;
	loop {
		let j1 = 2 * i + 1;
		if j1 >= n {
			break;
		}
		let mut j = j1;
		let j2 = j1 + 1;
		if j2 < n && h.less(j2, j1) {
			j = j2;
		}
		if !h.less(j, i) {
			break;
		}
		h.swap(i, j);
		i = j;
	}
	i > i0
}
