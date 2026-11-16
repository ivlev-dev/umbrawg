use core::ops::Range;

pub const MAX_GSO_SEGMENTS: usize = 64;
pub const MAX_GSO_GROUPS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GsoGroup {
    pub start: usize,
    pub segment_len: usize,
    pub segments: usize,
}

impl GsoGroup {
    pub const EMPTY: Self = Self {
        start: 0,
        segment_len: 0,
        segments: 0,
    };

    #[must_use]
    pub const fn end(&self) -> usize {
        self.start + self.segment_len * self.segments
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.segment_len * self.segments
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.segments == 0 || self.segment_len == 0
    }

    pub fn ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        let start = self.start;
        let segment = self.segment_len;
        (0..self.segments).map(move |index| {
            let offset = start + index * segment;
            offset..offset + segment
        })
    }
}

#[derive(Clone, Debug)]
pub struct BatchLayout {
    groups: [GsoGroup; MAX_GSO_GROUPS],
    len: usize,
}

impl BatchLayout {
    #[must_use]
    pub fn new() -> Self {
        Self {
            groups: [GsoGroup::EMPTY; MAX_GSO_GROUPS],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn push(&mut self, start: usize, segment_len: usize) -> bool {
        if segment_len == 0 {
            return true;
        }
        if let Some(last) = self.groups[..self.len].last_mut() {
            if last.segment_len == segment_len
                && last.end() == start
                && last.segments < MAX_GSO_SEGMENTS
            {
                last.segments += 1;
                return true;
            }
        }
        if self.len == MAX_GSO_GROUPS {
            return false;
        }
        self.groups[self.len] = GsoGroup {
            start,
            segment_len,
            segments: 1,
        };
        self.len += 1;
        true
    }

    #[must_use]
    pub fn groups(&self) -> &[GsoGroup] {
        &self.groups[..self.len]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn total_len(&self) -> usize {
        self.groups().iter().map(GsoGroup::len).sum()
    }
}

impl Default for BatchLayout {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct GroSegments {
    offset: usize,
    total: usize,
    segment: usize,
}

impl GroSegments {
    #[must_use]
    pub fn new(total: usize, segment: usize) -> Option<Self> {
        if segment == 0 || total == 0 {
            return None;
        }
        Some(Self {
            offset: 0,
            total,
            segment,
        })
    }

    #[must_use]
    pub const fn segment_len(&self) -> usize {
        self.segment
    }
}

impl Iterator for GroSegments {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.total {
            return None;
        }
        let start = self.offset;
        let end = (start + self.segment).min(self.total);
        self.offset = end;
        Some(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_packets_are_coalesced() {
        let mut layout = BatchLayout::new();
        assert!(layout.push(0, 32));
        assert!(layout.push(32, 32));
        assert!(layout.push(64, 32));
        assert_eq!(layout.len(), 1);
        assert_eq!(
            layout.groups()[0],
            GsoGroup {
                start: 0,
                segment_len: 32,
                segments: 3
            }
        );
        assert_eq!(layout.total_len(), 96);
        assert_eq!(
            layout.groups()[0].ranges().collect::<Vec<_>>(),
            vec![0..32, 32..64, 64..96]
        );
    }

    #[test]
    fn different_sizes_start_a_new_group() {
        let mut layout = BatchLayout::new();
        assert!(layout.push(0, 32));
        assert!(layout.push(32, 32));
        assert!(layout.push(64, 40));
        assert!(layout.push(104, 32));
        assert_eq!(layout.len(), 3);
        assert_eq!(layout.groups()[1].segment_len, 40);
        assert_eq!(layout.groups()[1].segments, 1);
    }

    #[test]
    fn groups_are_limited() {
        let mut layout = BatchLayout::new();
        for index in 0..MAX_GSO_GROUPS {
            assert!(layout.push(index * 2, index + 1));
        }
        assert!(!layout.push(MAX_GSO_GROUPS * 4, 100));
    }

    #[test]
    fn empty_segments_are_ignored() {
        let mut layout = BatchLayout::new();
        assert!(layout.push(0, 0));
        assert!(layout.is_empty());
        assert_eq!(layout.total_len(), 0);
    }

    #[test]
    fn gro_segments_split_evenly_and_keep_the_tail() {
        let segments: Vec<_> = GroSegments::new(100, 32).unwrap().collect();
        assert_eq!(segments, vec![0..32, 32..64, 64..96, 96..100]);
        assert!(GroSegments::new(100, 0).is_none());
        assert!(GroSegments::new(0, 32).is_none());
    }

    #[test]
    fn group_helpers() {
        let group = GsoGroup {
            start: 10,
            segment_len: 20,
            segments: 2,
        };
        assert_eq!(group.end(), 50);
        assert_eq!(group.len(), 40);
        assert!(!group.is_empty());
        assert!(GsoGroup::EMPTY.is_empty());
    }
}
