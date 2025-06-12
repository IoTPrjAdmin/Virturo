// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//!
//! Handles pattern lookup and matching.
//! In context of this application, patterns are binary bytes.
//!

use std::usize;

// Holds pattern item
#[derive(Debug, Clone)]
pub struct PatternItem {
    // To store pattern as bytes
    pub pattern: Vec<u8>,
    // count of items in buffer, in this case number of bytes in pattern
    pub count: usize,
    // pattern identifier, can be used to identify detected patterns
    pub id: u64,
}

// Used to hold patterns and abstract matching
#[derive(Debug, Clone)]
pub struct PatternsHolder {
    // Patterns vector, suitable for small amount of patterns
    patterns: Vec<PatternItem>,
    // Minimal size of the stored pattern
    min_len: usize,
    // Maximal size of the stored pattern
    max_len: usize,
    // Indicates whether empty pattern exists in patterns list
    empty_exists: bool,
}

impl PatternItem {
    pub fn new(pat_buff: &[u8], id: u64) -> Self {
        Self {
            pattern: pat_buff.to_vec(),
            count: pat_buff.len(),
            id,
        }
    }

    #[allow(dead_code)]
    pub fn new_empty(id: u64) -> Self {
        Self {
            pattern: Vec::new(),
            count: 0,
            id
        }
    }

    pub fn starts_with(&self, buff: &[u8]) -> bool {
        if buff.len() >= self.count {
            if buff.starts_with(&self.pattern) {
                return true;
            }
        }
        false
    }
}

impl PatternsHolder {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            min_len: usize::MAX,
            max_len: usize::MIN,
            empty_exists: false
        }
    }

    #[allow(dead_code)]
    pub fn new_with_capacity(expected_items: usize) -> Self {
        Self {
            patterns: Vec::with_capacity(expected_items),
            min_len: usize::MAX,
            max_len: usize::MIN,
            empty_exists: false,
        }
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.min_len = usize::MAX;
        self.max_len = usize::MIN;
        self.empty_exists = false;
    }

    // Add pattern item to list, return true if added
    // Pattern must have at least 1 item (byte)
    pub fn add(&mut self, id: u64, pat_buff: &[u8]) -> bool {
        let pat_buff_len = pat_buff.len();
        if pat_buff_len > 0 {
            self.patterns.push(PatternItem::new(pat_buff, id));
            /* Update min-max  */
            if pat_buff_len < self.min_len {
                self.min_len = pat_buff_len;
            }
            if pat_buff_len > self.max_len {
                self.max_len = pat_buff_len;
            }
            return true;
        }
        // TODO Add empty pattern without updating length
        // else {
        //     self.empty_exists = true;
        //     self.patterns.push(PatternItem::new_empty(id));
        // }
        false
    }

    // Sort by pattern length in descending order
    pub fn sort_by_len_desc(&mut self) {
        self.patterns.sort_by(|a, b| b.count.cmp(&a.count));
    }

    // Find longest pattern matching bytes given buffer start.
    // Return matched id or None
    // Buff must be at least of minimal length if no empty pattern exists
    pub fn match_pattern_starts_with(&self, buff: &[u8]) -> Option<u64> {
        let buff_len = buff.len();
        // Check if empty pattern exists,
        if (self.patterns.len() > 0)
            && (buff_len > self.min_len) {
            for item in &self.patterns {
                if item.starts_with(buff) == true {
                    return Some(item.id);
                }
            }
        }
        None
    }
}
