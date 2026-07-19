//! [`FileUpload`] - modal-only file uploader.  Discord component type
//! `19`.  Submitted values are Fancy Mumble file ids referencing
//! uploads the client has staged for this interaction.

use serde::{Deserialize, Serialize};

use super::Component;

/// Modal-only file upload field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUpload {
    /// Echoed in the modal-submit payload.
    pub custom_id: String,
    /// Minimum files required (default 1).
    #[serde(default = "default_min")]
    pub min_values: u32,
    /// Maximum files accepted (default 1, hard max 10).
    #[serde(default = "default_max")]
    pub max_values: u32,
    /// Whether at least one file is required.
    #[serde(default = "default_required")]
    pub required: bool,
}

fn default_min() -> u32 {
    1
}
fn default_max() -> u32 {
    1
}
fn default_required() -> bool {
    true
}

impl FileUpload {
    /// Build a [`FileUpload`] field requiring exactly one file.
    #[must_use]
    pub fn new(custom_id: impl Into<String>) -> Self {
        Self {
            custom_id: custom_id.into(),
            min_values: default_min(),
            max_values: default_max(),
            required: default_required(),
        }
    }

    /// Minimum file count.
    #[must_use]
    pub fn min_values(mut self, n: u32) -> Self {
        self.min_values = n;
        self
    }

    /// Maximum file count.
    #[must_use]
    pub fn max_values(mut self, n: u32) -> Self {
        self.max_values = n;
        self
    }

    /// Mark required / optional.
    #[must_use]
    pub fn required(mut self, r: bool) -> Self {
        self.required = r;
        self
    }
}

impl From<FileUpload> for Component {
    fn from(f: FileUpload) -> Self {
        Self::FileUpload(f)
    }
}

/// Build a [`FileUpload`].
///
/// ```ignore
/// use mumble_plugin_api::file_upload;
/// let f = file_upload!("attachments", max = 5);
/// ```
#[macro_export]
macro_rules! file_upload {
    ($custom_id:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __f = $crate::components::FileUpload::new($custom_id);
        $( $crate::__file_upload_modifier!(__f; $($rest)*); )?
        __f
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __file_upload_modifier {
    ($f:ident; min = $n:expr $(, $($rest:tt)*)?) => {
        $f = $f.min_values($n);
        $( $crate::__file_upload_modifier!($f; $($rest)*); )?
    };
    ($f:ident; max = $n:expr $(, $($rest:tt)*)?) => {
        $f = $f.max_values($n);
        $( $crate::__file_upload_modifier!($f; $($rest)*); )?
    };
    ($f:ident; required = $r:expr $(, $($rest:tt)*)?) => {
        $f = $f.required($r);
        $( $crate::__file_upload_modifier!($f; $($rest)*); )?
    };
    ($f:ident;) => {};
}

#[cfg(test)]
mod tests {

    #[test]
    fn macro_chain() {
        let f = file_upload!("a", min = 0, max = 3, required = false);
        assert_eq!(f.min_values, 0);
        assert_eq!(f.max_values, 3);
        assert!(!f.required);
    }
}
