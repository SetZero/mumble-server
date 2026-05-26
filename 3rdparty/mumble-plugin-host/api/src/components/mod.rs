//! Tier-1 UI **component** vocabulary.
//!
//! Each Discord-style component lives in its own submodule alongside
//! its declarative shortcut macro (`button!`, `string_select!`, ...).
//! The [`Component`] enum dispatches over every variant and is the
//! type stored inside [`ActionRow`] / [`Section`] / [`Container`].
//!
//! See <https://docs.discord.com/developers/components/reference> for
//! the upstream Discord shape this mirrors.  Mumble-specific
//! adaptations:
//!
//! * `User` / `Channel` selects return Mumble `SessionId` / `ChannelId`
//!   values (as strings, like the rest of the wire format).
//! * `Role` / `Mentionable` selects return ACL group names plus, for
//!   the mentionable case, user ids.
//! * `File` and `FileUpload` are wired to the Fancy Mumble file system
//!   (URIs of the form `fancy-file://<id>` or `attachment://<name>`).

pub mod action_row;
pub mod button;
pub mod channel_select;
pub mod checkbox;
pub mod checkbox_group;
pub mod container;
pub mod file;
pub mod file_upload;
pub mod label;
pub mod media_gallery;
pub mod mentionable_select;
pub mod modal_field;
pub mod radio_group;
pub mod role_select;
pub mod section;
pub mod separator;
pub mod string_select;
pub mod text_display;
pub mod text_input;
pub mod thumbnail;
pub mod unfurled_media;
pub mod user_select;

pub use action_row::ActionRow;
pub use button::{Button, ButtonStyle};
pub use channel_select::ChannelSelect;
pub use checkbox::Checkbox;
pub use checkbox_group::{CheckboxGroup, CheckboxOption};
pub use container::Container;
pub use file::FileComponent;
pub use file_upload::FileUpload;
pub use label::Label;
pub use media_gallery::{MediaGallery, MediaGalleryItem};
pub use mentionable_select::MentionableSelect;
pub use modal_field::ModalFieldValue;
pub use radio_group::{RadioGroup, RadioOption};
pub use role_select::RoleSelect;
pub use section::{Section, SectionAccessory};
pub use separator::{Separator, SeparatorSpacing};
pub use string_select::{SelectMenu, SelectOption, StringSelect};
pub use text_display::TextDisplay;
pub use text_input::{TextInput, TextInputBuilder, TextInputStyle};
pub use thumbnail::Thumbnail;
pub use unfurled_media::UnfurledMediaItem;
pub use user_select::UserSelect;

use serde::{Deserialize, Serialize};

/// A single component, in any of the supported shapes.
///
/// Variants are serde-tagged with `"type"` (kebab-case).  Wire-format
/// stable names for legacy variants are preserved via
/// `#[serde(alias = ...)]` so manifests authored against schema
/// version 1 keep deserialising.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[allow(
    clippy::large_enum_variant,
    reason = "components are constructed once per response; size disparity is acceptable"
)]
pub enum Component {
    /// Click target.  See [`Button`].
    Button(Button),
    /// String-valued dropdown.  Wire-tagged `"string-select"`; the
    /// legacy `"select-menu"` tag is accepted for backward compat.
    #[serde(alias = "select-menu")]
    StringSelect(StringSelect),
    /// User picker; returns session ids.  See [`UserSelect`].
    UserSelect(UserSelect),
    /// Role picker; returns ACL group names.  See [`RoleSelect`].
    RoleSelect(RoleSelect),
    /// Mentionable picker (users + ACL groups).  See
    /// [`MentionableSelect`].
    MentionableSelect(MentionableSelect),
    /// Channel picker; returns channel ids.  See [`ChannelSelect`].
    ChannelSelect(ChannelSelect),
    /// Free-form text field (modal-only).  See [`TextInput`].
    TextInput(TextInput),
    /// Markdown text block.  See [`TextDisplay`].
    TextDisplay(TextDisplay),
    /// Inline thumbnail image (section accessory).  See [`Thumbnail`].
    Thumbnail(Thumbnail),
    /// Image / video gallery (1-10 items).  See [`MediaGallery`].
    MediaGallery(MediaGallery),
    /// File attachment reference.  Variant name `"file"`.  See
    /// [`FileComponent`].
    #[serde(rename = "file")]
    File(FileComponent),
    /// Modal-only file uploader.  See [`FileUpload`].
    FileUpload(FileUpload),
    /// Vertical padding / optional divider.  See [`Separator`].
    Separator(Separator),
    /// Visual grouping with optional accent colour.  See [`Container`].
    Container(Container),
    /// Text-plus-accessory layout block.  See [`Section`].
    Section(Section),
    /// Modal-only label wrapping a single child component.  See
    /// [`Label`].
    Label(Label),
    /// Modal-only single-choice radio set.  See [`RadioGroup`].
    RadioGroup(RadioGroup),
    /// Modal-only multi-choice checkbox set.  See [`CheckboxGroup`].
    CheckboxGroup(CheckboxGroup),
    /// Modal-only single boolean checkbox.  See [`Checkbox`].
    Checkbox(Checkbox),
}
