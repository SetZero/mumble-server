//! Declarative macros for building [`crate::PluginInfo`] (and its
//! nested [`crate::ClientManifest`]) without the usual `Vec`/`Some`/`.into()`
//! struct-literal noise.
//!
//! # Quick example
//!
//! ```
//! use mumble_plugin_api::plugin_info;
//!
//! let info = plugin_info! {
//!     description: "Example plugin",
//!     author: "Fancy Mumble",
//!     tags: ["greeting", "ping"],
//!     debug_info: {
//!         "active_sessions" => 3usize,
//!         "http_port" => 8080u16,
//!     },
//!     manifest: {
//!         capabilities: [SlashCommands, Components],
//!         slash_commands: [
//!             {
//!                 name: "greet",
//!                 description: "Send a friendly greeting",
//!                 options: [
//!                     { name: "name", description: "Who to greet", type: String, required: true },
//!                 ],
//!             },
//!         ],
//!         settings_panels: [
//!             { id: "status", title: "Greeter", rows: [ "Template" => "Welcome!" ] },
//!         ],
//!     },
//! };
//! assert_eq!(info.description, "Example plugin");
//! assert_eq!(info.author.as_deref(), Some("Fancy Mumble"));
//! let manifest = info.client_manifest.expect("manifest set");
//! assert_eq!(manifest.slash_commands[0].name, "greet");
//! ```
//!
//! All fields are optional except `description`.  Field order is free.
//! `manifest:` (or `client_manifest: <expr>`) accept the inline DSL or a
//! pre-built [`crate::ClientManifest`] value.
//!
//! # Grammar conventions
//!
//! * `capabilities: [Ident, ...]` inside `manifest` - bare identifiers
//!   are prefixed with `Capability::`.  Use the inline DSL for the
//!   common case; reach for `client_manifest: <expr>` if you need
//!   computed variants.
//! * `type: Ident` inside a slash-command option - bare identifier
//!   prefixed with `OptionType::`.
//! * `rows: ["label" => "value", ...]` and `debug_info: { "k" => v, ... }`
//!   use the same arrow-pair sugar; in `debug_info` the value side is
//!   `format!("{}", value)` so any `Display` works.
//! * String fields accept anything `Into<String>` (so `&str`, `String`,
//!   `Cow<str>` all work).
//! * Optional fields (`author`, `homepage`) take a bare value; the macro
//!   wraps it in `Some(...)` for you.

// ---------------------------------------------------------------------------
// plugin_info!
// ---------------------------------------------------------------------------

/// Build a [`crate::PluginInfo`] declaratively.  See the module-level
/// documentation in [`crate::info_macros`] for the full grammar.
#[macro_export]
macro_rules! plugin_info {
    ($($body:tt)*) => {{
        #[allow(unused_mut, reason = "mut needed when any field setter arms fire; \
                may stay unused for an empty invocation")]
        let mut __info = $crate::PluginInfo {
            description: ::std::string::String::new(),
            author: ::std::option::Option::None,
            homepage: ::std::option::Option::None,
            tags: ::std::vec::Vec::new(),
            debug_rows: ::std::vec::Vec::new(),
            client_manifest: ::std::option::Option::None,
        };
        $crate::__plugin_info_fields!(__info; $($body)*);
        __info
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __plugin_info_fields {
    ($info:ident;) => {};
    ($info:ident; , $($rest:tt)*) => {
        $crate::__plugin_info_fields!($info; $($rest)*);
    };
    ($info:ident; description: $v:expr $(, $($rest:tt)*)?) => {
        $info.description = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
    ($info:ident; author: $v:expr $(, $($rest:tt)*)?) => {
        $info.author = ::std::option::Option::Some(
            ::std::convert::Into::<::std::string::String>::into($v),
        );
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
    ($info:ident; homepage: $v:expr $(, $($rest:tt)*)?) => {
        $info.homepage = ::std::option::Option::Some(
            ::std::convert::Into::<::std::string::String>::into($v),
        );
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
    ($info:ident; tags: [$($tag:expr),* $(,)?] $(, $($rest:tt)*)?) => {
        $info.tags = ::std::vec![$(
            ::std::convert::Into::<::std::string::String>::into($tag)
        ),*];
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
    ($info:ident; debug_info: { $($label:expr => $value:expr),* $(,)? } $(, $($rest:tt)*)?) => {
        $info.debug_rows = ::std::vec![$(
            $crate::DebugRow {
                label: ::std::convert::Into::<::std::string::String>::into($label),
                value: ::std::format!("{}", $value),
            }
        ),*];
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
    // `debug_info: <expr>` accepts a pre-built `Vec<DebugRow>` (or
    // anything `Into<Vec<DebugRow>>`).  Use this when rows are computed
    // from runtime state and the literal `{ "k" => v }` form does not
    // fit.  Conflicts with `debug_info: {...}` in the same invocation
    // (whichever appears last wins).
    ($info:ident; debug_info: $v:expr $(, $($rest:tt)*)?) => {
        $info.debug_rows = ::std::convert::Into::<
            ::std::vec::Vec<$crate::DebugRow>
        >::into($v);
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
    ($info:ident; manifest: { $($mbody:tt)* } $(, $($rest:tt)*)?) => {
        $info.client_manifest = ::std::option::Option::Some(
            $crate::client_manifest!{ $($mbody)* }
        );
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
    ($info:ident; client_manifest: $v:expr $(, $($rest:tt)*)?) => {
        $info.client_manifest = ::std::option::Option::Some($v);
        $crate::__plugin_info_fields!($info; $($($rest)*)?);
    };
}

// ---------------------------------------------------------------------------
// client_manifest!
// ---------------------------------------------------------------------------

/// Build a [`crate::ClientManifest`] declaratively.  Usually composed
/// inline via `manifest: { ... }` inside [`plugin_info!`]; use this
/// directly when you need a `ClientManifest` value outside of a
/// [`crate::PluginInfo`].
#[macro_export]
macro_rules! client_manifest {
    ($($body:tt)*) => {{
        #[allow(unused_mut, reason = "mut needed when any field setter arms fire; \
                may stay unused for an empty invocation")]
        let mut __m = <$crate::ClientManifest as ::std::default::Default>::default();
        $crate::__client_manifest_fields!(__m; $($body)*);
        __m
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __client_manifest_fields {
    ($m:ident;) => {};
    ($m:ident; , $($rest:tt)*) => {
        $crate::__client_manifest_fields!($m; $($rest)*);
    };
    ($m:ident; schema_version: $v:expr $(, $($rest:tt)*)?) => {
        $m.schema_version = $v;
        $crate::__client_manifest_fields!($m; $($($rest)*)?);
    };
    ($m:ident; capabilities: [$($cap:ident),* $(,)?] $(, $($rest:tt)*)?) => {
        $m.capabilities = ::std::vec![$($crate::Capability::$cap),*];
        $crate::__client_manifest_fields!($m; $($($rest)*)?);
    };
    ($m:ident; slash_commands: [$($cmd:tt),* $(,)?] $(, $($rest:tt)*)?) => {
        $m.slash_commands = ::std::vec![$($crate::__slash_command!($cmd)),*];
        $crate::__client_manifest_fields!($m; $($($rest)*)?);
    };
    ($m:ident; settings_panels: [$($p:tt),* $(,)?] $(, $($rest:tt)*)?) => {
        $m.settings_panels = ::std::vec![$($crate::__settings_panel!($p)),*];
        $crate::__client_manifest_fields!($m; $($($rest)*)?);
    };
    ($m:ident; config_schema: [$($s:tt),* $(,)?] $(, $($rest:tt)*)?) => {
        $m.config_schema = ::std::vec![$($crate::__config_setting!($s)),*];
        $crate::__client_manifest_fields!($m; $($($rest)*)?);
    };
}

// ---------------------------------------------------------------------------
// SlashCommand
// ---------------------------------------------------------------------------

#[doc(hidden)]
#[macro_export]
macro_rules! __slash_command {
    ({ $($body:tt)* }) => {{
        #[allow(unused_mut, reason = "mut needed when any field setter arms fire; \
                may stay unused for an empty invocation")]
        let mut __c = $crate::SlashCommand {
            name: ::std::string::String::new(),
            description: ::std::string::String::new(),
            options: ::std::vec::Vec::new(),
        };
        $crate::__slash_command_fields!(__c; $($body)*);
        __c
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __slash_command_fields {
    ($c:ident;) => {};
    ($c:ident; , $($rest:tt)*) => {
        $crate::__slash_command_fields!($c; $($rest)*);
    };
    ($c:ident; name: $v:expr $(, $($rest:tt)*)?) => {
        $c.name = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__slash_command_fields!($c; $($($rest)*)?);
    };
    ($c:ident; description: $v:expr $(, $($rest:tt)*)?) => {
        $c.description = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__slash_command_fields!($c; $($($rest)*)?);
    };
    ($c:ident; options: [$($opt:tt),* $(,)?] $(, $($rest:tt)*)?) => {
        $c.options = ::std::vec![$($crate::__slash_command_option!($opt)),*];
        $crate::__slash_command_fields!($c; $($($rest)*)?);
    };
}

// ---------------------------------------------------------------------------
// SlashCommandOption
// ---------------------------------------------------------------------------

#[doc(hidden)]
#[macro_export]
macro_rules! __slash_command_option {
    ({ $($body:tt)* }) => {{
        #[allow(unused_mut, reason = "mut needed when any field setter arms fire; \
                may stay unused for an empty invocation")]
        let mut __o = $crate::SlashCommandOption {
            name: ::std::string::String::new(),
            description: ::std::string::String::new(),
            option_type: $crate::OptionType::String,
            required: true,
            choices: ::std::vec::Vec::new(),
        };
        $crate::__slash_command_option_fields!(__o; $($body)*);
        __o
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __slash_command_option_fields {
    ($o:ident;) => {};
    ($o:ident; , $($rest:tt)*) => {
        $crate::__slash_command_option_fields!($o; $($rest)*);
    };
    ($o:ident; name: $v:expr $(, $($rest:tt)*)?) => {
        $o.name = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__slash_command_option_fields!($o; $($($rest)*)?);
    };
    ($o:ident; description: $v:expr $(, $($rest:tt)*)?) => {
        $o.description = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__slash_command_option_fields!($o; $($($rest)*)?);
    };
    ($o:ident; type: $t:ident $(, $($rest:tt)*)?) => {
        $o.option_type = $crate::OptionType::$t;
        $crate::__slash_command_option_fields!($o; $($($rest)*)?);
    };
    ($o:ident; required: $v:expr $(, $($rest:tt)*)?) => {
        $o.required = $v;
        $crate::__slash_command_option_fields!($o; $($($rest)*)?);
    };
    ($o:ident; choices: [$($ch:tt),* $(,)?] $(, $($rest:tt)*)?) => {
        $o.choices = ::std::vec![$($crate::__option_choice!($ch)),*];
        $crate::__slash_command_option_fields!($o; $($($rest)*)?);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __option_choice {
    ({ label: $l:expr, value: $v:expr $(,)? }) => {
        $crate::OptionChoice {
            label: ::std::convert::Into::<::std::string::String>::into($l),
            value: ::std::convert::Into::<::std::string::String>::into($v),
        }
    };
    (($l:expr, $v:expr)) => {
        $crate::OptionChoice {
            label: ::std::convert::Into::<::std::string::String>::into($l),
            value: ::std::convert::Into::<::std::string::String>::into($v),
        }
    };
}

// ---------------------------------------------------------------------------
// SettingsPanel
// ---------------------------------------------------------------------------

#[doc(hidden)]
#[macro_export]
macro_rules! __settings_panel {
    ({ $($body:tt)* }) => {{
        #[allow(unused_mut, reason = "mut needed when any field setter arms fire; \
                may stay unused for an empty invocation")]
        let mut __p = $crate::SettingsPanel {
            id: ::std::string::String::new(),
            title: ::std::string::String::new(),
            rows: ::std::vec::Vec::new(),
        };
        $crate::__settings_panel_fields!(__p; $($body)*);
        __p
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __settings_panel_fields {
    ($p:ident;) => {};
    ($p:ident; , $($rest:tt)*) => {
        $crate::__settings_panel_fields!($p; $($rest)*);
    };
    ($p:ident; id: $v:expr $(, $($rest:tt)*)?) => {
        $p.id = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__settings_panel_fields!($p; $($($rest)*)?);
    };
    ($p:ident; title: $v:expr $(, $($rest:tt)*)?) => {
        $p.title = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__settings_panel_fields!($p; $($($rest)*)?);
    };
    ($p:ident; rows: [$($label:expr => $value:expr),* $(,)?] $(, $($rest:tt)*)?) => {
        $p.rows = ::std::vec![$(
            $crate::PanelRow {
                label: ::std::convert::Into::<::std::string::String>::into($label),
                value: ::std::convert::Into::<::std::string::String>::into($value),
            }
        ),*];
        $crate::__settings_panel_fields!($p; $($($rest)*)?);
    };
}

// ---------------------------------------------------------------------------
// ConfigSetting
// ---------------------------------------------------------------------------

#[doc(hidden)]
#[macro_export]
macro_rules! __config_setting {
    ({ $($body:tt)* }) => {{
        #[allow(unused_mut, reason = "mut needed when any field setter arms fire; \
                may stay unused for an empty invocation")]
        let mut __s = $crate::ConfigSetting {
            key: ::std::string::String::new(),
            label: ::std::string::String::new(),
            setting_type: $crate::SettingType::String,
            default: ::std::option::Option::None,
            options: ::std::vec::Vec::new(),
            secret: false,
            help: ::std::option::Option::None,
        };
        $crate::__config_setting_fields!(__s; $($body)*);
        __s
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __config_setting_fields {
    ($s:ident;) => {};
    ($s:ident; , $($rest:tt)*) => {
        $crate::__config_setting_fields!($s; $($rest)*);
    };
    ($s:ident; key: $v:expr $(, $($rest:tt)*)?) => {
        $s.key = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__config_setting_fields!($s; $($($rest)*)?);
    };
    ($s:ident; label: $v:expr $(, $($rest:tt)*)?) => {
        $s.label = ::std::convert::Into::<::std::string::String>::into($v);
        $crate::__config_setting_fields!($s; $($($rest)*)?);
    };
    ($s:ident; type: $t:ident $(, $($rest:tt)*)?) => {
        $s.setting_type = $crate::SettingType::$t;
        $crate::__config_setting_fields!($s; $($($rest)*)?);
    };
    ($s:ident; default: $v:expr $(, $($rest:tt)*)?) => {
        $s.default = ::std::option::Option::Some(
            ::std::convert::Into::<::std::string::String>::into($v),
        );
        $crate::__config_setting_fields!($s; $($($rest)*)?);
    };
    ($s:ident; options: [$($o:expr),* $(,)?] $(, $($rest:tt)*)?) => {
        $s.options = ::std::vec![$(
            ::std::convert::Into::<::std::string::String>::into($o)
        ),*];
        $crate::__config_setting_fields!($s; $($($rest)*)?);
    };
    ($s:ident; secret: $v:expr $(, $($rest:tt)*)?) => {
        $s.secret = $v;
        $crate::__config_setting_fields!($s; $($($rest)*)?);
    };
    ($s:ident; help: $v:expr $(, $($rest:tt)*)?) => {
        $s.help = ::std::option::Option::Some(
            ::std::convert::Into::<::std::string::String>::into($v),
        );
        $crate::__config_setting_fields!($s; $($($rest)*)?);
    };
}
