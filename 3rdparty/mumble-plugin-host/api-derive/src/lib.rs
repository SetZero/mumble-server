//! Proc-macros for `mumble-plugin-api`.
//!
//! Re-exported from `mumble_plugin_api` so plugin authors only need
//! one dependency.  See the api crate's `commands` and `info_macros`
//! modules for the runtime side the generated code calls into.

use proc_macro::TokenStream;

mod command;
mod component;
mod fancy_plugin;
mod macros_runtime;
mod modal;

/// Marks a method as a slash-command handler.  Consumed by
/// [`macro@fancy_plugin`] on the surrounding `impl` block, which uses
/// the function signature to build a `CommandDescriptor` and to
/// generate the dispatch shim that extracts typed args from the
/// inbound interaction payload.
///
/// ```ignore
/// #[command(name = "greet", description = "Send a greeting")]
/// fn greet(&self, name: String, loud: bool) -> InteractionResponse {
///     /* ... */
/// }
/// ```
///
/// * `name` (required): the slash-command name as typed by the user
///   in the composer (without the leading `/`).
/// * `description` (optional): one-line description shown in the
///   command picker.  Defaults to the doc-comment on the function;
///   a warning is emitted if neither is present.
///
/// Parameter types must implement
/// `mumble_plugin_api::FromOption`.  `Option<T>` parameters become
/// `required: false` in the manifest; everything else is required.
/// Each parameter's doc-comment (if any) becomes that option's
/// description.
///
#[proc_macro_attribute]
pub fn command(args: TokenStream, item: TokenStream) -> TokenStream {
    command::expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Marks a method as a message-component (button / select menu)
/// interaction handler.  Consumed by [`macro@fancy_plugin`] on the
/// surrounding `impl` block, which derives a wire `custom_id`
/// (`"<TypeName>::<method>"` unless overridden) and a dispatch arm
/// that routes inbound `Component` interactions to the method.
///
/// ```ignore
/// #[component]
/// fn on_cancel(&self) -> InteractionResponse { /* ... */ }
///
/// #[component]
/// fn on_role_pick(&self, values: Vec<String>) -> InteractionResponse {
///     /* ... */
/// }
/// ```
///
/// * `custom_id` (optional): overrides the auto-generated wire id.
///   Must be a `&'static str` expression (string literal or const).
///
/// Parameter shapes accepted:
/// * `(&self)` - no values bound (typical for buttons).
/// * `(&self, values: Vec<String>)` - bound to all selected option
///   values (typical for multi-select menus).
///
/// The matching builder side uses `mumble_plugin_api::handler_id!`
/// to pull the auto-generated id into a `mumble_plugin_api::Button`
/// or `mumble_plugin_api::SelectMenu` without manual stringly-typed
/// wiring.
#[proc_macro_attribute]
pub fn component(args: TokenStream, item: TokenStream) -> TokenStream {
    component::expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Marks a method as a modal-submission handler.  Consumed by
/// [`macro@fancy_plugin`] on the surrounding `impl` block, which
/// derives a wire `custom_id` (`"<TypeName>::<method>"` unless
/// overridden), a per-field id table, and a dispatch arm that
/// extracts typed field values via
/// `mumble_plugin_api::FromField`.
///
/// ```ignore
/// #[modal]
/// fn on_greet_submit(
///     &self,
///     #[field] message: String,
///     #[field] cc: Option<String>,
/// ) -> InteractionResponse { /* ... */ }
/// ```
///
/// * `custom_id` (optional): overrides the auto-generated wire id.
///
/// Every modal parameter (other than `&self`) must be tagged
/// `#[field]` and have a type implementing
/// `mumble_plugin_api::FromField` (`String`, `Option<String>`).
/// Field names on the wire come from the parameter idents.
///
/// The matching builder side uses `mumble_plugin_api::modal!` to
/// pull the auto-generated `custom_id` and field ids into a
/// `ShowModal` response.
#[proc_macro_attribute]
pub fn modal(args: TokenStream, item: TokenStream) -> TokenStream {
    modal::modal_expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Per-parameter marker used inside [`macro@modal`] handlers to flag
/// a wire-side modal field.  Takes no arguments and produces no
/// code on its own; consumed by [`macro@fancy_plugin`]'s walker.
#[proc_macro_attribute]
pub fn field(args: TokenStream, item: TokenStream) -> TokenStream {
    modal::field_expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Annotates `impl MumblePlugin for MyPlugin { ... }` so that the
/// trivial trait methods (`name`, `version`, `info_json`,
/// `on_plugin_message` dispatch prelude) and the slash-command
/// manifest are synthesised from the surrounding items.
///
/// ```ignore
/// #[fancy_plugin(name = "fancy-greeter")]
/// impl MumblePlugin for GreeterPlugin {
///     plugin_info! { description: "...", manifest: { /* no slash_commands! */ } }
///
///     #[command(name = "greet")]
///     fn greet(&self, name: String) -> InteractionResponse { /* ... */ }
///
///     fn on_plugin_message(&self, msg: PluginMessageIn) -> PluginResult<()> {
///         // dispatch prelude auto-inserted; this body runs for non-command
///         // payload types only.
///         ROk(())
///     }
/// }
/// ```
///
/// Arguments:
/// * `name = "fancy-greeter"` or `name = MY_NAME_CONST` (required):
///   the value returned from `MumblePlugin::name`.
/// * `version = "1.2.3"` or `version = MY_VERSION_CONST` (optional):
///   the value returned from `MumblePlugin::version`.  Defaults to
///   `env!("CARGO_PKG_VERSION")` of the calling crate.
///
/// The macro requires that the impl block contains at most one
/// impl-position `plugin_info! { ... }` invocation (whose tokens are
/// used to synthesise `info_json`).  If you already define `fn name`,
/// `fn version`, or `fn info_json` by hand the macro errors out.
///
#[proc_macro_attribute]
pub fn fancy_plugin(args: TokenStream, item: TokenStream) -> TokenStream {
    fancy_plugin::expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Resolve the wire id of a `#[command]`, `#[component]`, or
/// `#[modal]` handler at compile time as a `&'static str`.
///
/// Expands `<Path>::<method>` to `<Path>::__FANCY_ID__<method>`,
/// which is emitted as an associated const on the plugin's inherent
/// impl by [`macro@fancy_plugin`].
///
/// ```ignore
/// use mumble_plugin_api::{handler_id, Button};
/// let b = Button::new(handler_id!(Self::on_cancel), "Cancel");
/// ```
#[proc_macro]
pub fn handler_id(input: TokenStream) -> TokenStream {
    macros_runtime::handler_id_expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Build a `ShowModal`-kind `InteractionResponse` wired to a
/// `#[modal]`-annotated handler method.
///
/// ```ignore
/// use mumble_plugin_api::{show_modal, TextInput, TextInputStyle};
/// let resp = show_modal!(Self::on_greet_submit, "Send a greeting", {
///     message: TextInput::label("Message").style(TextInputStyle::Paragraph),
///     cc:      TextInput::label("CC").required(false),
/// });
/// ```
///
/// Expands references to `<Path>::__FANCY_ID__<method>` and
/// `<Path>::__FANCY_FIELD__<method>__<field>` associated consts on
/// the plugin's inherent impl - both emitted by [`macro@fancy_plugin`].
/// A typo'd field ident produces a "no associated item" error
/// pointing at the offending line.
#[proc_macro]
pub fn show_modal(input: TokenStream) -> TokenStream {
    macros_runtime::show_modal_expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
