use proc_macro::TokenStream;
use quote::quote;
use syn::{
    DeriveInput, Item, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// Parsed attributes for FFI type macros
#[derive(Default)]
struct FfiTypeAttrs {
    mobile_name: Option<String>,
    web_name: Option<String>,
    skip_serde_derive: bool,
    only_web: bool,
    only_mobile: bool,
}

impl Parse for FfiTypeAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut mobile_name = None;
        let mut web_name = None;
        let mut skip_serde_derive = false;
        let mut only_web = false;
        let mut only_mobile = false;
        let mut only_web_span = None;
        let mut only_mobile_span = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;

            match key.to_string().as_str() {
                "skip_serde_derive" => skip_serde_derive = true,
                "only_web" => {
                    only_web = true;
                    only_web_span = Some(key.span());
                }
                "only_mobile" => {
                    only_mobile = true;
                    only_mobile_span = Some(key.span());
                }
                "mobile_name" => {
                    input.parse::<Token![=]>()?;
                    let value: LitStr = input.parse()?;
                    mobile_name = Some(value.value());
                }
                "web_name" => {
                    input.parse::<Token![=]>()?;
                    let value: LitStr = input.parse()?;
                    web_name = Some(value.value());
                }
                _ => return Err(syn::Error::new(key.span(), "Unknown attribute")),
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        if only_web && only_mobile {
            return Err(syn::Error::new(
                only_mobile_span.unwrap(),
                "only_web and only_mobile are mutually exclusive",
            ));
        }
        if only_web && mobile_name.is_some() {
            return Err(syn::Error::new(
                only_web_span.unwrap(),
                "mobile_name has no effect with only_web",
            ));
        }
        if only_mobile && web_name.is_some() {
            return Err(syn::Error::new(
                only_mobile_span.unwrap(),
                "web_name has no effect with only_mobile",
            ));
        }

        Ok(FfiTypeAttrs {
            mobile_name,
            web_name,
            skip_serde_derive,
            only_web,
            only_mobile,
        })
    }
}

/// Serde derives for FFI types. Emitted under `wasm` (tsify needs them) and
/// under a standalone `serde` feature, so native consumers can (de)serialize
/// these types without pulling in the wasm bindings. Crates using these
/// macros should declare `serde = []` and have `wasm` enable it.
fn serde_derive() -> impl quote::ToTokens {
    quote! {
        #[cfg_attr(any(feature = "wasm", feature = "serde"), derive(serde::Serialize, serde::Deserialize))]
    }
}

#[proc_macro_derive(Error)]
pub fn derive_error(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let expanded = quote! {
        impl std::error::Error for #name {}
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(expanded)
}

/// Attribute macro for FFI types (structs and enums)
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Record for structs, uniffi::Enum for enums
/// - wasm: derives tsify::Tsify, serde::Serialize, serde::Deserialize
/// - serde: derives serde::Serialize, serde::Deserialize (implied by wasm)
///
/// Pass `only_web` or `only_mobile` when a type is only ever consumed directly by one FFI
/// target (the other target either never sees it, or defines its own identically-named mirror
/// type and converts via `From`). This avoids generating dead bindings that can collide by name
/// with a consuming crate's own FFI-exported types.
///
/// Note: this no longer derives `tsify(into_wasm_abi, from_wasm_abi)` (deprecated, leaks memory
/// on (de)serialization failure, see https://github.com/madonoharu/tsify/issues/65).
/// Wherever a generated type crosses a `#[wasm_bindgen]` function boundary (as a parameter or
/// return type, including inside `Vec<_>`/`Option<_>`), wrap it in `tsify::Ts<_>` at the
/// call site and convert with `.to_rust()` / `.into_ts()` inside the function body.
///
/// # Examples
/// ```
/// #[ffi_type]
/// pub struct MyStruct {
///     pub field: String,
/// }
///
/// #[ffi_type(mobile_name = "MobileType", web_name = "WebType")]
/// pub enum MyEnum {
///     Variant1,
///     Variant2(String),
/// }
///
/// // Only proton-pass-web uses this type directly; proton-pass-mobile mirrors it instead.
/// #[ffi_type(only_web)]
/// pub struct WebOnlyType {
///     pub field: String,
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_type(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = if attr.is_empty() {
        FfiTypeAttrs::default()
    } else {
        parse_macro_input!(attr as FfiTypeAttrs)
    };

    let input = parse_macro_input!(item as Item);

    let uniffi_derive = match &input {
        Item::Struct(_) => quote! { uniffi::Record },
        Item::Enum(_) => quote! { uniffi::Enum },
        _ => panic!("ffi_type can only be used on structs or enums"),
    };

    let mobile_derive = if attrs.only_web {
        quote! {}
    } else {
        quote! { #[cfg_attr(feature = "uniffi", derive(#uniffi_derive))] }
    };

    let mobile_rename = if let Some(name) = attrs.mobile_name {
        quote! { #[cfg_attr(feature = "uniffi", uniffi(export_name = #name))] }
    } else {
        quote! {}
    };

    let web_rename = if let Some(name) = attrs.web_name {
        quote! { #[cfg_attr(feature = "wasm", serde(rename = #name))] }
    } else {
        quote! {}
    };

    let serde_derive = serde_derive();
    let wasm_derive = if attrs.only_mobile {
        quote! {}
    } else if attrs.skip_serde_derive {
        quote! { #[cfg_attr(feature = "wasm", derive(tsify::Tsify))] }
    } else {
        quote! {
            #serde_derive
            #[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
        }
    };

    let expanded = quote! {
        #mobile_derive
        #mobile_rename
        #wasm_derive
        #web_rename
        #input
    };

    TokenStream::from(expanded)
}

/// Attribute macro for FFI error types
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Error
/// - wasm: derives tsify::Tsify, serde::Serialize, serde::Deserialize
/// - serde: derives serde::Serialize, serde::Deserialize (implied by wasm)
///
/// Note: You should also derive Debug for error types
///
/// # Example
/// ```
/// #[ffi_error]
/// #[derive(Debug)]
/// pub enum MyError {
///     InvalidInput,
///     NotFound,
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_error(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);
    let serde_derive = serde_derive();

    let expanded = quote! {
        #[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
        #[cfg_attr(feature = "uniffi", uniffi(flat_error))]
        #serde_derive
        #[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
        #input
    };

    TokenStream::from(expanded)
}

/// Attribute macro for FFI id newtypes (single-field tuple structs wrapping a primitive)
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: registers the type as a custom newtype via `uniffi::custom_newtype!`
/// - wasm: derives tsify::Tsify, serde::Serialize, serde::Deserialize
/// - serde: derives serde::Serialize, serde::Deserialize (implied by wasm)
///
/// # Example
/// ```
/// #[ffi_id_type]
/// pub struct MyId(pub(crate) String);
/// ```
#[proc_macro_attribute]
pub fn ffi_id_type(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::ItemStruct);

    let ident = &input.ident;
    let inner_type = match &input.fields {
        syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => &fields.unnamed[0].ty,
        _ => panic!("ffi_id_type can only be used on single-field tuple structs"),
    };
    let serde_derive = serde_derive();

    let expanded = quote! {
        #serde_derive
        #[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
        #input

        #[cfg(feature = "uniffi")]
        uniffi::custom_newtype!(#ident, #inner_type);
    };

    TokenStream::from(expanded)
}

/// Attribute macro for FFI object/class types
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Object
/// - wasm: Currently not applicable for objects (stateful classes)
///
/// Pass `only_mobile` to make the (already mobile-only) behavior explicit, or `only_web` to
/// suppress the `uniffi::Object` derive entirely - e.g. when the type is exposed to wasm via
/// hand-written annotations elsewhere and shouldn't also be scaffolded for uniffi.
///
/// # Example
/// ```
/// #[ffi_object]
/// pub struct MyObject {
///     state: String,
/// }
///
/// #[ffi_object(mobile_name = "MobileObject")]
/// pub struct MyOtherObject {
///     state: String,
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_object(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = if attr.is_empty() {
        FfiTypeAttrs::default()
    } else {
        parse_macro_input!(attr as FfiTypeAttrs)
    };

    let input = parse_macro_input!(item as Item);

    let mobile_derive = if attrs.only_web {
        quote! {}
    } else {
        quote! { #[cfg_attr(feature = "uniffi", derive(uniffi::Object))] }
    };

    let mobile_rename = if let Some(name) = attrs.mobile_name {
        quote! { #[cfg_attr(feature = "uniffi", uniffi(export_name = #name))] }
    } else {
        quote! {}
    };

    let expanded = quote! {
        #mobile_derive
        #mobile_rename
        #input
    };

    TokenStream::from(expanded)
}
