// SPDX-License-Identifier: MPL-2.0

//! Attribute groups: attributes declared together,
//! either in the device's directory or in a subdirectory of it.
//!
//! [`AttrGroup<D>`] is the declaration, like Linux's `struct attribute_group`.
//! A named group becomes a [`Dir`] under the device whose files are served by
//! [`GroupDirOps`], which reaches the device through a weak reference.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::fmt::{self, Write};

use crate::common::{
    AnyDevice, Error, Result, SysStr,
    attr::{Attr, TyErasedAttr},
    node::{Dir, DirAttrOps},
};

/// A statically declared group of attributes of devices of type `D`.
///
/// The attributes of an unnamed group are files in the device's directory.
/// Those of a named group are files in a subdirectory with that name,
/// such as `topology` under a CPU device.
pub struct AttrGroup<D: ?Sized + 'static> {
    name: Option<&'static str>,
    attrs: &'static [Attr<D>],
}

impl<D: ?Sized + 'static> AttrGroup<D> {
    /// Creates a group whose attributes are files in the device's directory.
    pub const fn unnamed(attrs: &'static [Attr<D>]) -> Self {
        Self { name: None, attrs }
    }

    /// Creates a group whose attributes are files in the subdirectory `name`.
    ///
    /// `name` must be a valid node name according to [`aster_systree::is_valid_name`].
    pub const fn named(name: &'static str, attrs: &'static [Attr<D>]) -> Self {
        Self {
            name: Some(name),
            attrs,
        }
    }

    /// Returns the subdirectory name, if the group has one.
    pub fn name(&self) -> Option<&'static str> {
        self.name
    }

    /// Returns the attributes.
    pub fn attrs(&self) -> &'static [Attr<D>] {
        self.attrs
    }
}

impl<D: ?Sized + 'static> fmt::Debug for AttrGroup<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttrGroup")
            .field("name", &self.name)
            .field("attrs", &self.attrs)
            .finish()
    }
}

/// An attribute group whose callbacks take `&dyn AnyDevice`.
#[derive(Debug)]
pub struct TyErasedAttrGroup {
    pub(crate) name: Option<&'static str>,
    pub(crate) attrs: Vec<TyErasedAttr>,
}

impl TyErasedAttrGroup {
    /// Wraps type-erased attributes as an unnamed group.
    pub(crate) fn unnamed(attrs: Vec<TyErasedAttr>) -> Self {
        Self { name: None, attrs }
    }

    /// Converts a group for devices of Rust type `D` into a type-erased group.
    pub(crate) fn from_typed<D: AnyDevice>(group: &AttrGroup<D>) -> Self {
        Self {
            name: group.name,
            attrs: TyErasedAttr::from_typed_slice(group.attrs),
        }
    }
}

/// Creates the directory of the named group `name`, whose files serve `attrs` for `owner`.
///
/// Fails if the group name or an attribute name is invalid, or if an attribute name is repeated.
pub(crate) fn new_group_dir(
    name: &'static str,
    attrs: Vec<TyErasedAttr>,
    owner: Weak<dyn AnyDevice>,
) -> Result<Arc<Dir>> {
    if !aster_systree::is_valid_name(name) {
        return Err(Error::InvalidName);
    }
    let mut seen = BTreeSet::new();
    if !attrs.iter().all(|attr| seen.insert(attr.name())) {
        return Err(Error::NameConflict);
    }
    let entries: Vec<_> = attrs
        .iter()
        .map(|attr| (attr.name(), attr.perms()))
        .collect();
    let dir = Dir::with_attrs(SysStr::from(name), &entries)?;
    dir.set_ops(Box::new(GroupDirOps {
        owner,
        attrs: attrs.into_iter().map(|attr| (attr.name(), attr)).collect(),
    }));
    Ok(dir)
}

/// The files of a named group's directory.
struct GroupDirOps {
    owner: Weak<dyn AnyDevice>,
    attrs: BTreeMap<&'static str, TyErasedAttr>,
}

impl GroupDirOps {
    /// Returns the owner device and the attribute `name`, if the device is registered.
    fn lookup(&self, name: &str) -> Result<(Arc<dyn AnyDevice>, &TyErasedAttr)> {
        let dev = self.owner.upgrade().ok_or(Error::NotFound)?;
        if !dev.base().is_added() {
            return Err(Error::NotAdded);
        }
        let attr = self.attrs.get(name).ok_or(Error::NotFound)?;
        Ok((dev, attr))
    }
}

impl DirAttrOps for GroupDirOps {
    fn show(&self, name: &str, w: &mut dyn Write) -> Result<()> {
        let (dev, attr) = self.lookup(name)?;
        attr.show(dev.as_ref(), w)
    }

    fn store(&self, name: &str, value: &str) -> Result<()> {
        let (dev, attr) = self.lookup(name)?;
        attr.store(dev.as_ref(), value)
    }
}
