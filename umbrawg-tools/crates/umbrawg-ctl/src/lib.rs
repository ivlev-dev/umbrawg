//! UmbraWG control plane: kernel netlink and userspace UAPI clients.

pub mod error;
pub mod model;
pub mod uapi;

#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod rtnl;

pub use error::Error;
pub use model::{BbrStats, ConfigApplication, Device, FecStats, Peer, SetDevice, TimeSpec};
pub use uapi::{
    build_set_request, parse_get_response, parse_set_response, socket_dir, socket_path,
    DEFAULT_SOCKET_DIR,
};

use umbrawg_config::Config;

pub async fn list_interfaces() -> Result<Vec<String>, Error> {
    #[cfg(target_os = "linux")]
    let mut interfaces = rtnl::get_kernel_interfaces()?;
    #[cfg(not(target_os = "linux"))]
    let mut interfaces = Vec::new();
    interfaces.extend(uapi::list_interfaces().await?);
    Ok(interfaces)
}

pub async fn get_device(name: &str) -> Result<Device, Error> {
    uapi::validate_interface_name(name)?;
    if uapi::has_interface(name).await {
        return uapi::get_device(name).await;
    }
    kernel_get_device(name).await
}

pub async fn set_device(config: &SetDevice) -> Result<(), Error> {
    uapi::validate_interface_name(&config.name)?;
    if uapi::has_interface(&config.name).await {
        return uapi::set_device(config).await;
    }
    kernel_set_device(config).await
}

/// Applies a configuration file like `uwg setconf`.
pub async fn setconf(name: &str, config: &Config) -> Result<(), Error> {
    let set = SetDevice::from_config_file(name, config, ConfigApplication::Replace);
    set_device(&set).await
}

/// Appends a configuration file like `uwg addconf`.
pub async fn addconf(name: &str, config: &Config) -> Result<(), Error> {
    let set = SetDevice::from_config_file(name, config, ConfigApplication::Append);
    set_device(&set).await
}

/// Synchronizes a configuration file like `uwg syncconf`.
///
/// Peers missing from the file are removed explicitly so that peers shared
/// with the running configuration keep their sessions.
pub async fn syncconf(name: &str, config: &Config) -> Result<(), Error> {
    let runtime = get_device(name).await?;
    let set = SetDevice::synced_from(name, config, &runtime);
    set_device(&set).await
}

#[cfg(target_os = "linux")]
async fn kernel_get_device(name: &str) -> Result<Device, Error> {
    netlink::get_device(name).await
}

#[cfg(not(target_os = "linux"))]
async fn kernel_get_device(name: &str) -> Result<Device, Error> {
    let _ = name;
    Err(Error::NoKernelSupport(
        "this platform has no kernel UmbraWG support".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
async fn kernel_set_device(config: &SetDevice) -> Result<(), Error> {
    netlink::set_device(config).await
}

#[cfg(not(target_os = "linux"))]
async fn kernel_set_device(config: &SetDevice) -> Result<(), Error> {
    let _ = config;
    Err(Error::NoKernelSupport(
        "this platform has no kernel UmbraWG support".to_owned(),
    ))
}

pub fn create_interface(name: &str) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        rtnl::create_interface(name, "umbrawg")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err(Error::NoKernelSupport(
            "this platform has no kernel UmbraWG support".to_owned(),
        ))
    }
}

pub fn delete_interface(name: &str) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        rtnl::delete_interface(name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err(Error::NoKernelSupport(
            "this platform has no kernel UmbraWG support".to_owned(),
        ))
    }
}
