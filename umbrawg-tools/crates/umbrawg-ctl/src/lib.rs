//! UmbraWG control plane: kernel netlink and userspace UAPI clients.

pub mod error;
pub mod model;
pub mod uapi;

#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod rtnl;

pub use error::Error;
pub use model::{Device, Peer, SetDevice, TimeSpec};
pub use uapi::{
    build_set_request, parse_get_response, parse_set_response, socket_dir, socket_path,
    DEFAULT_SOCKET_DIR,
};

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
