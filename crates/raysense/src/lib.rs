pub const NAME: &str = "raysense";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn package_name() -> &'static str {
    NAME
}

pub fn package_version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_package_identity() {
        assert_eq!(package_name(), "raysense");
        assert_eq!(package_version(), env!("CARGO_PKG_VERSION"));
    }
}
