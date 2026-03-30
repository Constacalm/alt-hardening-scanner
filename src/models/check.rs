#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interface {
    Sysctl,
    Grub,
}

impl Interface {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sysctl => "sysctl",
            Self::Grub => "grub",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub id: u32,
    pub param: String,
    pub interface: Interface,
    pub target_value: String,
    pub default_value: String,
    pub description: String,
    pub section: String,
}
