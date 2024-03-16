pub trait Upgrader: Send + Sync {}

pub struct NoopUpgrader {}

impl Upgrader for NoopUpgrader {}
