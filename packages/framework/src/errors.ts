export class HpkeError extends Error {}

export class I2OspError extends HpkeError {}

export class Os2IpError extends HpkeError {}

export class ValidationError extends HpkeError {}

export class DeserializeError extends HpkeError {}

export class EncapError extends HpkeError {}

export class DecapError extends HpkeError {}

export class UnsupportedError extends HpkeError {}

export class MessageLimitReachedError extends HpkeError {}

export class OpenError extends HpkeError {}

export class PskError extends HpkeError {}

export class InvalidConfig extends HpkeError {}
