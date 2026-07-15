macro_rules! enum_builder {
    (
        $(#[$m:meta])*
        @U8
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var
            ),*
            ,
            /// An identifier that is not recognized by this build.
            Unknown(u8)
        }

        impl From<u8> for $enum_name {
            fn from(x: u8) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl $enum_name {
            #[allow(dead_code)]
            /// Returns the numeric identifier observed on the wire.
            pub(crate) fn value(self) -> u8 {
                match self {
                    $($enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x,
                }
            }
        }

        impl ::std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => write!(f, stringify!($enum_var))),*
                    ,$enum_name::Unknown(x) => write!(f, "Unknown ({x:#06x})"),
                }
            }
        }

        impl ::serde::Serialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }
    };
    (
        $(#[$m:meta])*
        @U16
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var
            ),*
            ,
            /// An identifier that is not recognized by this build.
            Unknown(u16)
        }

        impl From<u16> for $enum_name {
            fn from(x: u16) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl $enum_name {
            #[allow(dead_code)]
            /// Returns the numeric identifier observed on the wire.
            pub(crate) fn value(self) -> u16 {
                match self {
                    $($enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x,
                }
            }
        }

        impl ::std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => write!(f, stringify!($enum_var))),*
                    ,$enum_name::Unknown(x) => if is_grease_value(*x) {
                        write!(f, "GREASE ({x:#06x})")
                        } else {
                        write!(f, "Unknown ({x:#06x})")
                        }
                }
            }
        }

        impl ::serde::Serialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

    };
}

macro_rules! enum_builder2 {
    (
        $(#[$m:meta])*
        @U16
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var
            ),*
            ,
            /// An identifier that is not recognized by this build.
            Unknown(u16)
        }

        impl From<u16> for $enum_name {
            fn from(x: u16) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl $enum_name {
            #[allow(dead_code)]
            /// Returns the numeric identifier observed on the wire.
            pub(crate) fn value(self) -> u16 {
                match self {
                    $($enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x,
                }
            }
        }

        impl ::serde::Serialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

    };
}
