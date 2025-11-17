COMPONENTS_REQUIRE_QT(5 Core)
COMPONENTS_CONFIGURE_COMPONENT(Encryption
    Qt5::Core
    ssl
    crypto
    sodium
)

COMPONENTS_LINK_COMPONENT(Encryption Filework)
