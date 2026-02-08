if (COMPONENTS_IS_ENABLED_QT)
    COMPONENTS_CONFIGURE_COMPONENT(Encryption
        Qt5::Core
        ssl
        crypto
        sodium
    )
else()
    COMPONENTS_CONFIGURE_COMPONENT(Encryption
        ssl
        crypto
        sodium
    )
endif()

COMPONENTS_LINK_COMPONENT(Encryption Filework)
