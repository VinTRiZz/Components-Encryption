COMPONENTS_CONFIGURE_COMPONENT(Encryption "1.0.0"
    ssl
    crypto
    sodium
)
if (COMPONENTS_IS_ENABLED_QT)
    target_link_libraries(Components-Encryption PRIVATE Qt5::Core)
endif()

COMPONENTS_LINK_COMPONENT(Components-Encryption Filework)
COMPONENTS_LINK_COMPONENT(Components-Encryption ExtraClasses)

COMPONENTS_ADD_COMPONENT_TEST(Encryption)
