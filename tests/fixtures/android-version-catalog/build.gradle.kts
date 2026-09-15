// Test fixture: the Android plugin is declared only in the version catalog
// (gradle/libs.versions.toml) and applied through a project alias, so no build
// script names it.
plugins {
    alias(libs.plugins.example.application) apply false
}
