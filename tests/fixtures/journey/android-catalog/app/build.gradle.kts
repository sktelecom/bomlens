plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.catalog"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.bundles.networking)
}
