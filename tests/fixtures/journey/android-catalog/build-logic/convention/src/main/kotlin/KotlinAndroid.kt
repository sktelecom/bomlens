internal fun configureKotlinAndroid(commonExtension: Any) {
    commonExtension.apply {
        compileSdk = 37

        defaultConfig {
            minSdk = 23
        }
    }
}
